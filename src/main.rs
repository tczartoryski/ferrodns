use ferrodns::hints::{self, Hint};
use ferrodns::resolver::{Config, Resolution, Resolver};
use ferrodns::wire::{Name, RType, rcode};
use ferrodns::{server, sim};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const USAGE: &str = "\
ferrodns: a recursive DNS resolver from scratch

USAGE:
    ferrodns query <name> [type] [--trace] [options]
    ferrodns viz <name> [type] [--out dir] [options]
    ferrodns serve [--trace-dir dir] [--listen 127.0.0.1:5353] [options]
    ferrodns demo                     run against a simulated internet on loopback
    ferrodns sim [port]               just run the simulated internet (default port 15353)

OPTIONS:
    --trace                 print every step of the resolution
    --trace-json <file>     write query trace JSON, including resolution failures
    --trace-dir <dir>       trace serve requests reaching resolution (not rejected packets)
    --out <dir>             viz output directory (default ferrodns-viz)
    --ipv6                  also use IPv6 nameserver addresses
    --timeout-ms <ms>       per-query upstream timeout (default 1500)
    --upstream-port <port>  port to query nameservers on (default 53)
    --root <name>=<ip>      override root hints (repeatable)
";

struct Opts {
    positional: Vec<String>,
    trace: bool,
    listen: SocketAddr,
    trace_json: Option<PathBuf>,
    out: Option<PathBuf>,
    cfg: Config,
}

fn parse_args(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        positional: vec![],
        trace: false,
        trace_json: None,
        out: None,
        listen: "127.0.0.1:5353".parse().unwrap(),
        cfg: Config::default(),
    };
    let mut roots: Vec<Hint> = vec![];
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or(format!("{a} needs a value"));
        match a.as_str() {
            "--trace" => o.trace = true,
            "--trace-json" => o.trace_json = Some(val()?.into()),
            "--trace-dir" => o.cfg.trace_dir = Some(val()?.into()),
            "--out" => o.out = Some(val()?.into()),
            "--ipv6" => o.cfg.ipv6 = true,
            "--listen" => o.listen = val()?.parse().map_err(|e| format!("--listen: {e}"))?,
            "--timeout-ms" => {
                o.cfg.timeout =
                    Duration::from_millis(val()?.parse().map_err(|e| format!("--timeout-ms: {e}"))?)
            }
            "--upstream-port" => {
                o.cfg.port = val()?
                    .parse()
                    .map_err(|e| format!("--upstream-port: {e}"))?
            }
            "--root" => {
                let v = val()?;
                let (name, ip) = v.split_once('=').ok_or("--root expects name=ip")?;
                roots.push(Hint {
                    name: name.parse().map_err(|e| format!("--root: {e}"))?,
                    addr: ip.parse().map_err(|e| format!("--root: {e}"))?,
                });
            }
            "-h" | "--help" => return Err(String::new()),
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            _ => o.positional.push(a.clone()),
        }
    }
    if !roots.is_empty() {
        o.cfg.roots = roots;
    } else if o.cfg.ipv6 {
        o.cfg.roots = hints::internet_roots(true);
    }
    Ok(o)
}

fn print_resolution(name: &Name, qtype: RType, res: &Resolution, elapsed: Duration, upstream: u64) {
    println!(";; QUESTION: {name} IN {qtype}");
    println!(";; status: {}", rcode::name(res.rcode));
    if !res.answers.is_empty() {
        println!(";; ANSWER:");
        for r in &res.answers {
            println!("{r}");
        }
    }
    if !res.authority.is_empty() {
        println!(";; AUTHORITY:");
        for r in &res.authority {
            println!("{r}");
        }
    }
    println!(
        ";; {upstream} upstream queries, {:.1} ms",
        elapsed.as_secs_f64() * 1000.0
    );
}

fn query(resolver: &Resolver, name: &str, qtype: &str, trace: bool) -> Result<(), String> {
    query_output(resolver, name, qtype, trace, None, None)
}

fn query_output(
    resolver: &Resolver,
    name: &str,
    qtype: &str,
    trace: bool,
    json_path: Option<&Path>,
    viz_dir: Option<&Path>,
) -> Result<(), String> {
    // Read the template before querying; Task B supplies this runtime asset.
    let template = if viz_dir.is_some() {
        Some(
            std::fs::read_to_string("site/viz/index.html")
                .map_err(|e| format!("site/viz/index.html: {e}"))?,
        )
    } else {
        None
    };
    let name: Name = name.parse().map_err(|e| format!("{e}"))?;
    let qtype: RType = qtype.parse()?;
    let before = resolver.stats.upstream_queries.load(Ordering::Relaxed);
    let start = Instant::now();
    let (res, steps) = if json_path.is_some() || viz_dir.is_some() {
        let (res, recorded) = resolver.resolve_with_trace(&name, qtype);
        if let Some(path) = json_path {
            std::fs::write(path, recorded.to_json())
                .map_err(|e| format!("trace-json {}: {e}", path.display()))?;
        }
        if let (Some(dir), Some(template)) = (viz_dir, template) {
            std::fs::create_dir_all(dir).map_err(|e| format!("viz {}: {e}", dir.display()))?;
            let path = dir.join("index.html");
            std::fs::write(&path, recorded.embed_html(&template))
                .map_err(|e| format!("viz {}: {e}", path.display()))?;
            println!("{}", path.display());
        }
        (
            res,
            if trace {
                recorded
                    .events
                    .iter()
                    .map(ferrodns::trace::Event::text)
                    .collect()
            } else {
                vec![]
            },
        )
    } else {
        resolver.resolve_traced(&name, qtype, trace)
    };
    let elapsed = start.elapsed();
    let upstream = resolver.stats.upstream_queries.load(Ordering::Relaxed) - before;
    if trace {
        println!(";; TRACE:");
        for s in steps {
            println!(";;   {s}");
        }
    }
    match res {
        Ok(r) => {
            print_resolution(&name, qtype, &r, elapsed, upstream);
            Ok(())
        }
        Err(e) => Err(format!("SERVFAIL: {e}")),
    }
}

fn demo() -> Result<(), String> {
    let port = 15353;
    let net = sim::portable().map_err(|e| format!("starting simulated internet: {e}"))?;
    println!(
        "Portable simulated internet up on localhost ({} servers).\n",
        net.servers.len()
    );
    let cfg = Config {
        roots: net.roots.clone(),
        port,
        endpoints: net.endpoints.clone(),
        timeout: Duration::from_millis(300),
        ..Config::default()
    };
    let resolver = Resolver::new(cfg);
    let cases = [
        (
            "api.example.com",
            "A",
            "plain delegation chain: root -> com -> example.com",
        ),
        (
            "api.example.com",
            "A",
            "same question again: served from cache",
        ),
        (
            "www.example.com",
            "A",
            "CNAME into another zone (cdn-provider.net)",
        ),
        (
            "www.glueless.com",
            "A",
            "glueless delegation: must resolve the NS name first",
        ),
        (
            "nope.example.com",
            "A",
            "NXDOMAIN, negatively cached via SOA minimum",
        ),
        (
            "big.example.com",
            "TXT",
            "response too big for UDP: TC bit, retried over TCP",
        ),
    ];
    for (name, t, what) in cases {
        println!("=== {what}");
        query(&resolver, name, t, true)?;
        println!();
    }
    println!(
        "=== poisoning attempt: ns1.evil.com stuffs 'www.bank.com A 192.0.2.66' into every answer"
    );
    net.server("ns1.evil.com")
        .set_behavior(ferrodns::authority::Behavior {
            poison_additional: vec![ferrodns::wire::Record::new(
                "www.bank.com".parse().unwrap(),
                86400,
                ferrodns::wire::RData::A("192.0.2.66".parse().unwrap()),
            )],
            ..Default::default()
        });
    query(&resolver, "www.evil.com", "A", false)?;
    query(&resolver, "www.bank.com", "A", false)?;
    println!("(www.bank.com is 192.0.2.200: the out-of-bailiwick record was ignored)");
    let cs = resolver.cache_stats();
    println!(
        "\ncache: {} entries, {} hits, {} misses",
        resolver.cache_len(),
        cs.hits,
        cs.misses
    );
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().cloned() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let opts = match parse_args(&args[1..]) {
        Ok(o) => o,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("error: {e}\n");
            }
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    if (opts.trace_json.is_some() && cmd != "query")
        || (opts.cfg.trace_dir.is_some() && cmd != "serve")
        || (opts.out.is_some() && cmd != "viz")
    {
        eprintln!("--trace-json requires query; --trace-dir requires serve; --out requires viz");
        return ExitCode::from(2);
    }
    let result = match cmd.as_str() {
        "query" | "viz" => {
            let name = opts.positional.first().cloned().unwrap_or_default();
            let qtype = opts
                .positional
                .get(1)
                .cloned()
                .unwrap_or_else(|| "A".into());
            if name.is_empty() {
                Err("query needs a name".to_string())
            } else {
                let resolver = Resolver::new(opts.cfg);
                let out = opts.out.unwrap_or_else(|| PathBuf::from("ferrodns-viz"));
                query_output(
                    &resolver,
                    &name,
                    &qtype,
                    opts.trace,
                    opts.trace_json.as_deref(),
                    (cmd == "viz").then_some(out.as_path()),
                )
            }
        }
        "serve" => {
            if let Some(dir) = &opts.cfg.trace_dir
                && let Err(e) = std::fs::create_dir_all(dir)
            {
                eprintln!("trace-dir {}: {e}", dir.display());
                return ExitCode::FAILURE;
            }
            let resolver = Arc::new(Resolver::new(opts.cfg));
            eprintln!("ferrodns listening on {} (udp+tcp)", opts.listen);
            server::serve(resolver, opts.listen).map_err(|e| format!("serve: {e}"))
        }
        "demo" => demo(),
        "sim" => {
            let port: u16 = opts
                .positional
                .first()
                .and_then(|p| p.parse().ok())
                .unwrap_or(15353);
            match sim::portable() {
                Ok(net) => {
                    let cfg = Config {
                        roots: net.roots.clone(),
                        endpoints: net.endpoints.clone(),
                        ..Config::default()
                    };
                    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
                    if let Err(e) = server::spawn(Arc::new(Resolver::new(cfg)), addr) {
                        eprintln!("sim client listener: {e}");
                        return ExitCode::FAILURE;
                    }
                    eprintln!(
                        "portable simulated internet; recursive client endpoint {addr} (UDP + TCP)"
                    );
                    eprintln!("try: dig @127.0.0.1 -p {port} www.example.com");
                    loop {
                        std::thread::park();
                    }
                }
                Err(e) => Err(format!("sim: {e}")),
            }
        }
        _ => Err(format!("unknown command {cmd}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_json_is_written_before_reporting_resolution_failure() {
        let path = std::env::temp_dir().join(format!(
            "ferrodns-query-failure-{}.json",
            std::process::id()
        ));
        let resolver = Resolver::new(Config {
            max_queries: 0,
            ..Config::default()
        });
        let result = query_output(&resolver, "example.com", "A", true, Some(&path), None);
        assert_eq!(
            result,
            Err("SERVFAIL: upstream query budget exhausted".into())
        );
        let json = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        assert!(json.contains("\"rcode\":\"SERVFAIL\""));
        assert!(json.contains("\"name\":\"example.com.\""));
        assert_eq!(resolver.stats.client_queries.load(Ordering::Relaxed), 1);
    }
}
