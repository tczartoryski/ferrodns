//! Integration tests against the simulated internet in `ferrodns::sim`.
//! Each test uses its own port so the suite runs in parallel.

use ferrodns::authority::Behavior;
use ferrodns::resolver::{Config, ResolveError, Resolver};
use ferrodns::sim::{self, SimNet};
use ferrodns::wire::{Edns, Message, Name, RData, RType, Record, rcode};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn setup(port: u16) -> (SimNet, Resolver) {
    let net = sim::portable().expect("start sim");
    let cfg = Config {
        roots: net.roots.clone(),
        port,
        endpoints: net.endpoints.clone(),
        timeout: Duration::from_millis(200),
        ..Config::default()
    };
    (net, Resolver::new(cfg))
}

fn ips(records: &[Record]) -> Vec<IpAddr> {
    records
        .iter()
        .filter_map(|r| match r.data {
            RData::A(ip) => Some(IpAddr::V4(ip)),
            RData::Aaaa(ip) => Some(IpAddr::V6(ip)),
            _ => None,
        })
        .collect()
}

fn v4(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn follows_delegation_chain_from_the_root() {
    let (_net, r) = setup(21001);
    let (res, trace) = r.resolve_traced(&n("api.example.com"), RType::A, true);
    let res = res.unwrap();
    assert_eq!(res.rcode, rcode::NOERROR);
    let mut got = ips(&res.answers);
    got.sort();
    assert_eq!(got, vec![v4("192.0.2.10"), v4("192.0.2.11")]);
    let joined = trace.join("\n");
    assert!(
        joined.contains("[.]") && joined.contains("referral to com."),
        "{joined}"
    );
    assert!(joined.contains("referral to example.com."), "{joined}");
}

#[test]
fn second_query_is_served_from_cache() {
    let (net, r) = setup(21002);
    r.resolve(&n("api.example.com"), RType::A).unwrap();
    let before = net.total_queries();
    let res = r.resolve(&n("api.example.com"), RType::A).unwrap();
    assert_eq!(
        net.total_queries(),
        before,
        "no upstream traffic on a cache hit"
    );
    assert_eq!(res.answers.len(), 2);
    // Sibling names reuse the cached delegation: only the example.com server is asked.
    let root_before = net.server("a.root-servers.net").query_count()
        + net.server("b.root-servers.net").query_count();
    r.resolve(&n("mail.example.com"), RType::A).unwrap();
    let root_after = net.server("a.root-servers.net").query_count()
        + net.server("b.root-servers.net").query_count();
    assert_eq!(root_before, root_after);
    assert_eq!(net.total_queries(), before + 1);
}

#[test]
fn chases_cname_into_another_zone() {
    let (_net, r) = setup(21003);
    let res = r.resolve(&n("www.example.com"), RType::A).unwrap();
    assert_eq!(res.answers[0].rtype, RType::CNAME);
    assert_eq!(res.answers[0].target(), Some(&n("web.cdn-provider.net")));
    assert_eq!(ips(&res.answers), vec![v4("198.51.100.7")]);
    // In-zone CNAME chain.
    let res = r.resolve(&n("alias.example.com"), RType::A).unwrap();
    assert_eq!(res.answers.len(), 3);
}

#[test]
fn resolves_glueless_delegations() {
    let (_net, r) = setup(21004);
    let (res, trace) = r.resolve_traced(&n("www.glueless.com"), RType::A, true);
    assert_eq!(ips(&res.unwrap().answers), vec![v4("203.0.113.5")]);
    assert!(
        trace.iter().any(|l| l.contains("glueless delegation")),
        "{trace:?}"
    );
}

#[test]
fn nxdomain_is_negatively_cached_including_names_below_it() {
    let (net, r) = setup(21005);
    let res = r.resolve(&n("nope.example.com"), RType::A).unwrap();
    assert_eq!(res.rcode, rcode::NXDOMAIN);
    assert_eq!(res.authority[0].rtype, RType::SOA);
    let before = net.total_queries();
    assert_eq!(
        r.resolve(&n("nope.example.com"), RType::AAAA)
            .unwrap()
            .rcode,
        rcode::NXDOMAIN
    );
    // RFC 8020: nothing exists below an NXDOMAIN.
    assert_eq!(
        r.resolve(&n("a.b.nope.example.com"), RType::A)
            .unwrap()
            .rcode,
        rcode::NXDOMAIN
    );
    assert_eq!(net.total_queries(), before);
}

#[test]
fn nodata_and_empty_non_terminals() {
    let (net, r) = setup(21006);
    let res = r.resolve(&n("api.example.com"), RType::AAAA).unwrap();
    assert_eq!(res.rcode, rcode::NOERROR);
    assert!(res.answers.is_empty());
    assert_eq!(res.authority[0].rtype, RType::SOA);
    let before = net.total_queries();
    r.resolve(&n("api.example.com"), RType::AAAA).unwrap();
    assert_eq!(net.total_queries(), before, "NODATA cached");
    // empty.example.com has no records but deep.empty.example.com does: NODATA, not NXDOMAIN.
    assert_eq!(
        r.resolve(&n("empty.example.com"), RType::A).unwrap().rcode,
        rcode::NOERROR
    );
}

#[test]
fn fails_over_from_a_dead_nameserver_and_learns_to_avoid_it() {
    let (net, r) = setup(21007);
    net.server("ns1.example.com").set_behavior(Behavior {
        drop: true,
        ..Default::default()
    });
    for name in [
        "api.example.com",
        "mail.example.com",
        "txt.example.com",
        "www.example.com",
    ] {
        let qt = if name.starts_with("txt") {
            RType::TXT
        } else {
            RType::A
        };
        let res = r.resolve(&n(name), qt).unwrap();
        assert!(!res.answers.is_empty(), "{name}");
    }
    // After at most one timeout, SRTT ordering sends traffic to ns2 first.
    assert!(
        net.server("ns1.example.com").query_count() <= 1,
        "dead server retried {} times",
        net.server("ns1.example.com").query_count()
    );
}

#[test]
fn servfail_and_refused_servers_are_skipped() {
    let (net, r) = setup(21008);
    net.server("ns1.example.com").set_behavior(Behavior {
        rcode: Some(rcode::SERVFAIL),
        ..Default::default()
    });
    net.server("ns2.example.com").set_behavior(Behavior {
        rcode: Some(rcode::REFUSED),
        ..Default::default()
    });
    let err = r.resolve(&n("api.example.com"), RType::A).unwrap_err();
    assert_eq!(err, ResolveError::AllServersFailed(n("example.com")));
    // Recovery once one server is healthy again.
    net.server("ns2.example.com")
        .set_behavior(Behavior::default());
    assert_eq!(
        r.resolve(&n("api.example.com"), RType::A)
            .unwrap()
            .answers
            .len(),
        2
    );
}

#[test]
fn truncated_udp_falls_back_to_tcp() {
    let (_net, r) = setup(21009);
    let res = r.resolve(&n("big.example.com"), RType::TXT).unwrap();
    assert_eq!(res.answers.len(), 24);
    assert!(r.stats.tcp_fallbacks.load(Ordering::Relaxed) >= 1);
}

#[test]
fn ignores_out_of_bailiwick_poison() {
    let (net, r) = setup(21010);
    let fake = Ipv4Addr::new(192, 0, 2, 66);
    net.server("ns1.evil.com").set_behavior(Behavior {
        poison_additional: vec![
            Record::new(n("www.bank.com"), 86400, RData::A(fake)),
            Record::new(n("ns1.bank.com"), 86400, RData::A(fake)),
        ],
        poison_authority: vec![Record::new(
            n("bank.com"),
            86400,
            RData::Ns(n("ns1.evil.com")),
        )],
        ..Default::default()
    });
    assert_eq!(
        ips(&r.resolve(&n("www.evil.com"), RType::A).unwrap().answers),
        vec![v4("192.0.2.77")]
    );
    assert_eq!(
        ips(&r.resolve(&n("www.bank.com"), RType::A).unwrap().answers),
        vec![v4("192.0.2.200")]
    );
    assert!(
        net.server("ns1.bank.com").query_count() >= 1,
        "bank.com was resolved via its real server"
    );
}

#[test]
fn cname_loops_are_detected() {
    let (_net, r) = setup(21011);
    assert_eq!(
        r.resolve(&n("loop1.example.com"), RType::A).unwrap_err(),
        ResolveError::CnameLoop
    );
}

#[test]
fn unreachable_roots_fail_cleanly() {
    let (net, r) = setup(21012);
    for h in ["a.root-servers.net", "b.root-servers.net"] {
        net.server(h).set_behavior(Behavior {
            drop: true,
            ..Default::default()
        });
    }
    assert_eq!(
        r.resolve(&n("api.example.com"), RType::A).unwrap_err(),
        ResolveError::AllServersFailed(Name::root())
    );
}

#[test]
fn work_per_request_is_bounded() {
    let net = sim::portable().unwrap();
    let cfg = Config {
        roots: net.roots.clone(),
        port: 21013,
        endpoints: net.endpoints.clone(),
        timeout: Duration::from_millis(200),
        max_queries: 2,
        ..Config::default()
    };
    let r = Resolver::new(cfg);
    assert_eq!(
        r.resolve(&n("api.example.com"), RType::A).unwrap_err(),
        ResolveError::QueryBudgetExhausted
    );
}

#[test]
fn concurrent_clients_share_one_cache() {
    let (_net, r) = setup(21014);
    let r = Arc::new(r);
    let handles: Vec<_> = (0..32)
        .map(|i| {
            let r = Arc::clone(&r);
            std::thread::spawn(move || {
                let name = [
                    "api.example.com",
                    "www.example.com",
                    "www.glueless.com",
                    "www.bank.com",
                ][i % 4];
                r.resolve(&n(name), RType::A).unwrap()
            })
        })
        .collect();
    for h in handles {
        assert!(!h.join().unwrap().answers.is_empty());
    }
}

// ---- end to end through the recursive server ----

fn client_query(name: &str, qtype: RType, edns: bool) -> Message {
    let mut q = Message::query(0x4242, n(name), qtype, true, edns.then(|| Edns::new(4096)));
    q.header.rd = true;
    q
}

fn udp_ask(server: SocketAddr, q: &Message) -> Message {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.send_to(&q.to_bytes().unwrap(), server).unwrap();
    let mut buf = [0u8; 65535];
    let (len, _) = s.recv_from(&mut buf).unwrap();
    Message::parse(&buf[..len]).unwrap()
}

fn tcp_ask(server: SocketAddr, q: &Message) -> Message {
    let mut s = TcpStream::connect(server).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let b = q.to_bytes().unwrap();
    let mut framed = (b.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&b);
    s.write_all(&framed).unwrap();
    let mut len = [0u8; 2];
    s.read_exact(&mut len).unwrap();
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut buf).unwrap();
    Message::parse(&buf).unwrap()
}

#[test]
fn serves_stub_clients_over_udp_and_tcp() {
    let (_net, r) = setup(21015);
    let addr: SocketAddr = "127.0.0.1:21115".parse().unwrap();
    ferrodns::server::spawn(Arc::new(r), addr).unwrap();
    std::thread::sleep(Duration::from_millis(50));

    let resp = udp_ask(addr, &client_query("www.example.com", RType::A, true));
    assert!(resp.header.qr && resp.header.ra && resp.header.rd);
    assert_eq!(resp.header.id, 0x4242);
    assert_eq!(resp.header.rcode, rcode::NOERROR);
    assert_eq!(resp.answers.len(), 2);
    assert!(resp.edns.is_some());

    // Without EDNS the 512-byte limit applies: big answer comes back truncated...
    let resp = udp_ask(addr, &client_query("big.example.com", RType::TXT, false));
    assert!(resp.header.tc && resp.answers.is_empty());
    // ...and the client gets it in full over TCP.
    let resp = tcp_ask(addr, &client_query("big.example.com", RType::TXT, false));
    assert!(!resp.header.tc);
    assert_eq!(resp.answers.len(), 24);

    let resp = udp_ask(addr, &client_query("nope.example.com", RType::A, true));
    assert_eq!(resp.header.rcode, rcode::NXDOMAIN);
    assert_eq!(resp.authority.len(), 1);

    let resp = udp_ask(addr, &client_query("loop1.example.com", RType::A, true));
    assert_eq!(resp.header.rcode, rcode::SERVFAIL);

    // Garbage gets FORMERR, not silence or a crash.
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.send_to(
        &[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xFF],
        addr,
    )
    .unwrap();
    let mut buf = [0u8; 512];
    let (len, _) = s.recv_from(&mut buf).unwrap();
    let resp = Message::parse(&buf[..len]).unwrap();
    assert_eq!(resp.header.rcode, rcode::FORMERR);
    assert_eq!(resp.header.id, 0x1234);
}

#[test]
fn portable_sim_uses_only_localhost_and_isolates_servers() {
    let net = sim::portable().unwrap();
    let endpoints: std::collections::HashSet<_> = net.endpoints.values().copied().collect();
    assert_eq!(endpoints.len(), net.servers.len());
    assert!(
        endpoints
            .iter()
            .all(|a| a.ip() == v4("127.0.0.1") && a.port() != 0)
    );
    let r = Resolver::new(Config {
        roots: net.roots.clone(),
        endpoints: net.endpoints.clone(),
        ..Config::default()
    });
    assert_eq!(
        ips(&r.resolve(&n("api.example.com"), RType::A).unwrap().answers).len(),
        2
    );
    assert_eq!(
        r.resolve(&n("big.example.com"), RType::TXT)
            .unwrap()
            .answers
            .len(),
        24
    );
    assert!(r.stats.tcp_fallbacks.load(Ordering::Relaxed) > 0);
}

// Kept in this test file so the golden fixture stays within Task A's file scope.
const LOOKUP_GOLDEN: &str = concat!(
    r#"{"question":{"name":"api.example.com.","type":"A"},"started_at":"TIME","total_ms":0.000,"rcode":"NOERROR","answers":["api.example.com. 300 IN A 192.0.2.10","api.example.com. 300 IN A 192.0.2.11"],"events":["#,
    r#"{"t_ms":0.000,"dur_ms":0.000,"depth":0,"kind":"query","zone":".","server":"ns1.example.com.","ip":"127.0.0.30","qname":"api.example.com.","qtype":"A","transport":"udp","outcome":"answer","detail":"ANSWER 192.0.2.10, 192.0.2.11"}]}"#,
);

#[test]
fn structured_sim_lookup_matches_golden() {
    let net = sim::portable().unwrap();
    let resolver = Resolver::new(Config {
        roots: vec![ferrodns::hints::Hint {
            name: n("ns1.example.com"),
            addr: v4("127.0.0.30"),
        }],
        endpoints: net.endpoints.clone(),
        ..Config::default()
    });
    let (result, mut trace) = resolver.resolve_with_trace(&n("api.example.com"), RType::A);
    result.unwrap();
    assert_eq!(trace.events.len(), 1);
    assert!(trace.total_ms >= trace.events[0].dur_ms);
    trace.started_at = "TIME".into();
    trace.total_ms = 0.0;
    for event in &mut trace.events {
        event.t_ms = 0.0;
        event.dur_ms = 0.0;
    }
    assert_eq!(trace.to_json(), LOOKUP_GOLDEN);
    let (result, cached) = resolver.resolve_with_trace(&n("api.example.com"), RType::A);
    result.unwrap();
    assert_eq!(cached.events.len(), 1);
    assert_eq!(cached.events[0].kind, "cache_hit");
}

#[test]
fn structured_events_cover_cname_glueless_and_tcp() {
    let (_net, resolver) = setup(21017);
    let (result, trace) = resolver.resolve_with_trace(&n("www.example.com"), RType::A);
    result.unwrap();
    assert!(trace.events.iter().any(|e| e.kind == "cname"));
    assert!(trace.events.iter().any(|e| e.outcome == Some("referral")));
    let (result, trace) = resolver.resolve_with_trace(&n("www.glueless.com"), RType::A);
    result.unwrap();
    assert!(trace.events.iter().any(|e| e.kind == "glueless"));
    assert!(
        trace
            .events
            .iter()
            .any(|e| e.depth == 1 && e.kind == "query")
    );
    let (result, trace) = resolver.resolve_with_trace(&n("big.example.com"), RType::TXT);
    result.unwrap();
    let event = trace
        .events
        .iter()
        .find(|e| e.transport == Some("tcp"))
        .unwrap();
    assert_eq!(event.outcome, Some("answer"));
    assert!(event.text().contains("TC, retried over TCP"));
    assert!(event.dur_ms > 0.0);
}

#[test]
fn failed_udp_exchange_has_null_transport() {
    let (net, resolver) = setup(21018);
    for name in ["a.root-servers.net", "b.root-servers.net"] {
        net.server(name).set_behavior(Behavior {
            drop: true,
            ..Default::default()
        });
    }
    let (result, trace) = resolver.resolve_with_trace(&n("api.example.com"), RType::A);
    assert!(result.is_err());
    assert_eq!(trace.rcode, "SERVFAIL");
    assert_eq!(trace.events.len(), 2);
    for event in &trace.events {
        assert_eq!(event.transport, None);
        assert_eq!(event.outcome, Some("timeout"));
        assert!(event.dur_ms > 0.0);
    }
    assert_eq!(trace.to_json().matches("\"transport\":null").count(), 2);
}

#[test]
fn failed_tcp_fallback_has_null_transport() {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = std::net::TcpListener::bind(addr).unwrap();
    tcp.set_nonblocking(true).unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let worker = std::thread::spawn(move || {
        let mut buf = [0; 4096];
        let (len, peer) = udp.recv_from(&mut buf).unwrap();
        let mut response = Message::parse(&buf[..len]).unwrap();
        response.header.qr = true;
        response.header.tc = true;
        udp.send_to(&response.to_bytes().unwrap(), peer).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match tcp.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "no TCP fallback connection"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("TCP accept: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut len = [0; 2];
        stream.read_exact(&mut len).unwrap();
        let mut query = vec![0; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut query).unwrap();
        // A mismatched TCP reply is an error after a genuine UDP -> TCP fallback.
        response.header.tc = false;
        response.header.id = response.header.id.wrapping_add(1);
        let bytes = response.to_bytes().unwrap();
        stream
            .write_all(&(bytes.len() as u16).to_be_bytes())
            .unwrap();
        stream.write_all(&bytes).unwrap();
    });
    let resolver = Resolver::new(Config {
        roots: vec![ferrodns::hints::Hint {
            name: n("ns.fail"),
            addr: addr.ip(),
        }],
        port: addr.port(),
        timeout: Duration::from_secs(2),
        ..Config::default()
    });
    let (result, trace) = resolver.resolve_with_trace(&n("api.example.com"), RType::A);
    worker.join().unwrap();
    assert!(result.is_err());
    assert_eq!(trace.events.len(), 1);
    assert_eq!(trace.events[0].transport, None);
    assert_eq!(trace.events[0].outcome, Some("error"));
    assert_eq!(trace.events[0].detail, "response does not match query");
    assert!(trace.to_json().contains("\"transport\":null"));
}

struct TraceTestDir(std::path::PathBuf);
impl TraceTestDir {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ferrodns-trace-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for TraceTestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn trace_directory_records_concurrent_client_failures_without_overwrites() {
    let dir = TraceTestDir::new();
    // Simulate files left by a previous process with the same PID.
    for id in 0..32 {
        std::fs::write(
            dir.0
                .join(format!("trace-{}-{id}.json", std::process::id())),
            "existing",
        )
        .unwrap();
    }
    let resolver = Arc::new(Resolver::new(Config {
        max_queries: 0,
        trace_dir: Some(dir.0.clone()),
        ..Config::default()
    }));
    let workers: Vec<_> = (0..8)
        .map(|i| {
            let resolver = Arc::clone(&resolver);
            std::thread::spawn(move || {
                let query = client_query("api.example.com", RType::A, false)
                    .to_bytes()
                    .unwrap();
                let bytes = ferrodns::server::handle_packet(&resolver, &query, i % 2 == 0).unwrap();
                assert_eq!(
                    Message::parse(&bytes).unwrap().header.rcode,
                    rcode::SERVFAIL
                );
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let mut new_files = 0;
    for file in std::fs::read_dir(&dir.0).unwrap() {
        let text = std::fs::read_to_string(file.unwrap().path()).unwrap();
        if text != "existing" {
            new_files += 1;
            assert!(text.contains("\"rcode\":\"SERVFAIL\""));
            assert!(text.contains("\"name\":\"api.example.com.\""));
        }
    }
    assert_eq!(new_files, 8);
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 40);
    assert_eq!(resolver.stats.client_queries.load(Ordering::Relaxed), 8);
    // Packet rejection occurs before resolution, so it cannot create a trace in this scope.
    let query = client_query("api.example.com", RType::ANY, false)
        .to_bytes()
        .unwrap();
    ferrodns::server::handle_packet(&resolver, &query, true).unwrap();
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 40);
}

#[test]
fn trace_write_error_does_not_replace_resolution_result() {
    let dir = TraceTestDir::new();
    let resolver = Resolver::new(Config {
        max_queries: 0,
        trace_dir: Some(dir.0.join("missing")),
        ..Config::default()
    });
    let (result, text) = resolver.resolve_traced(&n("api.example.com"), RType::A, false);
    assert_eq!(result, Err(ResolveError::QueryBudgetExhausted));
    assert!(text.is_empty());
}
