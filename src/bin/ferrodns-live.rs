use std::net::SocketAddr;
fn main() {
    let mut args = std::env::args().skip(1);
    let bind: SocketAddr = match args.next().as_deref() {
        None => "127.0.0.1:8080".parse().unwrap(),
        Some("--bind") => args
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| usage()),
        _ => usage(),
    };
    if args.next().is_some() || bind.port() < 1024 {
        usage();
    }
    if let Err(e) = ferrodns::live_http::serve(bind) {
        eprintln!("live: {e}");
        std::process::exit(1);
    }
}
fn usage() -> ! {
    eprintln!("usage: ferrodns-live [--bind IP:PORT] (unprivileged HTTP port only)");
    std::process::exit(2)
}
