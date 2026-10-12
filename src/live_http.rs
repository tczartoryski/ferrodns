//! Small isolated HTTP/1.1 GET + SSE service; never a DNS listener.
use crate::live_policy::{Control, hostname};
use crate::resolver::{Config, Resolver};
use crate::trace::string;
use crate::wire::{Name, RType};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

pub const ORIGIN: &str = "https://tczartoryski.github.io";
const HEADER_LIMIT: usize = 8192;
#[derive(Debug, PartialEq)]
pub enum Request {
    Health,
    Resolve(Name, RType),
}

pub fn parse(bytes: &[u8]) -> Result<Request, u16> {
    if bytes.len() > HEADER_LIMIT {
        return Err(431);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| 400u16)?;
    if !text.is_ascii() || !text.ends_with("\r\n\r\n") {
        return Err(400);
    }
    let mut lines = text[..text.len() - 4].split("\r\n");
    let parts: Vec<_> = lines.next().ok_or(400u16)?.split(' ').collect();
    if parts.len() != 3 || parts[2] != "HTTP/1.1" {
        return Err(400);
    }
    if parts[0] != "GET" {
        return Err(405);
    }
    let mut headers = HashMap::new();
    for line in lines {
        let (key, value) = line.split_once(':').ok_or(400u16)?;
        if key.is_empty()
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| b < 32 && b != b'\t' || b == 127)
        {
            return Err(400);
        }
        if headers
            .insert(key.to_ascii_lowercase(), value.trim())
            .is_some()
        {
            return Err(400);
        }
    }
    if headers.get("host").is_none_or(|h| h.is_empty()) {
        return Err(400);
    }
    if headers.contains_key("content-length")
        || headers.contains_key("transfer-encoding")
        || headers.contains_key("expect")
    {
        return Err(400);
    }
    if headers.get("origin").is_some_and(|o| *o != ORIGIN) {
        return Err(403);
    }
    if parts[1] == "/health" {
        return Ok(Request::Health);
    }
    let query = parts[1].strip_prefix("/resolve?").ok_or(404u16)?;
    let mut params = HashMap::new();
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').ok_or(400u16)?;
        if !["name", "type"].contains(&key) || params.insert(key, decode(value)?).is_some() {
            return Err(400);
        }
    }
    if params.len() != 2 {
        return Err(400);
    }
    let name = &params["name"];
    if !hostname(name) {
        return Err(400);
    }
    let qtype = match params["type"].as_str() {
        "A" => RType::A,
        "AAAA" => RType::AAAA,
        _ => return Err(400),
    };
    Ok(Request::Resolve(name.parse().map_err(|_| 400u16)?, qtype))
}
fn decode(value: &str) -> Result<String, u16> {
    let mut out = Vec::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let digits = bytes.get(i + 1..i + 3).ok_or(400u16)?;
            let hex = std::str::from_utf8(digits).map_err(|_| 400u16)?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| 400u16)?);
            i += 3;
        } else {
            out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| 400)
}

pub struct Slots {
    used: AtomicUsize,
    limit: usize,
}
pub struct Permit(Arc<Slots>);
impl Slots {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            used: AtomicUsize::new(0),
            limit,
        })
    }
    pub fn acquire(self: &Arc<Self>) -> Option<Permit> {
        let mut n = self.used.load(Ordering::Acquire);
        loop {
            if n >= self.limit {
                return None;
            }
            match self
                .used
                .compare_exchange_weak(n, n + 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Some(Permit(self.clone())),
                Err(actual) => n = actual,
            }
        }
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::AcqRel);
    }
}
struct Cancel(Control);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub struct Rates {
    since: Instant,
    global: usize,
    peers: HashMap<IpAddr, usize>,
}
impl Rates {
    pub fn new(now: Instant) -> Self {
        Self {
            since: now,
            global: 0,
            peers: HashMap::new(),
        }
    }
    pub fn allow(&mut self, peer: IpAddr, now: Instant) -> bool {
        if now.duration_since(self.since) >= Duration::from_secs(60) {
            self.since = now;
            self.global = 0;
            self.peers.clear();
        }
        if self.global >= 30
            || self.peers.get(&peer).copied().unwrap_or(0) >= 6
            || (!self.peers.contains_key(&peer) && self.peers.len() >= 1024)
        {
            return false;
        }
        self.global += 1;
        *self.peers.entry(peer).or_default() += 1;
        true
    }
}

fn read_request(s: &mut TcpStream, timeout: Duration) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    let mut buf = [0; 1024];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        s.set_read_timeout(Some(left))?;
        let n = s.read(&mut buf)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        bytes.extend_from_slice(&buf[..n]);
        if bytes.len() > HEADER_LIMIT {
            return Ok(bytes);
        }
        if bytes.windows(4).any(|b| b == b"\r\n\r\n") {
            return Ok(bytes);
        }
    }
}
fn response(s: &mut TcpStream, status: u16, body: &str) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        _ => "Service Unavailable",
    };
    write!(
        s,
        "HTTP/1.1 {status} {reason}\r\nAccess-Control-Allow-Origin: {ORIGIN}\r\nVary: Origin\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    )
}
fn event(s: &mut TcpStream, name: &str, json: &str) -> io::Result<()> {
    write!(s, "event: {name}\ndata: {json}\n\n")?;
    s.flush()
}

pub fn serve(bind: SocketAddr) -> io::Result<()> {
    let listener = TcpListener::bind(bind)?;
    eprintln!("live HTTP listening on {}", listener.local_addr()?);
    let connections = Slots::new(16);
    let active = Slots::new(4);
    let rates = Arc::new(Mutex::new(Rates::new(Instant::now())));
    let resolver = Arc::new(Resolver::new(Config {
        max_queries: 32,
        max_referrals: 12,
        max_cname: 8,
        max_depth: 4,
        cache: crate::cache::CacheConfig {
            max_entries: 256,
            ..Default::default()
        },
        ..Config::default()
    }));
    for stream in listener.incoming() {
        let mut stream = stream?;
        let Some(connection) = connections.acquire() else {
            continue;
        };
        let active = active.clone();
        let rates = rates.clone();
        let resolver = resolver.clone();
        std::thread::spawn(move || {
            let _connection = connection;
            let _ = handle(&mut stream, active, rates, resolver);
        });
    }
    Ok(())
}
fn handle(
    s: &mut TcpStream,
    active: Arc<Slots>,
    rates: Arc<Mutex<Rates>>,
    resolver: Arc<Resolver>,
) -> io::Result<()> {
    s.set_write_timeout(Some(Duration::from_secs(1)))?;
    let bytes = match read_request(s, Duration::from_secs(3)) {
        Ok(b) => b,
        Err(_) => return response(s, 408, "Request timeout\n"),
    };
    let request = match parse(&bytes) {
        Ok(r) => r,
        Err(code) => return response(s, code, "Rejected request\n"),
    };
    // Only the socket peer is trusted. Shared proxies share this conservative allowance.
    if !rates
        .lock()
        .unwrap()
        .allow(s.peer_addr()?.ip(), Instant::now())
    {
        return response(s, 429, "Rate limit\n");
    }
    let Request::Resolve(name, qtype) = request else {
        return response(s, 200, "ok\n");
    };
    let Some(slot) = active.acquire() else {
        return response(s, 503, "Busy\n");
    };
    let control = Control::new(true, Duration::from_secs(15));
    let _cancel = Cancel(control.clone());
    write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nAccess-Control-Allow-Origin: {ORIGIN}\r\nVary: Origin\r\nCache-Control: no-store\r\nX-Accel-Buffering: no\r\nConnection: close\r\n\r\n"
    )?;
    event(
        s,
        "started",
        &format!(
            "{{\"question\":{{\"name\":{},\"type\":{}}}}}",
            string(&name.to_string()),
            string(&qtype.to_string())
        ),
    )?;
    let (tx, rx) = mpsc::sync_channel::<(&'static str, String)>(128);
    let worker_control = control.clone();
    std::thread::spawn(move || {
        let _slot = slot;
        let sink_tx = tx.clone();
        let sink_control = worker_control.clone();
        let sink = Arc::new(move |mut e: crate::trace::Event| {
            if e.detail.len() > 2048 {
                e.detail.truncate(e.detail.floor_char_boundary(2048));
            }
            if sink_tx.try_send(("trace", e.to_json())).is_err() {
                sink_control.cancel();
                false
            } else {
                true
            }
        });
        let (result, mut trace) = resolver.resolve_live(&name, qtype, worker_control.clone(), sink);
        trace.answers.truncate(64);
        for answer in &mut trace.answers {
            if answer.len() > 2048 {
                answer.truncate(answer.floor_char_boundary(2048));
            }
        }
        let terminal = match result {
            Ok(_) => ("done", trace.to_json()),
            Err(e) => (
                "error",
                format!(
                    "{{\"status\":\"error\",\"message\":{}}}",
                    string(&e.to_string())
                ),
            ),
        };
        if tx.try_send(terminal).is_err() {
            worker_control.cancel();
        }
    });
    s.set_read_timeout(Some(Duration::from_millis(1)))?;
    let mut heartbeat = Instant::now();
    loop {
        if let Err(message) = control.status() {
            event(
                s,
                "error",
                &format!("{{\"status\":\"error\",\"message\":{}}}", string(message)),
            )?;
            return Ok(());
        }
        let mut probe = [0];
        match s.peek(&mut probe) {
            Ok(_) => return Ok(()), // EOF, or unexpected request body/pipelining.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e),
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok((kind, json)) => {
                event(s, kind, &json)?;
                if kind == "done" || kind == "error" {
                    return Ok(());
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                event(
                    s,
                    "error",
                    "{\"status\":\"error\",\"message\":\"stream interrupted\"}",
                )?;
                return Ok(());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Err(message) = control.status() {
                    event(
                        s,
                        "error",
                        &format!("{{\"status\":\"error\",\"message\":{}}}", string(message)),
                    )?;
                    return Ok(());
                }
                if heartbeat.elapsed() >= Duration::from_secs(1) {
                    s.write_all(b": heartbeat\n\n")?;
                    s.flush()?;
                    heartbeat = Instant::now();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn req(path: &str, headers: &str) -> Vec<u8> {
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{headers}\r\n").into_bytes()
    }
    #[test]
    fn strict_http() {
        assert_eq!(parse(&req("/health", "")), Ok(Request::Health));
        assert!(matches!(
            parse(&req(
                "/resolve?name=example.com&type=AAAA",
                &format!("Origin: {ORIGIN}\r\n")
            )),
            Ok(Request::Resolve(_, RType::AAAA))
        ));
        for path in [
            "/resolve?name=localhost&type=A",
            "/resolve?name=x.test&type=A",
            "/resolve?name=example.com&type=TXT",
            "/resolve?name=example.com&type=A&type=A",
            "/resolve?name=example.com&type=A&root=1",
            "/resolve?name=%zz&type=A",
            "/resolve?name=127.0.0.1&type=A",
        ] {
            assert!(parse(&req(path, "")).is_err(), "{path}");
        }
        for header in [
            "Origin: null\r\n",
            "Origin: https://tczartoryski.github.io/ferrodns\r\n",
            "Origin: https://evil.test\r\n",
            "Content-Length: 0\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Host: duplicate\r\n",
            " bad: value\r\n",
        ] {
            assert!(parse(&req("/health", header)).is_err());
        }
        assert!(
            parse(
                &req("/health", "")
                    .into_iter()
                    .chain(b"BODY".iter().copied())
                    .collect::<Vec<_>>()
            )
            .is_err()
        );
        assert_eq!(parse(&vec![b'x'; 8193]), Err(431));
        assert_eq!(parse(b"POST /health HTTP/1.1\r\nHost: x\r\n\r\n"), Err(405));
        assert_eq!(parse(b"GET /health HTTP/1.0\r\nHost: x\r\n\r\n"), Err(400));
    }
    #[test]
    fn rate_and_slots() {
        let now = Instant::now();
        let mut rates = Rates::new(now);
        let ip = "127.0.0.1".parse().unwrap();
        for _ in 0..6 {
            assert!(rates.allow(ip, now));
        }
        assert!(!rates.allow(ip, now));
        for n in 2..6 {
            for _ in 0..6 {
                assert!(rates.allow(IpAddr::from([127, 0, 0, n]), now));
            }
        }
        assert!(!rates.allow(IpAddr::from([127, 0, 0, 6]), now));
        assert!(rates.allow(ip, now + Duration::from_secs(60)));
        let slots = Slots::new(4);
        let permits: Vec<_> = (0..4).map(|_| slots.acquire().unwrap()).collect();
        assert!(slots.acquire().is_none());
        drop(permits);
        assert!(slots.acquire().is_some());
    }
    #[test]
    fn cancellation_guard_releases_on_every_exit() {
        let control = Control::new(true, Duration::from_secs(1));
        {
            let _guard = Cancel(control.clone());
            assert!(control.status().is_ok());
        }
        assert_eq!(control.status(), Err("cancelled"));
    }
    fn http_roundtrip(request: &[u8], active_limit: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            handle(
                &mut socket,
                Slots::new(active_limit),
                Arc::new(Mutex::new(Rates::new(Instant::now()))),
                Arc::new(Resolver::new(Config {
                    max_queries: 0,
                    ..Config::default()
                })),
            )
            .unwrap();
        });
        let mut client = TcpStream::connect(endpoint).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client.write_all(request).unwrap();
        let mut output = String::new();
        client.read_to_string(&mut output).unwrap();
        worker.join().unwrap();
        output
    }
    #[test]
    fn wire_http_cors_errors_busy_and_exact_sse_terminal() {
        let output = http_roundtrip(&req("/health", ""), 4);
        assert!(output.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(output.ends_with("ok\n"));
        assert!(output.contains(&format!("Access-Control-Allow-Origin: {ORIGIN}\r\n")));
        assert!(
            http_roundtrip(&req("/health", "Origin: https://evil.test\r\n"), 4)
                .starts_with("HTTP/1.1 403")
        );
        assert!(
            http_roundtrip(&req("/resolve?name=example.com&type=A", ""), 0)
                .starts_with("HTTP/1.1 503")
        );
        let output = http_roundtrip(&req("/resolve?name=example.com&type=A", ""), 4);
        assert!(output.contains("Content-Type: text/event-stream\r\n"));
        assert_eq!(output.matches("event: started\n").count(), 1);
        assert_eq!(output.matches("event: error\n").count(), 1);
        assert!(!output.contains("event: done"));
        assert!(output.find("event: started").unwrap() < output.find("event: error").unwrap());
        assert!(output.contains("upstream query budget exhausted"));
    }
    #[test]
    fn slow_headers_absolute_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let worker = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let start = Instant::now();
            assert!(read_request(&mut s, Duration::from_millis(100)).is_err());
            assert!(start.elapsed() < Duration::from_secs(1));
        });
        for _ in 0..15 {
            if client.write_all(b"G").is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        worker.join().unwrap();
    }
}
