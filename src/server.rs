//! The recursive server: accepts stub queries over UDP and TCP and answers
//! them using the resolver.

use crate::resolver::{EDNS_UDP_SIZE, Resolver};
use crate::wire::{Edns, Header, Message, RClass, RType, opcode, rcode};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// Maximum client queries being worked on at once; beyond this UDP queries are dropped.
const MAX_INFLIGHT: usize = 1024;
const BADVERS: u16 = 16;

/// Build the wire response for one client packet. `udp` selects size limits.
/// Returns None when the packet should be silently dropped.
pub fn handle_packet(resolver: &Resolver, packet: &[u8], udp: bool) -> Option<Vec<u8>> {
    let query = match Message::parse(packet) {
        Ok(q) => q,
        Err(_) => {
            // FORMERR if we can at least read a header that isn't a response.
            if packet.len() < 12 || packet[2] & 0x80 != 0 {
                return None;
            }
            let id = u16::from_be_bytes([packet[0], packet[1]]);
            let resp = Message {
                header: Header {
                    id,
                    qr: true,
                    ra: true,
                    rcode: rcode::FORMERR,
                    ..Default::default()
                },
                ..Default::default()
            };
            return resp.to_bytes().ok();
        }
    };
    if query.header.qr {
        return None;
    }
    let mut resp = Message {
        header: Header {
            id: query.header.id,
            qr: true,
            opcode: query.header.opcode,
            rd: query.header.rd,
            ra: true,
            cd: query.header.cd,
            ..Default::default()
        },
        questions: query.questions.clone(),
        edns: query.edns.as_ref().map(|_| Edns::new(EDNS_UDP_SIZE)),
        ..Default::default()
    };
    let limit = if !udp {
        65535
    } else {
        query
            .edns
            .as_ref()
            .map(|e| e.udp_size.clamp(512, EDNS_UDP_SIZE) as usize)
            .unwrap_or(512)
    };
    let finish = |m: &Message| m.to_bytes_limited(limit).ok();

    if let Some(e) = &query.edns
        && e.version != 0
    {
        let edns = resp.edns.as_mut().expect("set above");
        edns.ext_rcode = (BADVERS >> 4) as u8;
        resp.header.rcode = (BADVERS & 0xF) as u8;
        return finish(&resp);
    }
    if query.header.opcode != opcode::QUERY {
        resp.header.rcode = rcode::NOTIMP;
        return finish(&resp);
    }
    let [q] = query.questions.as_slice() else {
        resp.header.rcode = rcode::FORMERR;
        return finish(&resp);
    };
    if q.qclass != RClass::IN {
        resp.header.rcode = rcode::REFUSED;
        return finish(&resp);
    }
    if q.qtype == RType::ANY {
        // RFC 8482 lets us decline ANY; we keep it simple and refuse it.
        resp.header.rcode = rcode::NOTIMP;
        return finish(&resp);
    }
    match resolver.resolve(&q.name, q.qtype) {
        Ok(res) => {
            resp.header.rcode = res.rcode;
            resp.answers = res.answers;
            resp.authority = res.authority;
        }
        Err(_) => resp.header.rcode = rcode::SERVFAIL,
    }
    finish(&resp)
}

/// Run the server until the process exits. Blocks the calling thread on UDP.
pub fn serve(resolver: Arc<Resolver>, addr: SocketAddr) -> io::Result<()> {
    let udp = UdpSocket::bind(addr)?;
    let tcp = TcpListener::bind(addr)?;
    spawn_tcp(Arc::clone(&resolver), tcp);
    run_udp(resolver, udp)
}

/// Start the server on background threads (used by tests and embedding).
pub fn spawn(resolver: Arc<Resolver>, addr: SocketAddr) -> io::Result<()> {
    let udp = UdpSocket::bind(addr)?;
    let tcp = TcpListener::bind(addr)?;
    spawn_tcp(Arc::clone(&resolver), tcp);
    thread::spawn(move || run_udp(resolver, udp));
    Ok(())
}

fn run_udp(resolver: Arc<Resolver>, udp: UdpSocket) -> io::Result<()> {
    let inflight = Arc::new(AtomicUsize::new(0));
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, peer) = match udp.recv_from(&mut buf) {
            Ok(x) => x,
            Err(_) => continue,
        };
        if inflight.load(Ordering::Relaxed) >= MAX_INFLIGHT {
            continue;
        }
        inflight.fetch_add(1, Ordering::Relaxed);
        let packet = buf[..n].to_vec();
        let (resolver, sock, inflight) = (
            Arc::clone(&resolver),
            udp.try_clone()?,
            Arc::clone(&inflight),
        );
        thread::spawn(move || {
            if let Some(bytes) = handle_packet(&resolver, &packet, true) {
                let _ = sock.send_to(&bytes, peer);
            }
            inflight.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

fn spawn_tcp(resolver: Arc<Resolver>, tcp: TcpListener) {
    thread::spawn(move || {
        for stream in tcp.incoming().flatten() {
            let resolver = Arc::clone(&resolver);
            thread::spawn(move || serve_tcp_conn(&resolver, stream));
        }
    });
}

fn serve_tcp_conn(resolver: &Resolver, mut s: TcpStream) {
    // RFC 7766: support multiple queries per connection; close when idle.
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    let mut len = [0u8; 2];
    while s.read_exact(&mut len).is_ok() {
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        if s.read_exact(&mut buf).is_err() {
            return;
        }
        let Some(bytes) = handle_packet(resolver, &buf, false) else {
            return;
        };
        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&bytes);
        if s.write_all(&framed).is_err() {
            return;
        }
    }
}
