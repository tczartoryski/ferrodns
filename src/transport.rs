//! Sending one query to one server: UDP first, TCP on truncation (RFC 7766).

use crate::wire::{Message, WireError};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum TransportError {
    Timeout,
    Io(io::Error),
    Wire(WireError),
    /// A TCP response didn't match the query.
    Mismatch,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Timeout => write!(f, "timeout"),
            TransportError::Io(e) => write!(f, "io: {e}"),
            TransportError::Wire(e) => write!(f, "bad response: {e}"),
            TransportError::Mismatch => write!(f, "response does not match query"),
        }
    }
}

impl From<io::Error> for TransportError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => TransportError::Timeout,
            _ => TransportError::Io(e),
        }
    }
}

impl From<WireError> for TransportError {
    fn from(e: WireError) -> Self {
        TransportError::Wire(e)
    }
}

pub struct Exchange {
    pub response: Message,
    pub rtt: Duration,
    pub tcp: bool,
}

#[derive(Clone, Debug)]
pub struct Transport {
    /// Destination port for upstream queries (53 on the real internet).
    pub port: u16,
    pub timeout: Duration,
    /// Explicit test-network routes; empty for ordinary internet resolution.
    pub endpoints: HashMap<IpAddr, SocketAddr>,
}

/// A response only counts if it answers exactly the question we asked
/// (RFC 5452 §9.1). Anything else is ignored, not trusted.
fn matches(q: &Message, r: &Message) -> bool {
    r.header.qr
        && r.header.id == q.header.id
        && r.questions.len() == 1
        && r.questions == q.questions
}

impl Transport {
    pub fn exchange(&self, server: IpAddr, query: &Message) -> Result<Exchange, TransportError> {
        let start = Instant::now();
        let response = self.udp(server, query)?;
        if response.header.tc {
            let response = self.tcp(server, query)?;
            return Ok(Exchange {
                response,
                rtt: start.elapsed(),
                tcp: true,
            });
        }
        Ok(Exchange {
            response,
            rtt: start.elapsed(),
            tcp: false,
        })
    }

    fn udp(&self, server: IpAddr, query: &Message) -> Result<Message, TransportError> {
        let bind: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .unwrap();
        // A fresh socket per query gives each query its own OS-chosen ephemeral
        // port, which (together with the random ID) is the RFC 5452 defence.
        let sock = UdpSocket::bind(bind)?;
        // connect() makes the kernel drop datagrams from any other source.
        sock.connect(self.endpoint(server))?;
        sock.send(&query.to_bytes()?)?;
        let deadline = Instant::now() + self.timeout;
        let mut buf = vec![0u8; 65535];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(TransportError::Timeout);
            }
            sock.set_read_timeout(Some(left))?;
            let n = sock.recv(&mut buf)?;
            match Message::parse(&buf[..n]) {
                Ok(m) if matches(query, &m) => return Ok(m),
                // Garbage or a spoof attempt: keep waiting for the real answer.
                _ => continue,
            }
        }
    }

    fn endpoint(&self, server: IpAddr) -> SocketAddr {
        self.endpoints
            .get(&server)
            .copied()
            .unwrap_or(SocketAddr::new(server, self.port))
    }

    fn tcp(&self, server: IpAddr, query: &Message) -> Result<Message, TransportError> {
        let mut s = TcpStream::connect_timeout(&self.endpoint(server), self.timeout)?;
        s.set_read_timeout(Some(self.timeout))?;
        s.set_write_timeout(Some(self.timeout))?;
        let bytes = query.to_bytes()?;
        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&bytes);
        s.write_all(&framed)?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len)?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut buf)?;
        let m = Message::parse(&buf)?;
        if !matches(query, &m) {
            return Err(TransportError::Mismatch);
        }
        Ok(m)
    }
}
