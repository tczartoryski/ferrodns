//! Sending one query to one server: UDP first, TCP on truncation (RFC 7766).

use crate::live_policy::{Control, public_ip};
use crate::wire::{Message, WireError};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum TransportError {
    Timeout,
    Budget,
    Policy,
    Cancelled,
    Io(io::Error),
    Wire(WireError),
    /// A TCP response didn't match the query.
    Mismatch,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Budget => write!(f, "upstream query budget exhausted"),
            TransportError::Policy => write!(f, "public endpoint policy rejected upstream"),
            TransportError::Cancelled => write!(f, "cancelled"),
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
        self.exchange_control(server, query, None)
    }

    pub fn exchange_control(
        &self,
        server: IpAddr,
        query: &Message,
        control: Option<&Control>,
    ) -> Result<Exchange, TransportError> {
        self.exchange_budget(server, query, control, None)
    }

    pub(crate) fn exchange_budget(
        &self,
        server: IpAddr,
        query: &Message,
        control: Option<&Control>,
        remaining: Option<&mut usize>,
    ) -> Result<Exchange, TransportError> {
        self.gate(server, control)?;
        let start = Instant::now();
        let response = self.udp(server, query, control)?;
        if response.header.tc {
            if let Some(remaining) = remaining {
                if *remaining == 0 {
                    return Err(TransportError::Budget);
                }
                *remaining -= 1;
            }
            let response = self.tcp(server, query, control)?;
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

    fn udp(
        &self,
        server: IpAddr,
        query: &Message,
        control: Option<&Control>,
    ) -> Result<Message, TransportError> {
        let bind: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .unwrap();
        // A fresh socket per query gives each query its own OS-chosen ephemeral
        // port, which (together with the random ID) is the RFC 5452 defence.
        self.gate(server, control)?;
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
            let wait = wait(control, deadline, left)?;
            sock.set_read_timeout(Some(wait))?;
            let n = match sock.recv(&mut buf) {
                Err(e)
                    if control.is_some()
                        && matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                {
                    continue;
                }
                result => result?,
            };
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

    fn gate(&self, server: IpAddr, control: Option<&Control>) -> Result<(), TransportError> {
        if let Some(c) = control {
            check(c)?;
            if c.public_only
                && (self.port != 53 || !self.endpoints.is_empty() || !public_ip(server))
            {
                return Err(TransportError::Policy);
            }
        }
        Ok(())
    }

    // Preserve the ordinary CLI/simulator timeout semantics; absolute request
    // deadlines and cancellation are an opt-in live policy.
    fn tcp_ordinary(&self, server: IpAddr, query: &Message) -> Result<Message, TransportError> {
        let mut s = TcpStream::connect_timeout(&self.endpoint(server), self.timeout)?;
        s.set_read_timeout(Some(self.timeout))?;
        s.set_write_timeout(Some(self.timeout))?;
        let bytes = query.to_bytes()?;
        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&bytes);
        s.write_all(&framed)?;
        let mut len = [0; 2];
        s.read_exact(&mut len)?;
        let mut buf = vec![0; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut buf)?;
        let m = Message::parse(&buf)?;
        if !matches(query, &m) {
            return Err(TransportError::Mismatch);
        }
        Ok(m)
    }

    fn tcp(
        &self,
        server: IpAddr,
        query: &Message,
        control: Option<&Control>,
    ) -> Result<Message, TransportError> {
        self.gate(server, control)?;
        if control.is_none() {
            return self.tcp_ordinary(server, query);
        }
        let deadline = Instant::now() + self.timeout;
        let connect_wait = control.map_or(Ok::<_, TransportError>(self.timeout), |c| {
            check(c)?;
            Ok(self
                .timeout
                .min(c.deadline.saturating_duration_since(Instant::now()))
                .min(Duration::from_millis(100)))
        })?;
        let mut s = TcpStream::connect_timeout(&self.endpoint(server), connect_wait)?;
        let bytes = query.to_bytes()?;
        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&bytes);
        let mut sent = 0;
        while sent < framed.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            s.set_write_timeout(Some(wait(control, deadline, left)?))?;
            match s.write(&framed[sent..]) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(n) => sent += n,
                Err(e)
                    if control.is_some()
                        && matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                {
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
        let mut len = [0u8; 2];
        read_bounded(&mut s, &mut len, deadline, control)?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        read_bounded(&mut s, &mut buf, deadline, control)?;
        let m = Message::parse(&buf)?;
        if !matches(query, &m) {
            return Err(TransportError::Mismatch);
        }
        Ok(m)
    }
}

fn check(c: &Control) -> Result<(), TransportError> {
    c.status().map_err(|e| {
        if e == "cancelled" {
            TransportError::Cancelled
        } else {
            TransportError::Timeout
        }
    })
}
fn wait(
    control: Option<&Control>,
    deadline: Instant,
    left: Duration,
) -> Result<Duration, TransportError> {
    if left.is_zero() {
        return Err(TransportError::Timeout);
    }
    control.map_or(Ok(left), |c| {
        c.wait(deadline).map_err(|e| {
            if e == "cancelled" {
                TransportError::Cancelled
            } else {
                TransportError::Timeout
            }
        })
    })
}
fn read_bounded(
    s: &mut TcpStream,
    mut buf: &mut [u8],
    deadline: Instant,
    control: Option<&Control>,
) -> Result<(), TransportError> {
    while !buf.is_empty() {
        s.set_read_timeout(Some(wait(
            control,
            deadline,
            deadline.saturating_duration_since(Instant::now()),
        )?))?;
        match s.read(buf) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            Ok(n) => buf = &mut buf[n..],
            Err(e)
                if control.is_some()
                    && matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
            {
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod live_tests {
    use super::*;
    #[test]
    fn ultimate_gate_rejects_private_and_overridden_routes_before_socket_creation() {
        let mut t = Transport {
            port: 53,
            timeout: Duration::from_secs(1),
            endpoints: HashMap::new(),
        };
        let c = Control::new(true, Duration::from_secs(1));
        let q = Message::query(
            7,
            "example.com".parse().unwrap(),
            crate::wire::RType::A,
            false,
            None,
        );
        for ip in ["127.0.0.1", "10.0.0.1", "::ffff:8.8.8.8", "2001:db8::1"] {
            assert!(matches!(
                t.exchange_control(ip.parse().unwrap(), &q, Some(&c)),
                Err(TransportError::Policy)
            ));
        }
        t.port = 8053;
        assert!(matches!(
            t.exchange_control("8.8.8.8".parse().unwrap(), &q, Some(&c)),
            Err(TransportError::Policy)
        ));
        t.port = 53;
        t.endpoints
            .insert("8.8.8.8".parse().unwrap(), "127.0.0.1:53".parse().unwrap());
        assert!(matches!(
            t.exchange_control("8.8.8.8".parse().unwrap(), &q, Some(&c)),
            Err(TransportError::Policy)
        ));
        c.cancel();
        assert!(matches!(
            t.exchange_control("8.8.8.8".parse().unwrap(), &q, Some(&c)),
            Err(TransportError::Cancelled)
        ));
        let expired = Control::new(true, Duration::ZERO);
        assert!(matches!(
            t.exchange_control("8.8.8.8".parse().unwrap(), &q, Some(&expired)),
            Err(TransportError::Timeout)
        ));
    }
    #[test]
    fn waits_never_extend_overall_deadline() {
        let c = Control::new(false, Duration::from_millis(30));
        assert!(
            wait(
                Some(&c),
                Instant::now() + Duration::from_secs(3),
                Duration::from_secs(3)
            )
            .unwrap()
                <= Duration::from_millis(30)
        );
        assert!(matches!(
            wait(
                Some(&c),
                Instant::now() - Duration::from_secs(1),
                Duration::ZERO
            ),
            Err(TransportError::Timeout)
        ));
    }
    #[test]
    fn tcp_slow_trickle_has_absolute_deadline() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut size = [0; 2];
            s.read_exact(&mut size).unwrap();
            let mut q = vec![0; u16::from_be_bytes(size) as usize];
            s.read_exact(&mut q).unwrap();
            for b in [0, 20, 0, 0, 0, 0, 0, 0] {
                if s.write_all(&[b]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        let server = "127.0.0.1".parse().unwrap();
        let t = Transport {
            port: 53,
            timeout: Duration::from_secs(3),
            endpoints: HashMap::from([(server, endpoint)]),
        };
        let q = Message::query(
            7,
            "example.com".parse().unwrap(),
            crate::wire::RType::A,
            false,
            None,
        );
        let c = Control::new(false, Duration::from_millis(100));
        let start = Instant::now();
        assert!(matches!(
            t.tcp(server, &q, Some(&c)),
            Err(TransportError::Timeout)
        ));
        assert!(start.elapsed() < Duration::from_secs(1));
        worker.join().unwrap();
    }
}
