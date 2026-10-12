//! A minimal authoritative server. It exists so the resolver can be tested
//! against a realistic delegation tree (and misbehaving servers) without
//! touching the real internet.

use crate::wire::{Message, Name, RClass, RData, RType, Record, Soa, opcode, rcode};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Zone {
    pub origin: Name,
    pub records: Vec<Record>,
}

fn abs_name(tok: &str, origin: &Name) -> Result<Name, String> {
    if tok == "@" {
        return Ok(origin.clone());
    }
    let s = if tok.ends_with('.') {
        tok.to_string()
    } else if origin.is_root() {
        format!("{tok}.")
    } else {
        format!("{tok}.{origin}")
    };
    s.parse().map_err(|e| format!("{tok}: {e}"))
}

impl Zone {
    /// Parse a tiny zone-file dialect: `name ttl [IN] TYPE rdata...` per line,
    /// `;` comments, `@` for the origin, relative names completed with the origin.
    pub fn parse(origin: &str, text: &str) -> Result<Zone, String> {
        let origin: Name = origin.parse().map_err(|e| format!("origin: {e}"))?;
        let mut records = Vec::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.split(';').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let err = |m: String| format!("line {}: {m}", lineno + 1);
            let mut toks: Vec<&str> = line.split_whitespace().collect();
            if toks.len() > 2 && toks[2].eq_ignore_ascii_case("IN") {
                toks.remove(2);
            }
            if toks.len() < 4 {
                return Err(err("expected: name ttl type rdata".into()));
            }
            let name = abs_name(toks[0], &origin).map_err(err)?;
            let ttl: u32 = toks[1].parse().map_err(|_| err("bad ttl".into()))?;
            let rtype: RType = toks[2].parse().map_err(err)?;
            let rd = &toks[3..];
            let nm = |i: usize| -> Result<Name, String> {
                abs_name(rd.get(i).ok_or("missing field")?, &origin)
            };
            let num = |i: usize| -> Result<u32, String> {
                rd.get(i)
                    .ok_or("missing field")?
                    .parse()
                    .map_err(|_| "bad number".to_string())
            };
            let data = match rtype {
                RType::A => RData::A(rd[0].parse().map_err(|_| err("bad IPv4".into()))?),
                RType::AAAA => RData::Aaaa(rd[0].parse().map_err(|_| err("bad IPv6".into()))?),
                RType::NS => RData::Ns(nm(0).map_err(err)?),
                RType::CNAME => RData::Cname(nm(0).map_err(err)?),
                RType::PTR => RData::Ptr(nm(0).map_err(err)?),
                RType::MX => RData::Mx {
                    preference: num(0).map_err(err)? as u16,
                    exchange: nm(1).map_err(err)?,
                },
                RType::SOA => RData::Soa(Soa {
                    mname: nm(0).map_err(err)?,
                    rname: nm(1).map_err(err)?,
                    serial: num(2).map_err(err)?,
                    refresh: num(3).map_err(err)?,
                    retry: num(4).map_err(err)?,
                    expire: num(5).map_err(err)?,
                    minimum: num(6).map_err(err)?,
                }),
                RType::TXT => {
                    let rest = rd.join(" ");
                    RData::Txt(vec![rest.trim_matches('"').as_bytes().to_vec()])
                }
                other => return Err(err(format!("type {other} not supported in zone files"))),
            };
            records.push(Record {
                name,
                rtype,
                class: RClass::IN,
                ttl,
                data,
            });
        }
        Ok(Zone { origin, records })
    }

    fn at(&self, name: &Name, rtype: RType) -> Vec<Record> {
        self.records
            .iter()
            .filter(|r| r.name == *name && r.rtype == rtype)
            .cloned()
            .collect()
    }

    fn soa(&self) -> Vec<Record> {
        self.at(&self.origin, RType::SOA)
    }

    /// Fill in an authoritative response for (qname, qtype).
    fn answer(&self, qname: &Name, qtype: RType, resp: &mut Message) {
        // Delegation: the topmost NS set below the apex that covers qname
        // (data below a zone cut isn't ours to answer for).
        let cut = qname
            .self_and_ancestors()
            .into_iter()
            .take_while(|n| *n != self.origin)
            .filter(|n| !self.at(n, RType::NS).is_empty())
            .last();
        if let Some(cut) = cut {
            let ns = self.at(&cut, RType::NS);
            for r in &ns {
                if let Some(t) = r.target() {
                    resp.additional.extend(self.at(t, RType::A));
                    resp.additional.extend(self.at(t, RType::AAAA));
                }
            }
            resp.authority = ns;
            return;
        }
        resp.header.aa = true;
        let mut cur = qname.clone();
        for _ in 0..8 {
            let direct = self.at(&cur, qtype);
            if !direct.is_empty() {
                resp.answers.extend(direct);
                return;
            }
            let cname = if qtype == RType::CNAME {
                vec![]
            } else {
                self.at(&cur, RType::CNAME)
            };
            match cname.first().and_then(|c| c.target().cloned()) {
                Some(target) => {
                    resp.answers.extend(cname);
                    if !target.is_subdomain_of(&self.origin) {
                        return;
                    }
                    cur = target;
                }
                None => break,
            }
        }
        if !resp.answers.is_empty() {
            return;
        }
        // Name exists (possibly as an empty non-terminal) → NODATA, else NXDOMAIN.
        let exists = self.records.iter().any(|r| r.name.is_subdomain_of(qname));
        if !exists {
            resp.header.rcode = rcode::NXDOMAIN;
        }
        resp.authority = self.soa();
    }
}

/// Knobs for simulating broken or hostile servers.
#[derive(Clone, Debug, Default)]
pub struct Behavior {
    /// Never respond (lame / unreachable server).
    pub drop: bool,
    /// Always set TC over UDP, forcing TCP.
    pub truncate_udp: bool,
    /// Override the response code (e.g. SERVFAIL, REFUSED).
    pub rcode: Option<u8>,
    /// Extra records stuffed into every response's additional section.
    pub poison_additional: Vec<Record>,
    /// Extra records stuffed into every response's authority section.
    pub poison_authority: Vec<Record>,
    pub delay: Duration,
}

pub struct AuthServer {
    zones: Vec<Zone>,
    behavior: Mutex<Behavior>,
    pub queries: AtomicUsize,
}

impl AuthServer {
    pub fn new(zones: Vec<Zone>) -> Arc<AuthServer> {
        Arc::new(AuthServer {
            zones,
            behavior: Mutex::new(Behavior::default()),
            queries: AtomicUsize::new(0),
        })
    }

    pub fn set_behavior(&self, b: Behavior) {
        *self.behavior.lock().unwrap() = b;
    }

    pub fn query_count(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }

    pub fn handle(&self, query: &Message, udp: bool) -> Option<Message> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        let b = self.behavior.lock().unwrap().clone();
        if b.drop {
            return None;
        }
        if !b.delay.is_zero() {
            thread::sleep(b.delay);
        }
        let mut resp = Message {
            header: crate::wire::Header {
                id: query.header.id,
                qr: true,
                opcode: query.header.opcode,
                rd: query.header.rd,
                ..Default::default()
            },
            questions: query.questions.clone(),
            edns: query.edns.as_ref().map(|_| crate::wire::Edns::new(1232)),
            ..Default::default()
        };
        let Some(q) = query
            .question()
            .filter(|_| query.header.opcode == opcode::QUERY && query.questions.len() == 1)
        else {
            resp.header.rcode = rcode::FORMERR;
            return Some(resp);
        };
        match self
            .zones
            .iter()
            .filter(|z| q.name.is_subdomain_of(&z.origin))
            .max_by_key(|z| z.origin.label_count())
        {
            Some(zone) => zone.answer(&q.name, q.qtype, &mut resp),
            None => resp.header.rcode = rcode::REFUSED,
        }
        if let Some(rc) = b.rcode {
            resp.header.rcode = rc;
            resp.header.aa = false;
            resp.answers.clear();
            resp.authority.clear();
            resp.additional.clear();
        }
        resp.additional.extend(b.poison_additional);
        resp.authority.extend(b.poison_authority);
        if udp && b.truncate_udp {
            resp.header.tc = true;
            resp.answers.clear();
            resp.authority.clear();
            resp.additional.clear();
        }
        Some(resp)
    }

    /// Serve UDP and TCP on `addr` from background threads.
    pub fn spawn(self: &Arc<Self>, addr: SocketAddr) -> io::Result<()> {
        self.spawn_bound(addr).map(|_| ())
    }

    /// Bind both transports to one port, including an OS-assigned port.
    pub fn spawn_bound(self: &Arc<Self>, addr: SocketAddr) -> io::Result<SocketAddr> {
        let udp = UdpSocket::bind(addr)?;
        let addr = udp.local_addr()?;
        let tcp = TcpListener::bind(addr)?;
        let me = Arc::clone(self);
        thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, peer)) = udp.recv_from(&mut buf) else {
                    continue;
                };
                let Ok(q) = Message::parse(&buf[..n]) else {
                    continue;
                };
                if let Some(resp) = me.handle(&q, true) {
                    let limit = q
                        .edns
                        .as_ref()
                        .map(|e| e.udp_size.max(512) as usize)
                        .unwrap_or(512);
                    if let Ok(bytes) = resp.to_bytes_limited(limit) {
                        let _ = udp.send_to(&bytes, peer);
                    }
                }
            }
        });
        let me = Arc::clone(self);
        thread::spawn(move || {
            for stream in tcp.incoming().flatten() {
                let me = Arc::clone(&me);
                thread::spawn(move || {
                    let mut s = stream;
                    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut len = [0u8; 2];
                    while s.read_exact(&mut len).is_ok() {
                        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
                        if s.read_exact(&mut buf).is_err() {
                            return;
                        }
                        let Ok(q) = Message::parse(&buf) else { return };
                        let Some(resp) = me.handle(&q, false) else {
                            return;
                        };
                        let Ok(bytes) = resp.to_bytes() else { return };
                        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
                        framed.extend_from_slice(&bytes);
                        if s.write_all(&framed).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Ok(addr)
    }
}
