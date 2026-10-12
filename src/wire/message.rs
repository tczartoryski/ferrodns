use super::{Name, RClass, RType, Record, WireError, read_bytes, read_u16, read_u32};
use std::collections::HashMap;

pub mod rcode {
    pub const NOERROR: u8 = 0;
    pub const FORMERR: u8 = 1;
    pub const SERVFAIL: u8 = 2;
    pub const NXDOMAIN: u8 = 3;
    pub const NOTIMP: u8 = 4;
    pub const REFUSED: u8 = 5;

    pub fn name(rc: u8) -> &'static str {
        match rc {
            NOERROR => "NOERROR",
            FORMERR => "FORMERR",
            SERVFAIL => "SERVFAIL",
            NXDOMAIN => "NXDOMAIN",
            NOTIMP => "NOTIMP",
            REFUSED => "REFUSED",
            _ => "RCODE?",
        }
    }
}

pub mod opcode {
    pub const QUERY: u8 = 0;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
    pub rcode: u8,
}

impl Header {
    fn flags(&self) -> u16 {
        (self.qr as u16) << 15
            | ((self.opcode as u16) & 0xF) << 11
            | (self.aa as u16) << 10
            | (self.tc as u16) << 9
            | (self.rd as u16) << 8
            | (self.ra as u16) << 7
            | (self.ad as u16) << 5
            | (self.cd as u16) << 4
            | (self.rcode as u16 & 0xF)
    }

    fn from_flags(id: u16, f: u16) -> Header {
        Header {
            id,
            qr: f & 0x8000 != 0,
            opcode: ((f >> 11) & 0xF) as u8,
            aa: f & 0x0400 != 0,
            tc: f & 0x0200 != 0,
            rd: f & 0x0100 != 0,
            ra: f & 0x0080 != 0,
            ad: f & 0x0020 != 0,
            cd: f & 0x0010 != 0,
            rcode: (f & 0xF) as u8,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: RType,
    pub qclass: RClass,
}

/// EDNS(0) pseudo-record (RFC 6891). Options are kept raw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edns {
    pub udp_size: u16,
    pub ext_rcode: u8,
    pub version: u8,
    pub dnssec_ok: bool,
    pub options: Vec<u8>,
}

impl Edns {
    pub fn new(udp_size: u16) -> Edns {
        Edns {
            udp_size,
            ext_rcode: 0,
            version: 0,
            dnssec_ok: false,
            options: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    /// Additional section, excluding the OPT pseudo-record (see `edns`).
    pub additional: Vec<Record>,
    pub edns: Option<Edns>,
}

impl Message {
    /// Build a query with a single question.
    pub fn query(id: u16, name: Name, qtype: RType, rd: bool, edns: Option<Edns>) -> Message {
        Message {
            header: Header {
                id,
                rd,
                opcode: opcode::QUERY,
                ..Default::default()
            },
            questions: vec![Question {
                name,
                qtype,
                qclass: RClass::IN,
            }],
            edns,
            ..Default::default()
        }
    }

    pub fn question(&self) -> Option<&Question> {
        self.questions.first()
    }

    pub fn parse(buf: &[u8]) -> Result<Message, WireError> {
        let mut pos = 0;
        let id = read_u16(buf, &mut pos)?;
        let flags = read_u16(buf, &mut pos)?;
        let qd = read_u16(buf, &mut pos)?;
        let an = read_u16(buf, &mut pos)?;
        let ns = read_u16(buf, &mut pos)?;
        let ar = read_u16(buf, &mut pos)?;
        let mut m = Message {
            header: Header::from_flags(id, flags),
            ..Default::default()
        };
        for _ in 0..qd {
            let name = Name::parse(buf, &mut pos)?;
            let qtype = RType(read_u16(buf, &mut pos)?);
            let qclass = RClass(read_u16(buf, &mut pos)?);
            m.questions.push(Question {
                name,
                qtype,
                qclass,
            });
        }
        for _ in 0..an {
            m.answers.push(Record::parse(buf, &mut pos)?);
        }
        for _ in 0..ns {
            m.authority.push(Record::parse(buf, &mut pos)?);
        }
        for _ in 0..ar {
            let rec_start = pos;
            let rec = Record::parse(buf, &mut pos)?;
            if rec.rtype == RType::OPT {
                if m.edns.is_some() || !rec.name.is_root() {
                    return Err(WireError::BadRdata("duplicate or misplaced OPT"));
                }
                // Re-read the fixed fields: CLASS = UDP size, TTL = ext-rcode/version/flags.
                let mut p = rec_start + 1;
                let _type = read_u16(buf, &mut p)?;
                let udp_size = read_u16(buf, &mut p)?;
                let ttl = read_u32(buf, &mut p)?;
                let rdlen = read_u16(buf, &mut p)? as usize;
                let options = read_bytes(buf, &mut p, rdlen)?.to_vec();
                m.edns = Some(Edns {
                    udp_size,
                    ext_rcode: (ttl >> 24) as u8,
                    version: (ttl >> 16) as u8,
                    dnssec_ok: ttl & 0x8000 != 0,
                    options,
                });
            } else {
                m.additional.push(rec);
            }
        }
        if pos != buf.len() {
            return Err(WireError::TrailingData);
        }
        Ok(m)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::with_capacity(512);
        let mut comp: HashMap<Name, u16> = HashMap::new();
        let ar = self.additional.len() + self.edns.is_some() as usize;
        for v in [
            self.header.id,
            self.header.flags(),
            self.questions.len() as u16,
            self.answers.len() as u16,
            self.authority.len() as u16,
            ar as u16,
        ] {
            out.extend_from_slice(&v.to_be_bytes());
        }
        for q in &self.questions {
            q.name.encode(&mut out, Some(&mut comp));
            out.extend_from_slice(&q.qtype.0.to_be_bytes());
            out.extend_from_slice(&q.qclass.0.to_be_bytes());
        }
        for r in self
            .answers
            .iter()
            .chain(&self.authority)
            .chain(&self.additional)
        {
            r.encode(&mut out, &mut comp);
        }
        if let Some(e) = &self.edns {
            out.push(0); // root name
            out.extend_from_slice(&RType::OPT.0.to_be_bytes());
            out.extend_from_slice(&e.udp_size.to_be_bytes());
            let ttl =
                (e.ext_rcode as u32) << 24 | (e.version as u32) << 16 | (e.dnssec_ok as u32) << 15;
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&(e.options.len() as u16).to_be_bytes());
            out.extend_from_slice(&e.options);
        }
        if out.len() > 65535 {
            return Err(WireError::TooLarge);
        }
        Ok(out)
    }

    /// Encode for a transport with a size limit. If the full message doesn't fit,
    /// send header + question (+ OPT) with TC set so the client retries over TCP.
    pub fn to_bytes_limited(&self, max: usize) -> Result<Vec<u8>, WireError> {
        let full = self.to_bytes()?;
        if full.len() <= max {
            return Ok(full);
        }
        let mut short = Message {
            header: self.header.clone(),
            questions: self.questions.clone(),
            edns: self.edns.clone(),
            ..Default::default()
        };
        short.header.tc = true;
        short.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{RData, Soa};
    use std::net::Ipv4Addr;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn sample() -> Message {
        let mut m = Message::query(
            0xBEEF,
            n("www.example.com"),
            RType::A,
            true,
            Some(Edns::new(1232)),
        );
        m.header.qr = true;
        m.header.ra = true;
        m.answers.push(Record::new(
            n("www.example.com"),
            300,
            RData::Cname(n("web.example.com")),
        ));
        m.answers.push(Record::new(
            n("web.example.com"),
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ));
        m.authority.push(Record::new(
            n("example.com"),
            3600,
            RData::Soa(Soa {
                mname: n("ns1.example.com"),
                rname: n("hostmaster.example.com"),
                serial: 2026101001,
                refresh: 7200,
                retry: 900,
                expire: 1209600,
                minimum: 300,
            }),
        ));
        m.additional.push(Record::new(
            n("example.com"),
            60,
            RData::Txt(vec![b"hello".to_vec(), b"".to_vec()]),
        ));
        m.additional.push(Record {
            name: n("example.com"),
            rtype: RType(65280),
            class: RClass::IN,
            ttl: 60,
            data: RData::Unknown(vec![1, 2, 3]),
        });
        m
    }

    #[test]
    fn roundtrip_full_message() {
        let m = sample();
        let bytes = m.to_bytes().unwrap();
        let back = Message::parse(&bytes).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn compression_shrinks_message() {
        let m = sample();
        let bytes = m.to_bytes().unwrap();
        // Uncompressed it would carry "example.com" ~8 times; compressed it's far smaller.
        assert!(bytes.len() < 230, "len = {}", bytes.len());
    }

    #[test]
    fn truncation_sets_tc() {
        let m = sample();
        let short = m.to_bytes_limited(40).unwrap();
        let back = Message::parse(&short).unwrap();
        assert!(back.header.tc);
        assert!(back.answers.is_empty());
        assert_eq!(back.questions, m.questions);
    }

    #[test]
    fn rejects_garbage_and_trailing_data() {
        assert!(Message::parse(&[0u8; 5]).is_err());
        let mut bytes = sample().to_bytes().unwrap();
        bytes.push(0);
        assert_eq!(Message::parse(&bytes), Err(WireError::TrailingData));
        // Every prefix of a valid message must fail cleanly, never panic.
        let bytes = sample().to_bytes().unwrap();
        for i in 0..bytes.len() {
            assert!(Message::parse(&bytes[..i]).is_err());
        }
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut x: u64 = 0x9E3779B97F4A7C15;
        for _ in 0..20000 {
            let len = (x % 300) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                buf.push(x as u8);
            }
            let _ = Message::parse(&buf);
        }
    }

    #[test]
    fn mutated_messages_never_panic() {
        let base = sample().to_bytes().unwrap();
        let mut x: u64 = 42;
        for _ in 0..20000 {
            let mut buf = base.clone();
            for _ in 0..3 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let i = (x as usize) % buf.len();
                buf[i] = (x >> 32) as u8;
            }
            let _ = Message::parse(&buf);
        }
    }
}
