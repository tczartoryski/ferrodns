use super::{Name, WireError, read_bytes, read_u8, read_u16, read_u32};
use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RType(pub u16);

impl RType {
    pub const A: RType = RType(1);
    pub const NS: RType = RType(2);
    pub const CNAME: RType = RType(5);
    pub const SOA: RType = RType(6);
    pub const PTR: RType = RType(12);
    pub const MX: RType = RType(15);
    pub const TXT: RType = RType(16);
    pub const AAAA: RType = RType(28);
    pub const OPT: RType = RType(41);
    pub const DS: RType = RType(43);
    pub const RRSIG: RType = RType(46);
    pub const DNSKEY: RType = RType(48);
    pub const ANY: RType = RType(255);

    const NAMES: &'static [(RType, &'static str)] = &[
        (RType::A, "A"),
        (RType::NS, "NS"),
        (RType::CNAME, "CNAME"),
        (RType::SOA, "SOA"),
        (RType::PTR, "PTR"),
        (RType::MX, "MX"),
        (RType::TXT, "TXT"),
        (RType::AAAA, "AAAA"),
        (RType::OPT, "OPT"),
        (RType::DS, "DS"),
        (RType::RRSIG, "RRSIG"),
        (RType::DNSKEY, "DNSKEY"),
        (RType::ANY, "ANY"),
    ];
}

impl fmt::Display for RType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match RType::NAMES.iter().find(|(t, _)| t == self) {
            Some((_, n)) => write!(f, "{n}"),
            None => write!(f, "TYPE{}", self.0),
        }
    }
}

impl fmt::Debug for RType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl FromStr for RType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let up = s.to_ascii_uppercase();
        if let Some((t, _)) = RType::NAMES.iter().find(|(_, n)| *n == up) {
            return Ok(*t);
        }
        up.strip_prefix("TYPE")
            .and_then(|n| n.parse().ok())
            .map(RType)
            .ok_or_else(|| format!("unknown record type: {s}"))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct RClass(pub u16);

impl RClass {
    pub const IN: RClass = RClass(1);
    pub const CH: RClass = RClass(3);
}

impl fmt::Display for RClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "IN"),
            3 => write!(f, "CH"),
            n => write!(f, "CLASS{n}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Soa {
    pub mname: Name,
    pub rname: Name,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(Name),
    Cname(Name),
    Ptr(Name),
    Mx {
        preference: u16,
        exchange: Name,
    },
    Soa(Soa),
    Txt(Vec<Vec<u8>>),
    /// Any type we don't interpret, kept opaque per RFC 3597.
    Unknown(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub rtype: RType,
    pub class: RClass,
    pub ttl: u32,
    pub data: RData,
}

impl Record {
    pub fn new(name: Name, ttl: u32, data: RData) -> Record {
        let rtype = match &data {
            RData::A(_) => RType::A,
            RData::Aaaa(_) => RType::AAAA,
            RData::Ns(_) => RType::NS,
            RData::Cname(_) => RType::CNAME,
            RData::Ptr(_) => RType::PTR,
            RData::Mx { .. } => RType::MX,
            RData::Soa(_) => RType::SOA,
            RData::Txt(_) => RType::TXT,
            RData::Unknown(_) => panic!("use Record {{ .. }} directly for unknown types"),
        };
        Record {
            name,
            rtype,
            class: RClass::IN,
            ttl,
            data,
        }
    }

    /// The name this record points at, for NS/CNAME/PTR/MX records.
    pub fn target(&self) -> Option<&Name> {
        match &self.data {
            RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => Some(n),
            RData::Mx { exchange, .. } => Some(exchange),
            _ => None,
        }
    }

    pub fn soa(&self) -> Option<&Soa> {
        match &self.data {
            RData::Soa(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn parse(msg: &[u8], pos: &mut usize) -> Result<Record, WireError> {
        let name = Name::parse(msg, pos)?;
        let rtype = RType(read_u16(msg, pos)?);
        let class = RClass(read_u16(msg, pos)?);
        let ttl = read_u32(msg, pos)?;
        let rdlen = read_u16(msg, pos)? as usize;
        let start = *pos;
        let end = start + rdlen;
        if end > msg.len() {
            return Err(WireError::Truncated);
        }
        // Parse inside a bounded view so compressed names inside rdata may still
        // point back into the full message, but fixed fields can't run past rdlen.
        let mut p = start;
        let data = match rtype {
            RType::A => {
                if rdlen != 4 {
                    return Err(WireError::BadRdata("A must be 4 bytes"));
                }
                let b = read_bytes(msg, &mut p, 4)?;
                RData::A(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            RType::AAAA => {
                if rdlen != 16 {
                    return Err(WireError::BadRdata("AAAA must be 16 bytes"));
                }
                let b: [u8; 16] = read_bytes(msg, &mut p, 16)?.try_into().unwrap();
                RData::Aaaa(Ipv6Addr::from(b))
            }
            RType::NS => RData::Ns(Name::parse(msg, &mut p)?),
            RType::CNAME => RData::Cname(Name::parse(msg, &mut p)?),
            RType::PTR => RData::Ptr(Name::parse(msg, &mut p)?),
            RType::MX => {
                let preference = read_u16(msg, &mut p)?;
                RData::Mx {
                    preference,
                    exchange: Name::parse(msg, &mut p)?,
                }
            }
            RType::SOA => {
                let mname = Name::parse(msg, &mut p)?;
                let rname = Name::parse(msg, &mut p)?;
                let mut f = [0u32; 5];
                for v in f.iter_mut() {
                    if p + 4 > end {
                        return Err(WireError::BadRdata("SOA too short"));
                    }
                    *v = read_u32(msg, &mut p)?;
                }
                RData::Soa(Soa {
                    mname,
                    rname,
                    serial: f[0],
                    refresh: f[1],
                    retry: f[2],
                    expire: f[3],
                    minimum: f[4],
                })
            }
            RType::TXT => {
                let mut strings = Vec::new();
                while p < end {
                    let len = read_u8(msg, &mut p)? as usize;
                    if p + len > end {
                        return Err(WireError::BadRdata("TXT string overruns rdata"));
                    }
                    strings.push(read_bytes(msg, &mut p, len)?.to_vec());
                }
                RData::Txt(strings)
            }
            _ => RData::Unknown(read_bytes(msg, &mut p, rdlen)?.to_vec()),
        };
        if p != end {
            return Err(WireError::BadRdata("rdata length mismatch"));
        }
        *pos = end;
        Ok(Record {
            name,
            rtype,
            class,
            ttl,
            data,
        })
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>, comp: &mut HashMap<Name, u16>) {
        self.name.encode(out, Some(comp));
        out.extend_from_slice(&self.rtype.0.to_be_bytes());
        out.extend_from_slice(&self.class.0.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        let len_at = out.len();
        out.extend_from_slice(&[0, 0]);
        match &self.data {
            RData::A(ip) => out.extend_from_slice(&ip.octets()),
            RData::Aaaa(ip) => out.extend_from_slice(&ip.octets()),
            // RFC 3597 §4: compression in rdata only for the RFC 1035 well-known types.
            RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => n.encode(out, Some(comp)),
            RData::Mx {
                preference,
                exchange,
            } => {
                out.extend_from_slice(&preference.to_be_bytes());
                exchange.encode(out, Some(comp));
            }
            RData::Soa(s) => {
                s.mname.encode(out, Some(comp));
                s.rname.encode(out, Some(comp));
                for v in [s.serial, s.refresh, s.retry, s.expire, s.minimum] {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            RData::Txt(strings) => {
                for s in strings {
                    out.push(s.len() as u8);
                    out.extend_from_slice(s);
                }
            }
            RData::Unknown(b) => out.extend_from_slice(b),
        }
        let rdlen = (out.len() - len_at - 2) as u16;
        out[len_at..len_at + 2].copy_from_slice(&rdlen.to_be_bytes());
    }
}

impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RData::A(ip) => write!(f, "{ip}"),
            RData::Aaaa(ip) => write!(f, "{ip}"),
            RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => write!(f, "{n}"),
            RData::Mx {
                preference,
                exchange,
            } => write!(f, "{preference} {exchange}"),
            RData::Soa(s) => write!(
                f,
                "{} {} {} {} {} {} {}",
                s.mname, s.rname, s.serial, s.refresh, s.retry, s.expire, s.minimum
            ),
            RData::Txt(strings) => {
                let parts: Vec<String> = strings
                    .iter()
                    .map(|s| format!("\"{}\"", String::from_utf8_lossy(s)))
                    .collect();
                write!(f, "{}", parts.join(" "))
            }
            RData::Unknown(b) => {
                write!(f, "\\# {}", b.len())?;
                if !b.is_empty() {
                    write!(f, " ")?;
                    for x in b {
                        write!(f, "{x:02x}")?;
                    }
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {}",
            self.name, self.ttl, self.class, self.rtype, self.data
        )
    }
}
