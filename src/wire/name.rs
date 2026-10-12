use super::WireError;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// Maximum number of compression pointers followed while decoding one name.
const MAX_POINTER_HOPS: usize = 32;

/// A domain name, stored as lowercase labels (DNS names compare case-insensitively).
/// The root name has no labels.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Name {
    labels: Vec<Vec<u8>>,
}

impl Name {
    pub fn root() -> Self {
        Name { labels: Vec::new() }
    }

    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Length of the uncompressed wire encoding, including the root byte.
    pub fn wire_len(&self) -> usize {
        self.labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1
    }

    pub fn parent(&self) -> Option<Name> {
        if self.is_root() {
            None
        } else {
            Some(Name {
                labels: self.labels[1..].to_vec(),
            })
        }
    }

    /// True if `self` equals `zone` or sits below it.
    pub fn is_subdomain_of(&self, zone: &Name) -> bool {
        let n = zone.labels.len();
        self.labels.len() >= n && self.labels[self.labels.len() - n..] == zone.labels[..]
    }

    /// The name itself followed by every ancestor up to and including the root.
    pub fn self_and_ancestors(&self) -> Vec<Name> {
        (0..=self.labels.len())
            .map(|i| Name {
                labels: self.labels[i..].to_vec(),
            })
            .collect()
    }

    /// Prepend a label (used to build names in tests and the simulator).
    pub fn child(&self, label: &str) -> Result<Name, WireError> {
        let mut labels = vec![label.as_bytes().to_ascii_lowercase()];
        labels.extend(self.labels.iter().cloned());
        let n = Name { labels };
        n.validate()?;
        Ok(n)
    }

    fn validate(&self) -> Result<(), WireError> {
        for l in &self.labels {
            if l.is_empty() || l.len() > 63 {
                return Err(WireError::BadLabel);
            }
        }
        if self.wire_len() > 255 {
            return Err(WireError::NameTooLong);
        }
        Ok(())
    }

    /// Decode a possibly-compressed name starting at `*pos` in `msg`.
    /// On return `*pos` points just past the name's bytes at its original location.
    pub fn parse(msg: &[u8], pos: &mut usize) -> Result<Name, WireError> {
        let mut labels = Vec::new();
        let mut p = *pos;
        let mut jumped = false;
        let mut hops = 0;
        let mut wire_len = 1usize;
        loop {
            let len = *msg.get(p).ok_or(WireError::Truncated)? as usize;
            match len & 0xC0 {
                0xC0 => {
                    let lo = *msg.get(p + 1).ok_or(WireError::Truncated)? as usize;
                    let target = ((len & 0x3F) << 8) | lo;
                    // Pointers must point strictly backwards; this, plus the hop limit,
                    // makes pointer loops impossible.
                    if target >= p {
                        return Err(WireError::BadPointer);
                    }
                    hops += 1;
                    if hops > MAX_POINTER_HOPS {
                        return Err(WireError::BadPointer);
                    }
                    if !jumped {
                        *pos = p + 2;
                        jumped = true;
                    }
                    p = target;
                }
                0x00 => {
                    if len == 0 {
                        if !jumped {
                            *pos = p + 1;
                        }
                        return Ok(Name { labels });
                    }
                    let label = msg.get(p + 1..p + 1 + len).ok_or(WireError::Truncated)?;
                    wire_len += len + 1;
                    if wire_len > 255 {
                        return Err(WireError::NameTooLong);
                    }
                    labels.push(label.to_ascii_lowercase());
                    p += 1 + len;
                }
                // 0x40 and 0x80 are extended / reserved label types (RFC 6891 §5).
                _ => return Err(WireError::BadLabel),
            }
        }
    }

    /// Encode the name, using and updating the compression table when given.
    /// Offsets in the table are relative to the start of `out`, which must be the
    /// start of the DNS message.
    pub fn encode(&self, out: &mut Vec<u8>, comp: Option<&mut HashMap<Name, u16>>) {
        match comp {
            None => {
                for l in &self.labels {
                    out.push(l.len() as u8);
                    out.extend_from_slice(l);
                }
                out.push(0);
            }
            Some(table) => {
                for i in 0..self.labels.len() {
                    let suffix = Name {
                        labels: self.labels[i..].to_vec(),
                    };
                    if let Some(&off) = table.get(&suffix) {
                        out.extend_from_slice(&(0xC000 | off).to_be_bytes());
                        return;
                    }
                    if out.len() < 0x3FFF {
                        table.insert(suffix, out.len() as u16);
                    }
                    let l = &self.labels[i];
                    out.push(l.len() as u8);
                    out.extend_from_slice(l);
                }
                out.push(0);
            }
        }
    }
}

impl FromStr for Name {
    type Err = WireError;

    /// Parse presentation format ("www.example.com" or "www.example.com.").
    /// Supports `\.` and `\DDD` escapes.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "." || s.is_empty() {
            return Ok(Name::root());
        }
        let bytes = s.as_bytes();
        let mut labels = Vec::new();
        let mut cur = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            match c {
                b'\\' => {
                    let next = *bytes
                        .get(i + 1)
                        .ok_or_else(|| WireError::BadName(s.into()))?;
                    if next.is_ascii_digit() {
                        let digits = bytes
                            .get(i + 1..i + 4)
                            .ok_or_else(|| WireError::BadName(s.into()))?;
                        let v: u16 = std::str::from_utf8(digits)
                            .ok()
                            .and_then(|d| d.parse().ok())
                            .filter(|v| *v <= 255)
                            .ok_or_else(|| WireError::BadName(s.into()))?;
                        cur.push(v as u8);
                        i += 4;
                    } else {
                        cur.push(next);
                        i += 2;
                    }
                }
                b'.' => {
                    if cur.is_empty() {
                        return Err(WireError::BadName(s.into()));
                    }
                    labels.push(std::mem::take(&mut cur).to_ascii_lowercase());
                    i += 1;
                }
                _ => {
                    cur.push(c);
                    i += 1;
                }
            }
        }
        if !cur.is_empty() {
            labels.push(cur.to_ascii_lowercase());
        }
        let n = Name { labels };
        n.validate()?;
        Ok(n)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return write!(f, ".");
        }
        for l in &self.labels {
            for &b in l {
                match b {
                    b'.' | b'\\' => write!(f, "\\{}", b as char)?,
                    0x21..=0x7E => write!(f, "{}", b as char)?,
                    _ => write!(f, "\\{b:03}")?,
                }
            }
            write!(f, ".")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn parse_and_display() {
        assert_eq!(n("WWW.Example.COM").to_string(), "www.example.com.");
        assert_eq!(n("www.example.com.").to_string(), "www.example.com.");
        assert!(n(".").is_root());
        assert_eq!(n("a\\.b.example").label_count(), 2);
        assert_eq!(n("a\\032b.example").labels()[0], b"a b");
        assert!("a..b".parse::<Name>().is_err());
        assert!(format!("{}.com", "x".repeat(64)).parse::<Name>().is_err());
    }

    #[test]
    fn subdomain_relationships() {
        assert!(n("www.example.com").is_subdomain_of(&n("example.com")));
        assert!(n("example.com").is_subdomain_of(&n("example.com")));
        assert!(n("example.com").is_subdomain_of(&Name::root()));
        assert!(!n("badexample.com").is_subdomain_of(&n("example.com")));
        assert!(!n("com").is_subdomain_of(&n("example.com")));
        assert_eq!(n("a.b.c").self_and_ancestors().len(), 4);
    }

    #[test]
    fn compression_roundtrip() {
        let mut out = vec![0u8; 12];
        let mut table = HashMap::new();
        n("www.example.com").encode(&mut out, Some(&mut table));
        let second = out.len();
        n("mail.example.com").encode(&mut out, Some(&mut table));
        // "mail" + pointer to "example.com" = 1 + 4 + 2 bytes
        assert_eq!(out.len() - second, 7);
        let mut p = 12;
        assert_eq!(Name::parse(&out, &mut p).unwrap(), n("www.example.com"));
        assert_eq!(p, second);
        assert_eq!(Name::parse(&out, &mut p).unwrap(), n("mail.example.com"));
        assert_eq!(p, out.len());
    }

    #[test]
    fn rejects_pointer_loops_and_forward_pointers() {
        // Pointer to itself.
        let buf = [0xC0, 0x00];
        assert_eq!(Name::parse(&buf, &mut 0), Err(WireError::BadPointer));
        // Forward pointer.
        let buf = [0xC0, 0x02, 0x00];
        assert_eq!(Name::parse(&buf, &mut 0), Err(WireError::BadPointer));
        // Truncated label.
        let buf = [0x05, b'a', b'b'];
        assert_eq!(Name::parse(&buf, &mut 0), Err(WireError::Truncated));
        // Reserved label type.
        let buf = [0x40, 0x00];
        assert_eq!(Name::parse(&buf, &mut 0), Err(WireError::BadLabel));
    }
}
