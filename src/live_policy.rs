//! Opt-in public recursion policy and per-request cancellation/deadline.
use std::net::IpAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Control {
    pub public_only: bool,
    pub deadline: Instant,
    cancelled: Arc<AtomicBool>,
}
impl Control {
    pub fn new(public_only: bool, timeout: Duration) -> Self {
        Self {
            public_only,
            deadline: Instant::now() + timeout,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    pub fn status(&self) -> Result<(), &'static str> {
        if self.cancelled.load(Ordering::Acquire) {
            Err("cancelled")
        } else if Instant::now() >= self.deadline {
            Err("deadline exceeded")
        } else {
            Ok(())
        }
    }
    pub fn wait(&self, deadline: Instant) -> Result<Duration, &'static str> {
        self.status()?;
        let left = deadline
            .min(self.deadline)
            .saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err("deadline exceeded")
        } else {
            Ok(left.min(Duration::from_millis(50)))
        }
    }
}

pub fn hostname(input: &str) -> bool {
    let name = input.strip_suffix('.').unwrap_or(input);
    if name.len() > 253 || !name.is_ascii() || name.parse::<IpAddr>().is_ok() {
        return false;
    }
    let labels: Vec<_> = name.split('.').collect();
    if labels.len() < 2 || labels.iter().all(|l| l.bytes().all(|b| b.is_ascii_digit())) {
        return false;
    }
    if labels.iter().any(|l| {
        l.is_empty()
            || l.len() > 63
            || l.starts_with('-')
            || l.ends_with('-')
            || !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    ![
        "localhost",
        "local",
        "internal",
        "home",
        "lan",
        "test",
        "invalid",
        "onion",
        "in-addr.arpa",
        "ip6.arpa",
        "home.arpa",
    ]
    .iter()
    .any(|suffix| lower == *suffix || lower.ends_with(&format!(".{suffix}")))
}

fn prefix(value: u128, base: u128, bits: u32) -> bool {
    value >> (128 - bits) == base >> (128 - bits)
}
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let n = u32::from(ip);
            ![
                (0x00000000, 8),
                (0x0a000000, 8),
                (0x64400000, 10),
                (0x7f000000, 8),
                (0xa9fe0000, 16),
                (0xac100000, 12),
                (0xc0000000, 24),
                (0xc0000200, 24),
                (0xc0586300, 24),
                (0xc0a80000, 16),
                (0xc6120000, 15),
                (0xc6336400, 24),
                (0xcb007100, 24),
                (0xe0000000, 4),
                (0xf0000000, 4),
            ]
            .iter()
            .any(|&(base, bits)| n >> (32 - bits) == base >> (32 - bits))
        }
        IpAddr::V6(ip) => {
            let n = u128::from(ip);
            // Conservative native global unicast. Exclude IETF assignments,
            // documentation, 6to4, AS112 and segment-routing reservations.
            prefix(n, 0x2000u128 << 112, 3)
                && ![
                    (0x2001u128 << 112, 23),
                    (0x20010db8u128 << 96, 32),
                    (0x2002u128 << 112, 16),
                    (0x2620004f8000u128 << 80, 48),
                    (0x3fffu128 << 112, 20),
                ]
                .iter()
                .any(|&(base, bits)| prefix(n, base, bits))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn targets() {
        for name in ["example.com", "A-B.example.com."] {
            assert!(hostname(name), "{name}");
        }
        for name in [
            "localhost",
            "x.local",
            "x.internal",
            "x.home",
            "x.lan",
            "x.test",
            "x.invalid",
            "x.onion",
            "x.in-addr.arpa",
            "x.ip6.arpa",
            "x.home.arpa",
            "127.0.0.1",
            "123.456",
            "::1",
            "a..com",
            "-x.com",
            "x_.com",
            "é.com",
            "a\\046b.com",
        ] {
            assert!(!hostname(name), "{name}");
        }
        assert!(!hostname(&format!("{}.com", "a".repeat(64))));
        for ip in [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.31.0.1",
            "192.0.0.9",
            "192.0.2.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2001:db8::1",
            "2001::1",
            "2002:808:808::1",
            "fc00::1",
            "fe80::1",
            "3fff::1",
            "2620:4f:8000::",
            "2620:4f:8000:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "2620:4f:7fff::1",
            "2620:4f:8001::1",
            "2620:4f::1",
            "8.8.8.8",
            "198.41.0.4",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(public_ip(ip.parse().unwrap()), "{ip}");
        }
    }
}
