//! A simulated internet on loopback: two root servers, TLD servers for com/net/org,
//! and a handful of authoritative zones that exercise the interesting cases
//! (CNAMEs across zones, glueless delegations, truncation, a hostile server).
//!
//! Every server listens on its own 127.0.0.x address on a shared port, so a
//! resolver pointed at the sim's root hints behaves exactly as it would on the
//! real internet, just with `port` instead of 53.

use crate::authority::{AuthServer, Zone};
use crate::hints::Hint;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

pub struct SimNet {
    pub port: u16,
    /// Servers by hostname, e.g. "ns1.example.com".
    pub servers: BTreeMap<&'static str, (IpAddr, Arc<AuthServer>)>,
    pub roots: Vec<Hint>,
    pub endpoints: HashMap<IpAddr, SocketAddr>,
}

impl SimNet {
    pub fn server(&self, host: &str) -> &Arc<AuthServer> {
        &self
            .servers
            .get(host)
            .unwrap_or_else(|| panic!("no sim server {host}"))
            .1
    }

    pub fn total_queries(&self) -> usize {
        self.servers.values().map(|(_, s)| s.query_count()).sum()
    }
}

const SOA: &str = "SOA ns1 hostmaster 2026101001 7200 900 1209600 300";

fn zone(origin: &str, body: &str) -> Zone {
    let text = format!("@ 3600 {SOA}\n{body}");
    Zone::parse(origin, &text).unwrap_or_else(|e| panic!("sim zone {origin}: {e}"))
}

fn big_txt() -> String {
    // ~2.4 KB of TXT data: bigger than the 1232-byte EDNS limit, so UDP truncates.
    (0..24)
        .map(|i| format!("big 300 TXT \"{i:02}-{}\"\n", "x".repeat(90)))
        .collect()
}

/// Build and start the standard simulated internet on `port`.
pub fn standard(port: u16) -> io::Result<SimNet> {
    build(port, false)
}

/// A simulated network using only the configured localhost address, with
/// separate OS-assigned ports. No loopback aliases or administrator rights.
pub fn portable() -> io::Result<SimNet> {
    build(0, true)
}

fn build(port: u16, portable: bool) -> io::Result<SimNet> {
    let root = zone(
        ".",
        "
        @ 518400 NS a.root-servers.net.
        @ 518400 NS b.root-servers.net.
        a.root-servers.net. 518400 A 127.0.0.10
        b.root-servers.net. 518400 A 127.0.0.11
        com. 172800 NS a.gtld-servers.net.
        net. 172800 NS a.gtld-servers.net.
        a.gtld-servers.net. 172800 A 127.0.0.20
        org. 172800 NS ns1.org-servers.org.
        ns1.org-servers.org. 172800 A 127.0.0.21
        ",
    );
    let com = zone(
        "com",
        "
        example 172800 NS ns1.example.com.
        example 172800 NS ns2.example.com.
        ns1.example 172800 A 127.0.0.30
        ns2.example 172800 A 127.0.0.31
        glueless 172800 NS ns.dns-host.net.
        bank 172800 NS ns1.bank.com.
        ns1.bank 172800 A 127.0.0.33
        evil 172800 NS ns1.evil.com.
        ns1.evil 172800 A 127.0.0.34
        ",
    );
    let net = zone(
        "net",
        "
        dns-host 172800 NS ns1.dns-host.net.
        ns1.dns-host 172800 A 127.0.0.40
        cdn-provider 172800 NS ns1.cdn-provider.net.
        ns1.cdn-provider 172800 A 127.0.0.41
        ",
    );
    let org = zone("org", "");
    let example = zone(
        "example.com",
        &format!(
            "
            @ 3600 NS ns1
            @ 3600 NS ns2
            ns1 3600 A 127.0.0.30
            ns2 3600 A 127.0.0.31
            @ 3600 MX 10 mail
            mail 3600 A 192.0.2.25
            api 300 A 192.0.2.10
            api 300 A 192.0.2.11
            alias 300 CNAME api
            www 300 CNAME web.cdn-provider.net.
            loop1 300 CNAME loop2
            loop2 300 CNAME loop1
            txt 300 TXT \"hello from example.com\"
            deep.empty 300 A 192.0.2.99
            {}",
            big_txt()
        ),
    );
    let dns_host = zone(
        "dns-host.net",
        "
        @ 3600 NS ns1
        ns1 3600 A 127.0.0.40
        ns 3600 A 127.0.0.35
        ",
    );
    let glueless = zone(
        "glueless.com",
        "
        @ 3600 NS ns.dns-host.net.
        www 300 A 203.0.113.5
        ",
    );
    let cdn = zone(
        "cdn-provider.net",
        "
        @ 3600 NS ns1
        ns1 3600 A 127.0.0.41
        web 60 A 198.51.100.7
        web 60 AAAA 2001:db8::7
        ",
    );
    let bank = zone(
        "bank.com",
        "
        @ 3600 NS ns1
        ns1 3600 A 127.0.0.33
        www 300 A 192.0.2.200
        ",
    );
    let evil = zone(
        "evil.com",
        "
        @ 3600 NS ns1
        ns1 3600 A 127.0.0.34
        www 300 A 192.0.2.77
        ",
    );

    let layout: Vec<(&'static str, &str, Vec<Zone>)> = vec![
        ("a.root-servers.net", "127.0.0.10", vec![root.clone()]),
        ("b.root-servers.net", "127.0.0.11", vec![root]),
        ("a.gtld-servers.net", "127.0.0.20", vec![com, net]),
        ("ns1.org-servers.org", "127.0.0.21", vec![org]),
        ("ns1.example.com", "127.0.0.30", vec![example.clone()]),
        ("ns2.example.com", "127.0.0.31", vec![example]),
        ("ns1.bank.com", "127.0.0.33", vec![bank]),
        ("ns1.evil.com", "127.0.0.34", vec![evil]),
        ("ns.dns-host.net", "127.0.0.35", vec![glueless]),
        ("ns1.dns-host.net", "127.0.0.40", vec![dns_host]),
        ("ns1.cdn-provider.net", "127.0.0.41", vec![cdn]),
    ];
    let mut servers = BTreeMap::new();
    let mut endpoints = HashMap::new();
    for (host, ip, zones) in layout {
        let ip: IpAddr = ip.parse().unwrap();
        let srv = AuthServer::new(zones);
        let bind = if portable {
            "127.0.0.1:0".parse().unwrap()
        } else {
            SocketAddr::new(ip, port)
        };
        endpoints.insert(ip, srv.spawn_bound(bind)?);
        servers.insert(host, (ip, srv));
    }
    let roots = ["a.root-servers.net", "b.root-servers.net"]
        .iter()
        .map(|h| Hint {
            name: h.parse().unwrap(),
            addr: servers[h].0,
        })
        .collect();
    Ok(SimNet {
        port,
        servers,
        roots,
        endpoints,
    })
}
