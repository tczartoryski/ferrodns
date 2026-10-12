//! Integration tests against the simulated internet in `ferrodns::sim`.
//! Each test uses its own port so the suite runs in parallel.

use ferrodns::authority::Behavior;
use ferrodns::resolver::{Config, ResolveError, Resolver};
use ferrodns::sim::{self, SimNet};
use ferrodns::wire::{Edns, Message, Name, RData, RType, Record, rcode};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn setup(port: u16) -> (SimNet, Resolver) {
    let net = sim::portable().expect("start sim");
    let cfg = Config {
        roots: net.roots.clone(),
        port,
        endpoints: net.endpoints.clone(),
        timeout: Duration::from_millis(200),
        ..Config::default()
    };
    (net, Resolver::new(cfg))
}

fn ips(records: &[Record]) -> Vec<IpAddr> {
    records
        .iter()
        .filter_map(|r| match r.data {
            RData::A(ip) => Some(IpAddr::V4(ip)),
            RData::Aaaa(ip) => Some(IpAddr::V6(ip)),
            _ => None,
        })
        .collect()
}

fn v4(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn follows_delegation_chain_from_the_root() {
    let (_net, r) = setup(21001);
    let (res, trace) = r.resolve_traced(&n("api.example.com"), RType::A, true);
    let res = res.unwrap();
    assert_eq!(res.rcode, rcode::NOERROR);
    let mut got = ips(&res.answers);
    got.sort();
    assert_eq!(got, vec![v4("192.0.2.10"), v4("192.0.2.11")]);
    let joined = trace.join("\n");
    assert!(
        joined.contains("[.]") && joined.contains("referral to com."),
        "{joined}"
    );
    assert!(joined.contains("referral to example.com."), "{joined}");
}

#[test]
fn second_query_is_served_from_cache() {
    let (net, r) = setup(21002);
    r.resolve(&n("api.example.com"), RType::A).unwrap();
    let before = net.total_queries();
    let res = r.resolve(&n("api.example.com"), RType::A).unwrap();
    assert_eq!(
        net.total_queries(),
        before,
        "no upstream traffic on a cache hit"
    );
    assert_eq!(res.answers.len(), 2);
    // Sibling names reuse the cached delegation: only the example.com server is asked.
    let root_before = net.server("a.root-servers.net").query_count()
        + net.server("b.root-servers.net").query_count();
    r.resolve(&n("mail.example.com"), RType::A).unwrap();
    let root_after = net.server("a.root-servers.net").query_count()
        + net.server("b.root-servers.net").query_count();
    assert_eq!(root_before, root_after);
    assert_eq!(net.total_queries(), before + 1);
}

#[test]
fn chases_cname_into_another_zone() {
    let (_net, r) = setup(21003);
    let res = r.resolve(&n("www.example.com"), RType::A).unwrap();
    assert_eq!(res.answers[0].rtype, RType::CNAME);
    assert_eq!(res.answers[0].target(), Some(&n("web.cdn-provider.net")));
    assert_eq!(ips(&res.answers), vec![v4("198.51.100.7")]);
    // In-zone CNAME chain.
    let res = r.resolve(&n("alias.example.com"), RType::A).unwrap();
    assert_eq!(res.answers.len(), 3);
}

#[test]
fn resolves_glueless_delegations() {
    let (_net, r) = setup(21004);
    let (res, trace) = r.resolve_traced(&n("www.glueless.com"), RType::A, true);
    assert_eq!(ips(&res.unwrap().answers), vec![v4("203.0.113.5")]);
    assert!(
        trace.iter().any(|l| l.contains("glueless delegation")),
        "{trace:?}"
    );
}

#[test]
fn nxdomain_is_negatively_cached_including_names_below_it() {
    let (net, r) = setup(21005);
    let res = r.resolve(&n("nope.example.com"), RType::A).unwrap();
    assert_eq!(res.rcode, rcode::NXDOMAIN);
    assert_eq!(res.authority[0].rtype, RType::SOA);
    let before = net.total_queries();
    assert_eq!(
        r.resolve(&n("nope.example.com"), RType::AAAA)
            .unwrap()
            .rcode,
        rcode::NXDOMAIN
    );
    // RFC 8020: nothing exists below an NXDOMAIN.
    assert_eq!(
        r.resolve(&n("a.b.nope.example.com"), RType::A)
            .unwrap()
            .rcode,
        rcode::NXDOMAIN
    );
    assert_eq!(net.total_queries(), before);
}

#[test]
fn nodata_and_empty_non_terminals() {
    let (net, r) = setup(21006);
    let res = r.resolve(&n("api.example.com"), RType::AAAA).unwrap();
    assert_eq!(res.rcode, rcode::NOERROR);
    assert!(res.answers.is_empty());
    assert_eq!(res.authority[0].rtype, RType::SOA);
    let before = net.total_queries();
    r.resolve(&n("api.example.com"), RType::AAAA).unwrap();
    assert_eq!(net.total_queries(), before, "NODATA cached");
    // empty.example.com has no records but deep.empty.example.com does: NODATA, not NXDOMAIN.
    assert_eq!(
        r.resolve(&n("empty.example.com"), RType::A).unwrap().rcode,
        rcode::NOERROR
    );
}

#[test]
fn fails_over_from_a_dead_nameserver_and_learns_to_avoid_it() {
    let (net, r) = setup(21007);
    net.server("ns1.example.com").set_behavior(Behavior {
        drop: true,
        ..Default::default()
    });
    for name in [
        "api.example.com",
        "mail.example.com",
        "txt.example.com",
        "www.example.com",
    ] {
        let qt = if name.starts_with("txt") {
            RType::TXT
        } else {
            RType::A
        };
        let res = r.resolve(&n(name), qt).unwrap();
        assert!(!res.answers.is_empty(), "{name}");
    }
    // After at most one timeout, SRTT ordering sends traffic to ns2 first.
    assert!(
        net.server("ns1.example.com").query_count() <= 1,
        "dead server retried {} times",
        net.server("ns1.example.com").query_count()
    );
}

#[test]
fn servfail_and_refused_servers_are_skipped() {
    let (net, r) = setup(21008);
    net.server("ns1.example.com").set_behavior(Behavior {
        rcode: Some(rcode::SERVFAIL),
        ..Default::default()
    });
    net.server("ns2.example.com").set_behavior(Behavior {
        rcode: Some(rcode::REFUSED),
        ..Default::default()
    });
    let err = r.resolve(&n("api.example.com"), RType::A).unwrap_err();
    assert_eq!(err, ResolveError::AllServersFailed(n("example.com")));
    // Recovery once one server is healthy again.
    net.server("ns2.example.com")
        .set_behavior(Behavior::default());
    assert_eq!(
        r.resolve(&n("api.example.com"), RType::A)
            .unwrap()
            .answers
            .len(),
        2
    );
}

#[test]
fn truncated_udp_falls_back_to_tcp() {
    let (_net, r) = setup(21009);
    let res = r.resolve(&n("big.example.com"), RType::TXT).unwrap();
    assert_eq!(res.answers.len(), 24);
    assert!(r.stats.tcp_fallbacks.load(Ordering::Relaxed) >= 1);
}

#[test]
fn ignores_out_of_bailiwick_poison() {
    let (net, r) = setup(21010);
    let fake = Ipv4Addr::new(192, 0, 2, 66);
    net.server("ns1.evil.com").set_behavior(Behavior {
        poison_additional: vec![
            Record::new(n("www.bank.com"), 86400, RData::A(fake)),
            Record::new(n("ns1.bank.com"), 86400, RData::A(fake)),
        ],
        poison_authority: vec![Record::new(
            n("bank.com"),
            86400,
            RData::Ns(n("ns1.evil.com")),
        )],
        ..Default::default()
    });
    assert_eq!(
        ips(&r.resolve(&n("www.evil.com"), RType::A).unwrap().answers),
        vec![v4("192.0.2.77")]
    );
    assert_eq!(
        ips(&r.resolve(&n("www.bank.com"), RType::A).unwrap().answers),
        vec![v4("192.0.2.200")]
    );
    assert!(
        net.server("ns1.bank.com").query_count() >= 1,
        "bank.com was resolved via its real server"
    );
}

#[test]
fn cname_loops_are_detected() {
    let (_net, r) = setup(21011);
    assert_eq!(
        r.resolve(&n("loop1.example.com"), RType::A).unwrap_err(),
        ResolveError::CnameLoop
    );
}

#[test]
fn unreachable_roots_fail_cleanly() {
    let (net, r) = setup(21012);
    for h in ["a.root-servers.net", "b.root-servers.net"] {
        net.server(h).set_behavior(Behavior {
            drop: true,
            ..Default::default()
        });
    }
    assert_eq!(
        r.resolve(&n("api.example.com"), RType::A).unwrap_err(),
        ResolveError::AllServersFailed(Name::root())
    );
}

#[test]
fn work_per_request_is_bounded() {
    let net = sim::portable().unwrap();
    let cfg = Config {
        roots: net.roots.clone(),
        port: 21013,
        endpoints: net.endpoints.clone(),
        timeout: Duration::from_millis(200),
        max_queries: 2,
        ..Config::default()
    };
    let r = Resolver::new(cfg);
    assert_eq!(
        r.resolve(&n("api.example.com"), RType::A).unwrap_err(),
        ResolveError::QueryBudgetExhausted
    );
}

#[test]
fn concurrent_clients_share_one_cache() {
    let (_net, r) = setup(21014);
    let r = Arc::new(r);
    let handles: Vec<_> = (0..32)
        .map(|i| {
            let r = Arc::clone(&r);
            std::thread::spawn(move || {
                let name = [
                    "api.example.com",
                    "www.example.com",
                    "www.glueless.com",
                    "www.bank.com",
                ][i % 4];
                r.resolve(&n(name), RType::A).unwrap()
            })
        })
        .collect();
    for h in handles {
        assert!(!h.join().unwrap().answers.is_empty());
    }
}

// ---- end to end through the recursive server ----

fn client_query(name: &str, qtype: RType, edns: bool) -> Message {
    let mut q = Message::query(0x4242, n(name), qtype, true, edns.then(|| Edns::new(4096)));
    q.header.rd = true;
    q
}

fn udp_ask(server: SocketAddr, q: &Message) -> Message {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.send_to(&q.to_bytes().unwrap(), server).unwrap();
    let mut buf = [0u8; 65535];
    let (len, _) = s.recv_from(&mut buf).unwrap();
    Message::parse(&buf[..len]).unwrap()
}

fn tcp_ask(server: SocketAddr, q: &Message) -> Message {
    let mut s = TcpStream::connect(server).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let b = q.to_bytes().unwrap();
    let mut framed = (b.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&b);
    s.write_all(&framed).unwrap();
    let mut len = [0u8; 2];
    s.read_exact(&mut len).unwrap();
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut buf).unwrap();
    Message::parse(&buf).unwrap()
}

#[test]
fn serves_stub_clients_over_udp_and_tcp() {
    let (_net, r) = setup(21015);
    let addr: SocketAddr = "127.0.0.1:21115".parse().unwrap();
    ferrodns::server::spawn(Arc::new(r), addr).unwrap();
    std::thread::sleep(Duration::from_millis(50));

    let resp = udp_ask(addr, &client_query("www.example.com", RType::A, true));
    assert!(resp.header.qr && resp.header.ra && resp.header.rd);
    assert_eq!(resp.header.id, 0x4242);
    assert_eq!(resp.header.rcode, rcode::NOERROR);
    assert_eq!(resp.answers.len(), 2);
    assert!(resp.edns.is_some());

    // Without EDNS the 512-byte limit applies: big answer comes back truncated...
    let resp = udp_ask(addr, &client_query("big.example.com", RType::TXT, false));
    assert!(resp.header.tc && resp.answers.is_empty());
    // ...and the client gets it in full over TCP.
    let resp = tcp_ask(addr, &client_query("big.example.com", RType::TXT, false));
    assert!(!resp.header.tc);
    assert_eq!(resp.answers.len(), 24);

    let resp = udp_ask(addr, &client_query("nope.example.com", RType::A, true));
    assert_eq!(resp.header.rcode, rcode::NXDOMAIN);
    assert_eq!(resp.authority.len(), 1);

    let resp = udp_ask(addr, &client_query("loop1.example.com", RType::A, true));
    assert_eq!(resp.header.rcode, rcode::SERVFAIL);

    // Garbage gets FORMERR, not silence or a crash.
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.send_to(
        &[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xFF],
        addr,
    )
    .unwrap();
    let mut buf = [0u8; 512];
    let (len, _) = s.recv_from(&mut buf).unwrap();
    let resp = Message::parse(&buf[..len]).unwrap();
    assert_eq!(resp.header.rcode, rcode::FORMERR);
    assert_eq!(resp.header.id, 0x1234);
}

#[test]
fn portable_sim_uses_only_localhost_and_isolates_servers() {
    let net = sim::portable().unwrap();
    let endpoints: std::collections::HashSet<_> = net.endpoints.values().copied().collect();
    assert_eq!(endpoints.len(), net.servers.len());
    assert!(
        endpoints
            .iter()
            .all(|a| a.ip() == v4("127.0.0.1") && a.port() != 0)
    );
    let r = Resolver::new(Config {
        roots: net.roots.clone(),
        endpoints: net.endpoints.clone(),
        ..Config::default()
    });
    assert_eq!(
        ips(&r.resolve(&n("api.example.com"), RType::A).unwrap().answers).len(),
        2
    );
    assert_eq!(
        r.resolve(&n("big.example.com"), RType::TXT)
            .unwrap()
            .answers
            .len(),
        24
    );
    assert!(r.stats.tcp_fallbacks.load(Ordering::Relaxed) > 0);
}
