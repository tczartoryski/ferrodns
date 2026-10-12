use ferrodns::{
    hints::Hint,
    live_policy::Control,
    resolver::{Config, Resolver},
    wire::{Message, RData, RType, Record},
};
use std::{
    collections::HashMap,
    net::UdpSocket,
    sync::{Arc, mpsc},
    time::Duration,
};
#[test]
fn incremental_events_arrive_while_upstream_is_waiting() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let endpoint = socket.local_addr().unwrap();
    let (release, wait) = mpsc::channel();
    let upstream = std::thread::spawn(move || {
        let mut buf = [0; 4096];
        let (n, peer) = socket.recv_from(&mut buf).unwrap();
        let mut reply = Message::parse(&buf[..n]).unwrap();
        wait.recv_timeout(Duration::from_secs(3)).unwrap();
        reply.header.qr = true;
        reply.header.aa = true;
        reply.answers.push(Record::new(
            reply.questions[0].name.clone(),
            30,
            RData::A("8.8.8.8".parse().unwrap()),
        ));
        socket.send_to(&reply.to_bytes().unwrap(), peer).unwrap();
    });
    let ip = "127.0.0.1".parse().unwrap();
    let resolver = Resolver::new(Config {
        roots: vec![Hint {
            name: "ns.example.com".parse().unwrap(),
            addr: ip,
        }],
        endpoints: HashMap::from([(ip, endpoint)]),
        timeout: Duration::from_secs(2),
        ..Config::default()
    });
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        resolver.resolve_live(
            &"example.com".parse().unwrap(),
            RType::A,
            Control::new(false, Duration::from_secs(3)),
            Arc::new(move |e| tx.send(e).is_ok()),
        )
    });
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(1)).unwrap().kind,
        "query_start"
    );
    assert!(!worker.is_finished());
    assert!(rx.try_recv().is_err());
    release.send(()).unwrap();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(1)).unwrap().kind,
        "query"
    );
    assert!(worker.join().unwrap().0.is_ok());
    upstream.join().unwrap();
}

#[test]
fn cancellation_reaches_waiting_udp_and_stops_further_queries() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let endpoint = socket.local_addr().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let ip = "127.0.0.1".parse().unwrap();
    let resolver = Resolver::new(Config {
        roots: vec![Hint {
            name: "ns.example.com".parse().unwrap(),
            addr: ip,
        }],
        endpoints: HashMap::from([(ip, endpoint)]),
        timeout: Duration::from_secs(3),
        ..Config::default()
    });
    let control = Control::new(false, Duration::from_secs(10));
    let worker_control = control.clone();
    let worker = std::thread::spawn(move || {
        resolver.resolve_live(
            &"example.com".parse().unwrap(),
            RType::A,
            worker_control,
            Arc::new(|_| true),
        )
    });
    let mut packet = [0; 4096];
    socket.recv_from(&mut packet).unwrap();
    let start = std::time::Instant::now();
    control.cancel();
    assert!(matches!(
        worker.join().unwrap().0,
        Err(ferrodns::resolver::ResolveError::Interrupted("cancelled"))
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn live_budget_counts_udp_and_tcp_attempts_including_failed_fallbacks() {
    use std::io::{Read, Write};
    use std::sync::atomic::Ordering;
    for budget in [1usize, 2, 32] {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let endpoint = udp.local_addr().unwrap();
        let tcp = std::net::TcpListener::bind(endpoint).unwrap();
        tcp.set_nonblocking(true).unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let upstream = std::thread::spawn(move || {
            let mut attempts = 0;
            for n in 0..budget.div_ceil(2) {
                let mut buf = [0; 4096];
                let (len, peer) = udp.recv_from(&mut buf).unwrap();
                attempts += 1;
                let mut reply = Message::parse(&buf[..len]).unwrap();
                reply.header.qr = true;
                reply.header.tc = true;
                udp.send_to(&reply.to_bytes().unwrap(), peer).unwrap();
                if n * 2 + 1 < budget {
                    let deadline = std::time::Instant::now() + Duration::from_secs(3);
                    let mut stream = loop {
                        match tcp.accept() {
                            Ok((s, _)) => break s,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                assert!(std::time::Instant::now() < deadline);
                                std::thread::sleep(Duration::from_millis(1));
                            }
                            Err(e) => panic!("{e}"),
                        }
                    };
                    attempts += 1;
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let mut len = [0; 2];
                    stream.read_exact(&mut len).unwrap();
                    let mut query = vec![0; u16::from_be_bytes(len) as usize];
                    stream.read_exact(&mut query).unwrap();
                    reply.header.tc = false;
                    reply.header.id = reply.header.id.wrapping_add(1);
                    let bytes = reply.to_bytes().unwrap();
                    stream
                        .write_all(&(bytes.len() as u16).to_be_bytes())
                        .unwrap();
                    stream.write_all(&bytes).unwrap();
                }
            }
            (attempts, udp, tcp)
        });
        let ip = endpoint.ip();
        let resolver = Resolver::new(Config {
            roots: (0..33)
                .map(|_| Hint {
                    name: "ns.example.com".parse().unwrap(),
                    addr: ip,
                })
                .collect(),
            endpoints: HashMap::from([(ip, endpoint)]),
            max_queries: budget,
            timeout: Duration::from_secs(2),
            ..Config::default()
        });
        let result = resolver
            .resolve_live(
                &"example.com".parse().unwrap(),
                RType::A,
                Control::new(false, Duration::from_secs(10)),
                Arc::new(|_| true),
            )
            .0;
        assert!(matches!(
            result,
            Err(ferrodns::resolver::ResolveError::QueryBudgetExhausted)
        ));
        let (attempts, udp, tcp) = upstream.join().unwrap();
        assert_eq!(attempts, budget);
        assert_eq!(
            resolver.stats.upstream_queries.load(Ordering::Relaxed),
            budget as u64
        );
        udp.set_nonblocking(true).unwrap();
        assert_eq!(
            udp.recv(&mut [0; 4096]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            tcp.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
