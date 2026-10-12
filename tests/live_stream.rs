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
