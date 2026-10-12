## Architecture

```
            stub client (dig, OS resolver)
                       │ UDP / TCP
                ┌──────▼──────┐
                │  server.rs  │  parse, validate, size-limit / truncate response
                └──────┬──────┘
                ┌──────▼──────┐        ┌──────────┐
                │ resolver.rs │◄──────►│ cache.rs │  RRsets + trust rank, NXDOMAIN/NODATA
                │  iterate,   │        └──────────┘
                │  classify,  │        ┌──────────┐
                │  bailiwick  │◄──────►│  SRTT    │  per-nameserver smoothed RTT
                └──────┬──────┘        └──────────┘
                ┌──────▼──────┐
                │transport.rs │  UDP → TCP on TC, ID/question matching
                └──────┬──────┘
                       ▼
       root → TLD → authoritative servers (real internet or sim.rs)
```

- `src/wire/`: DNS message encoding and decoding
- `src/resolver.rs`: the iterative algorithm. `classify()` decides what an upstream response means (answer, CNAME, referral, NXDOMAIN, NODATA or lame), and most of the security logic lives there.
- `src/cache.rs`: TTL-aware RRset cache with trust ranks and negative caching
- `src/transport.rs`: one query to one server
- `src/server.rs`: the recursive server for stub clients
- `src/authority.rs`: a small authoritative server with a minimal zone-file parser and knobs for misbehaving (drop, SERVFAIL, forced truncation, injecting poison records)
- `src/sim.rs`: a **simulated internet** on `127.0.0.0/8`, with two roots, com/net/org TLDs and several zones built to exercise the interesting cases


## Portable simulation

`sim::portable()` binds each authoritative server on a unique OS-assigned
localhost port. Its endpoint map is explicitly supplied to `Config`. DNS
referrals keep logical nameserver IP identities, while transport maps them to
actual sockets for both UDP and TCP. The default map is empty, so internet
queries are unchanged. `sim::standard(port)` remains available for hosts with
the full loopback range configured.

The `sim` CLI exposes a recursive stub endpoint over the portable network;
`demo` uses the same network in-process. No administrator rights are needed.
