![ferrodns](docs/img/banner.svg)

A recursive DNS resolver from scratch in Rust — root to answer, standard library only.

[![CI](https://github.com/tczartoryski/ferrodns/actions/workflows/ci.yml/badge.svg)](https://github.com/tczartoryski/ferrodns/actions/workflows/ci.yml)
[![MIT](https://img.shields.io/badge/license-MIT-teal)](LICENSE)
![zero dependencies](https://img.shields.io/badge/dependencies-zero-teal)
![tested Rust](https://img.shields.io/badge/tested_Rust-1.99.0-orange)

**Work in progress:** the visualizer is specified but not implemented.
There is no live demo, GIF or release yet. The repository remains private
until the required publication checks pass.

## What happens when you look up a name

1. A client asks for an address.
2. The resolver asks a root server where to go next.
3. The TLD server points to the domain’s authoritative servers.
4. CNAMEs start another walk; glueless nameservers need their own lookup.
5. The answer is cached until its TTL expires, then returned to the client.

```text
client → root → TLD → authoritative → answer
                         ↘ CNAME → another zone
```

## Quickstart

```sh
cargo build --release
./target/release/ferrodns query example.com A --trace
./target/release/ferrodns serve --listen 127.0.0.1:55353
# In another terminal (pick an unused local port):
dig @127.0.0.1 -p 55353 github.com A
./target/release/ferrodns demo
# Local-only simulated internet, useful for safe testing:
./target/release/ferrodns sim 15353
dig @127.0.0.1 -p 15353 www.example.com A
```

`viz` and `--trace-json` are not available yet; see the [trace spec](docs/specs/trace-json.md).
No system DNS changes are needed. Edition 2024 requires Rust 1.85 or newer;
this run tested stable 1.99.0, not the minimum supported version.

## Features

| Area | Behavior | Reference |
|---|---|---|
| Wire format | Parser and serializer for headers, questions, A/AAAA/NS/CNAME/SOA/MX/TXT/PTR, opaque unknown types, and EDNS(0) | RFC 1035, 3596, 3597, 6891 |
| Name compression | Decodes pointers and refuses forward pointers or chains longer than 32 hops, so loops are impossible. Compresses on encode. | RFC 1035 §4.1.4 |
| Iteration | Starts at the deepest cached delegation (root hints otherwise) and follows referrals. Refuses upward and sideways referrals. | RFC 1034 §5.3.3 |
| Glueless delegations | Resolves out-of-zone NS names itself, with a nesting limit. Skips in-zone NS that have no glue. | |
| CNAMEs | Chases chains across zones and detects loops | RFC 1034 §3.6.2 |
| Negative caching | NXDOMAIN and NODATA cached for min(SOA TTL, SOA MINIMUM). Nothing is cached without an SOA. | RFC 2308 |
| NXDOMAIN cut | An NXDOMAIN at a name answers every name below it | RFC 8020 |
| Trust ranking | Glue never overwrites, and is never served as, authoritative answer data | RFC 2181 §5.4.1 |
| Bailiwick | Only caches answer records on the CNAME chain from the question, inside the zone that was asked. Only accepts glue inside the referring zone. | |
| Spoofing defenses | Random 16-bit IDs from the OS CSPRNG, a fresh ephemeral port per query, connected UDP sockets, and strict response/question matching | RFC 5452 |
| Server selection | Smoothed RTT per nameserver (EWMA with 70/30 weighting). Timeouts back off exponentially. Unknown servers get explored first. | like BIND and Unbound |
| Transport | UDP with a 1232-byte EDNS buffer. Falls back to TCP when the response is truncated. The server truncates for clients and supports multiple queries per TCP connection. | RFC 7766, DNS Flag Day 2020 |
| Limits | Per-request upstream query budget, referral cap, CNAME cap, and bounded cache size | |

## Visualizer

Planned: a self-contained waterfall, delegation tree and cold/warm comparison.
Specs: [trace JSON](docs/specs/trace-json.md), [visualizer](docs/specs/viz.md),
[site shell](docs/specs/site-shell.md). No screenshots are presented as proof
of an implementation that does not exist.

## Real-internet results

One paced release-build sweep on macOS, 2026-10-12. Fresh cache per name.
Answers were compared with system `dig`; CDN/provider and CNAME equivalence
matters more than identical address ordering or TTL.

| Name | Type | Status | Answers | Upstream queries | ms | Pass/fail | Notes |
|---|---|---|---:|---:|---:|---|---|
| example.com | A | NOERROR | 2 | 3 | 177.1 | PASS | Status and public answer checked against dig. |
| wikipedia.org | A | NOERROR | 1 | 3 | 93.4 | PASS | Status and public answer checked against dig. |
| github.com | A | NOERROR | 1 | 3 | 86.1 | PASS | Status and public answer checked against dig. |
| www.apple.com | A | NOERROR | 4 | 14 | 875.3 | PASS | CNAME/provider or address set checked against dig; CDN TTLs may differ. |
| www.microsoft.com | A | NOERROR | 3 | 9 | 386.4 | PASS | CNAME/provider or address set checked against dig; CDN TTLs may differ. |
| www.amazon.com | A | NOERROR | 3 | 8 | 585.6 | PASS | CNAME/provider or address set checked against dig; CDN TTLs may differ. |
| bbc.co.uk | A | NOERROR | 4 | 3 | 326.0 | PASS | Status and public answer checked against dig. |
| google.com | TXT | NOERROR | 17 | 4 | 171.3 | PASS | Status and public answer checked against dig. |
| google.com | MX | NOERROR | 1 | 3 | 197.2 | PASS | Status and public answer checked against dig. |
| _dmarc.gmail.com | TXT | NOERROR | 1 | 4 | 256.9 | PASS | Status and public answer checked against dig. |
| nic.cz | A | NOERROR | 1 | 2 | 213.7 | PASS | Status and public answer checked against dig. |
| thisdoesnotexist-ferrodns-test.com | A | NXDOMAIN | 0 | 3 | 213.7 | PASS | Status and public answer checked against dig. |
| example.com | AAAA | NOERROR | 2 | 4 | 194.1 | PASS | Status and public answer checked against dig. |
| www.cloudflare.com | AAAA | NOERROR | 2 | 3 | 201.2 | PASS | CNAME/provider or address set checked against dig; CDN TTLs may differ. |

No live-internet resolver bug surfaced in this sweep. The simulator did
expose a macOS portability bug: extra loopback addresses were unavailable.
It now uses unique localhost ports and explicit routing, with a regression
test for both UDP and TCP. [Full results and raw runs](docs/real-internet-results.md).

## Architecture

```text
server → resolver ⇄ cache
             ↓
         transport → root / TLD / authoritative
```

- `wire/`: DNS parsing, encoding and compression.
- `resolver.rs`: iteration, classification, CNAME/glueless walks and bailiwick.
- `cache.rs`: TTLs, trust ranking, NXDOMAIN and NODATA.
- `transport.rs`: UDP, response matching and TCP fallback.
- `server.rs`: UDP/TCP stub interface.
- `authority.rs`, `sim.rs`: local authoritative zones and fault injection.

[Detailed architecture](docs/ARCHITECTURE.md).

## Testing

38 tests passed locally: 22 unit and 16 integration tests.
The simulated internet covers delegation, glueless NS, CNAME loops, negative
caching, failover, UDP truncation/TCP, poisoning and concurrent clients.
Fuzz-style parser tests require random and mutated packets to fail without panic.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Tests and demo need only localhost, not network aliases or elevated access.

## Performance — local baseline, not a capacity claim

One serial Python UDP client, warmed `api.example.com A`, release build on
macOS: 1,000 successful requests in 0.045421 s; 22,016.5 queries/s, p50
37.1 µs, p99 72.2 µs. Includes client overhead and thread-per-query serving.
This is a short simulator baseline, not internet performance or a rigorous
comparison with other resolvers. [Run and reproducible script](docs/runs/sim-baseline.txt).

## Limitations and roadmap

- No DNSSEC validation. Do not use as a production resolver.
- No EDNS-rejection fallback.
- Glueless NS resolution currently requests A records only.
- IPv4 transport by default; no Happy Eyeballs.
- One thread per query; no in-flight request coalescing.
- Cache eviction is not LRU.
- Planned: structured traces/UI, EDNS fallback, IPv6-only glueless resolution,
  QNAME minimisation and bounded concurrency.

## License

[MIT](LICENSE), Copyright (c) 2026 Thomas Czartoryski.
