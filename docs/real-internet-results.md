# Real-internet verification

Recorded 2026-10-12 on macOS, stable Rust 1.99.0, release build.
One paced sweep, fresh process/cache for each query; one second between names.
Each query used `--trace`; comparison used system `dig name type`.
Raw public-only outputs are in [runs/](runs/). No internet load testing.

## Failures first

No resolution failures in the 14-question sweep. No parser failures surfaced.
The initial full test suite failed all 15 integration tests on macOS with
`AddrNotAvailable` because unconfigured 127.0.0.x aliases cannot be bound.
This is a simulator portability bug, not an internet-resolution bug.

| Name | Type | Status | Answers | Upstream queries | ms | Pass/fail | Notes |
|---|---|---|---:|---:|---:|---|---|
| example.com | A | NOERROR | 2 | 3 | 177.1 | PASS | Status and public answer checked against dig. |
| wikipedia.org | A | NOERROR | 1 | 3 | 93.4 | PASS | Status and public answer checked against dig. |
| github.com | A | NOERROR | 1 | 3 | 86.1 | PASS | Azure-hosted address differed from dig (172.182.252.133 vs 20.29.134.23); plausible geo answer, not identical. |
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

## Fix and regression

Simulator servers now bind distinct OS-assigned localhost ports. An explicit
logical-IP-to-endpoint map lets DNS glue and nameserver selection keep their
identity without privileged network configuration. Both UDP and TCP use it.
Internet defaults have no mapping and still use port 53.
`demo`, `sim` and all integration tests use the portable mode.

Regression: [`portable_sim_uses_only_localhost_and_isolates_servers`](../tests/simnet.rs)
checks localhost-only unique endpoints, a delegation answer and TCP fallback.
All existing poisoning, glueless, failover and server tests now run on macOS.

## Checks

Local: 22 unit + 16 integration tests pass; fmt and all-target clippy pass.
No measured throughput claim is carried forward from the original README.
The supplied 2-vCPU numbers had no accessible run evidence and were removed.

## Stub-server transport and cache

The already-running resolver on port 55353 answered github.com in 65 ms;
a repeat one second later took 0 ms at dig’s millisecond granularity, with
a decremented TTL. A google.com TXT UDP query limited to 512 bytes returned
TC and no answer records; the TCP retry returned 17 answers without TC.
[Raw client evidence](runs/server-transport.txt). Port 5353 was left untouched.

## Preflight

Hickory DNS and Unbound are existing relevant projects (their GitHub pages
responded successfully). Neither fits the explicitly requested custom
zero-dependency resolver and hand-written trace/UI exercise; no library added.

## Structured trace follow-up

See [trace-recordings.md](trace-recordings.md) for the new matched cold/warm pair and public JSON sample evidence. These measurements are separate from the original 14-question sweep.
