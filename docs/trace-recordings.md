# Structured trace recordings

Recorded 2026-10-12, macOS release build. One paced set; no internet load test.
Apple cold/warm below are consecutive requests to the same newly started resolver.
The earlier standalone cold run is separate (595.338 ms), not the matched comparison.

| File | Source | Status | Answers | Upstream exchanges | ms | Observed behavior |
|---|---|---|---:|---:|---:|---|
| apple-cold.json | real internet | NOERROR | 4 | 13 | 487.240 | cname, glueless |
| apple-warm.json | real internet | NOERROR | 4 | 0 | 0.057 | cname, cache_hit |
| google-txt.json | real internet | NOERROR | 17 | 3 | 431.369 | UDP |
| nxdomain.json | real internet | NXDOMAIN | 0 | 2 | 50.228 | UDP |
| simulated-tcp.json | SIMULATED localhost | NOERROR | 24 | 3 | 1.188 | UDP truncation → TCP |

No real timeout/failover or upstream TCP fallback was observed in these JSON recordings.
Google TXT succeeded over UDP in this run; it is not a TCP example.
Apple cold includes a genuine glueless lookup of a public aaplimg.com nameserver.

Trace TCP duration combines the initial UDP exchange and TCP retry, not separate timing.
Failed exchange transport is null because the existing transport error loses that metadata.
trace-dir covers queries reaching resolution, not malformed/refused packets rejected earlier.
The golden JSON fixture is an inline constant in tests/simnet.rs to honor task file scope.

Generated export at /tmp during verification contained exactly one valid embedded trace.
Mock-DOM logic checks are recorded in docs/runs/viz-checks.txt, not browser rendering proof.
No capture, packet dump, screenshot, GIF or social preview was fabricated.
