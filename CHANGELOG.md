# Changelog

## v0.2.0 — 2026-10-12

- Hosted live A/AAAA lookup with incremental delegation tree and timing waterfall.
- Separate zero-dependency `ferrodns-live` HTTP/SSE binary, with public-only
  upstream policy, cancellation, deadlines, rate limits and bounded work.
- Explicit Cancel/Retry controls; uploads, samples and comparison remain available.
- Render Free deployment verified for outbound UDP/TCP DNS and real browser streaming.
- Live lifecycle, transport-budget, health and cancellation regression coverage.

## v0.1.0 — 2026-10-12

- Recursive resolution from root hints, CNAME chasing and TTL/negative caching.
- UDP transport with truncation-triggered TCP fallback and a UDP/TCP stub server.
- Portable simulator routing: distinct logical nameservers use separate localhost
  ports without operating-system network changes. Tests and demo use this mode.
- Structured trace JSON, per-resolved-client trace directories and standalone viz export.
- Self-contained HTML waterfall, delegation tree, comparison view and static gallery.
- HTML-safe JSON escaping and regression tests for failures, TCP metadata and concurrent trace writes.
- Published static gallery, demo assets and rendered-browser verification.
