# Changelog

## Unreleased — v0.1.0 candidate

- Recursive resolution from root hints, CNAME chasing and TTL/negative caching.
- UDP transport with truncation-triggered TCP fallback and a UDP/TCP stub server.
- Portable simulator routing: distinct logical nameservers use separate localhost
  ports without operating-system network changes. Tests and demo use this mode.
- Structured trace JSON, per-resolved-client trace directories and standalone viz export.
- Self-contained HTML waterfall, delegation tree, comparison view and static gallery.
- HTML-safe JSON escaping and regression tests for failures, TCP metadata and concurrent trace writes.
- Rendered-browser proof, demo assets and public deployment remain gated.
