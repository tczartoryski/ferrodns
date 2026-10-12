# Changelog

## Unreleased — v0.1.0 candidate

- Recursive resolution from root hints, CNAME chasing and TTL/negative caching.
- UDP transport with truncation-triggered TCP fallback and a UDP/TCP stub server.
- Portable simulator routing: distinct logical nameservers use separate localhost
  ports without operating-system network changes. Tests and demo use this mode.
- Structured trace JSON and visualizer are specified but not implemented yet.
