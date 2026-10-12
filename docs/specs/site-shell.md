### Spec C: the site shell (`site/`)

- `site/index.html` is the landing page:
  - a one-line pitch and a short explanation of what a recursive resolver does
  - the demo GIF
  - links to the viz gallery, the GitHub repo and the write-up
- `site/viz/samples/` holds 4–6 real traces you record in section 4: `www.apple.com` cold, the same name warm, a timeout followed by failover (if you catch one), a glueless delegation, an NXDOMAIN and a TCP fallback.
- The gallery links each sample to `viz/?trace=samples/<file>.json`.
- **Privacy:** sample traces must contain only public domain lookups. Strip anything from Thomas's local network.

---

