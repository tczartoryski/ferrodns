### Spec B: `docs/specs/viz.md` (one static file: `site/viz/index.html`)

- **Format:** a single self-contained HTML file with inline CSS and JS, plain SVG, no framework and no build step.
- **Loading:** it reads the embedded `#trace` if present. Otherwise it accepts a file picker, drag-and-drop, or `?trace=<relative path>`.
- **Waterfall, like the DevTools Network tab:**
  - one row per event, with bars positioned by `t_ms` and `dur_ms`
  - rows labeled `zone → server (ip)` and indented by depth
  - colors by outcome: referral, answer, cname, timeout, cache hit, nxdomain
  - a hover tooltip showing the detail
- **Delegation tree beside the waterfall:**
  - root → TLD → zone → answer as nodes
  - a CNAME starts a second branch
  - glueless sub-resolutions appear as a side branch
  - hovering a node highlights its rows in the waterfall
- **Summary strip:** total ms, upstream queries, servers contacted, TCP fallbacks and timeouts.
- **Compare mode:** two traces side by side (cold vs. warm, for example).
- **Look and feel:**
  - light and dark mode via `prefers-color-scheme`
  - a monospace face for names and IPs
  - works at laptop width and doesn't break on a phone
