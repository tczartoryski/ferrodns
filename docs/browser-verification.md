# Public browser verification — 2026-10-12

Pages: https://tczartoryski.github.io/ferrodns/
Initial deployment: https://github.com/tczartoryski/ferrodns/actions/runs/38309551443 (success).

First-class OpenClaw Chromium browser on public HTTPS; no local navigation workaround.

| Sample | Event rows | Tree nodes | Result |
|---|---:|---:|---|
| apple-cold | 17 | 19 | 487.24 ms displayed; 13 upstream; CNAME/glueless branches |
| apple-warm | 7 | 4 | 0.06 ms displayed; zero upstream |
| nxdomain | 2 | 3 | 50.23 ms; no answers |
| google-txt | 3 | 4 | 431.37 ms; TXT answers; UDP only |
| simulated-tcp | 3 | 4 | 1.19 ms; one TCP fallback; explicitly simulated |

All samples rendered with zero error panels. Actual pointer hover displayed the root referral tooltip; hovering apple.com highlighted its event row. Native file-input upload loaded the warm trace into the comparison panel and NXDOMAIN into the primary panel. Cold/warm screenshot records actual side-by-side UI.

Desktop light (1440×1000 viewport) and iPhone 13 dark (390 CSS pixels) tested. Phone body scroll width equals viewport width; tree/waterfall have contained horizontal scroll for long names and labels. Screenshots visually inspected, not only DOM assertions.

Assets: waterfall.png, cold-vs-warm.png and demo.gif under docs/img. GIF is a six-second three-frame sequence of genuine browser captures (loaded trace, waterfall tooltip, highlighted tree), not a continuous macOS recording or terminal-to-browser demonstration. No screenshot includes personal desktop/browser chrome. Social preview is an original wordmark plus real waterfall capture; manual Settings upload remains an owner action.

Still not exercised: an actual OS drag/drop gesture, local file:// navigation (policy blocked previously). Embedded export is hosted at viz/embedded/ for a legitimate HTTPS rendering check. No Wireshark capture: elevated packet capture was not authorized.
