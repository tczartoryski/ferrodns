# Coding rules

- Keep the resolver zero-dependency; `[dependencies]` stays empty.
- Run `cargo test` and `cargo clippy --all-targets -- -D warnings` before finishing. The owner independently verifies both.
- Never read `target/`, `*.pcap`, `docs/*.png`, `docs/*.gif` or binary demo assets.
- Keep diffs minimal and within the task file scope. Add regression tests for bug fixes.
- Task A: docs/specs/trace-json.md, medium reasoning.
- Task B: docs/specs/viz.md, low reasoning.
- Task C: docs/specs/site-shell.md, low reasoning.
- Use one plan approval and no more than two fix rounds per task, each in its own T3 Code thread and worktree.
