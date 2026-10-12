# Contributing

Use stable Rust (edition 2024). Run `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, and `cargo test`.

The resolver must remain zero-dependency. Every bug fix needs a regression
test. Simulated zones use only localhost endpoints and require no elevated
permissions. Never load-test internet authorities.
