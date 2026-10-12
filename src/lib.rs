//! ferrodns: a recursive DNS resolver written from scratch on the Rust standard library.

pub mod authority;
pub mod cache;
pub mod hints;
pub mod live_http;
pub mod live_policy;
pub mod resolver;
pub mod rng;
pub mod server;
pub mod sim;
pub mod trace;
pub mod transport;
pub mod wire;
