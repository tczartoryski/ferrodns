//! Randomness for query IDs and server tie-breaking.
//!
//! Query IDs are security-relevant (off-path spoofing, RFC 5452), so they come
//! straight from the OS CSPRNG via /dev/urandom rather than a userspace PRNG.

use std::fs::File;
use std::io::Read;
use std::sync::{Mutex, OnceLock};

fn urandom() -> &'static Mutex<Option<File>> {
    static F: OnceLock<Mutex<Option<File>>> = OnceLock::new();
    F.get_or_init(|| Mutex::new(File::open("/dev/urandom").ok()))
}

/// Fill `buf` with OS randomness. Falls back to std's randomly-keyed hasher
/// if /dev/urandom is unavailable (e.g. non-Unix platforms).
pub fn fill(buf: &mut [u8]) {
    if let Ok(mut guard) = urandom().lock()
        && let Some(f) = guard.as_mut()
        && f.read_exact(buf).is_ok()
    {
        return;
    }
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    for chunk in buf.chunks_mut(8) {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(chunk.as_ptr() as u64);
        let v = h.finish().to_le_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
}

pub fn u16() -> u16 {
    let mut b = [0u8; 2];
    fill(&mut b);
    u16::from_le_bytes(b)
}

pub fn u64() -> u64 {
    let mut b = [0u8; 8];
    fill(&mut b);
    u64::from_le_bytes(b)
}

/// Fisher-Yates shuffle.
pub fn shuffle<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let j = (u64() % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
}
