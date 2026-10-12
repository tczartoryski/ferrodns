//! DNS wire format (RFC 1035, RFC 3596, RFC 3597, RFC 6891), written from scratch.

mod message;
mod name;
mod record;

pub use message::{Edns, Header, Message, Question, opcode, rcode};
pub use name::Name;
pub use record::{RClass, RData, RType, Record, Soa};

use std::fmt;

/// Errors produced while decoding or encoding DNS messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The buffer ended before the structure was complete.
    Truncated,
    /// A label was empty, longer than 63 bytes, or used a reserved label type.
    BadLabel,
    /// A name exceeded 255 bytes on the wire.
    NameTooLong,
    /// A compression pointer pointed forward or the pointer chain was too long.
    BadPointer,
    /// RDATA did not match its declared length or type.
    BadRdata(&'static str),
    /// Bytes were left over after the declared sections.
    TrailingData,
    /// A text name could not be parsed.
    BadName(String),
    /// The message exceeds 65535 bytes.
    TooLarge,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => write!(f, "message truncated"),
            WireError::BadLabel => write!(f, "invalid label"),
            WireError::NameTooLong => write!(f, "name longer than 255 bytes"),
            WireError::BadPointer => write!(f, "invalid compression pointer"),
            WireError::BadRdata(why) => write!(f, "invalid rdata: {why}"),
            WireError::TrailingData => write!(f, "trailing data after message"),
            WireError::BadName(s) => write!(f, "invalid name: {s}"),
            WireError::TooLarge => write!(f, "message larger than 65535 bytes"),
        }
    }
}

impl std::error::Error for WireError {}

/// Bounds-checked big-endian reader helpers.
pub(crate) fn read_u8(buf: &[u8], pos: &mut usize) -> Result<u8, WireError> {
    let v = *buf.get(*pos).ok_or(WireError::Truncated)?;
    *pos += 1;
    Ok(v)
}

pub(crate) fn read_u16(buf: &[u8], pos: &mut usize) -> Result<u16, WireError> {
    let b = buf.get(*pos..*pos + 2).ok_or(WireError::Truncated)?;
    *pos += 2;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

pub(crate) fn read_u32(buf: &[u8], pos: &mut usize) -> Result<u32, WireError> {
    let b = buf.get(*pos..*pos + 4).ok_or(WireError::Truncated)?;
    *pos += 4;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

pub(crate) fn read_bytes<'a>(
    buf: &'a [u8],
    pos: &mut usize,
    n: usize,
) -> Result<&'a [u8], WireError> {
    let b = buf.get(*pos..*pos + n).ok_or(WireError::Truncated)?;
    *pos += n;
    Ok(b)
}
