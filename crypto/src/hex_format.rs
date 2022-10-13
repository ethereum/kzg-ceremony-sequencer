use crate::hex_format::HexDecodingError::{
    DecoderError, InvalidCharacter, InvalidLength, MissingPrefix,
};
use hex::FromHexError;
use serde::{de, Deserializer, Serializer};
use std::fmt;

/// Allocation free hex serializer with `0x` prefix.
///
/// Constant generic `N` is the length of the byte array. The value
/// `M` must be set to `2 + 2 * N`.
pub fn bytes_to_hex<S: Serializer, const N: usize, const M: usize>(
    serializer: S,
    bytes: [u8; N],
) -> Result<S::Ok, S::Error> {
    assert_eq!(2 + 2 * N, M);
    if serializer.is_human_readable() {
        let mut hex = [0_u8; M];
        hex[0] = b'0';
        hex[1] = b'x';
        hex::encode_to_slice(bytes, &mut hex[2..])
            .expect("BUG: output buffer is of the correct size");
        let str = std::str::from_utf8(&hex).expect("BUG: hex is valid UTF-8");
        serializer.serialize_str(str)
    } else {
        serializer.serialize_bytes(&bytes)
    }
}

/// Allocation free hex deserializer with `0x` prefix.
pub fn hex_to_bytes<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    if deserializer.is_human_readable() {
        deserializer.deserialize_str(StrVisitor::<N>)
    } else {
        deserializer.deserialize_bytes(ByteVisitor::<N>)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HexDecodingError {
    #[error("input length must equal {0}")]
    InvalidLength(usize),
    #[error("hex string must start with `0x`")]
    MissingPrefix,
    #[error("hex string must contain only lower-case hex digits")]
    InvalidCharacter,
    #[error("hex decoding failed: {0}")]
    DecoderError(FromHexError),
}

pub fn hex_str_to_bytes<const N: usize>(value: &str) -> Result<[u8; N], HexDecodingError> {
    let mut result = [0_u8; N];
    if value.len() != 2 + 2 * N {
        return Err(InvalidLength(2 + 2 * N));
    }
    if &value[..2] != "0x" {
        return Err(MissingPrefix);
    }
    if !value[2..]
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(InvalidCharacter);
    }
    hex::decode_to_slice(&value[2..], &mut result).map_err(DecoderError)?;
    Ok(result)
}

/// Serde Visitor for human readable formats. Requires `0x` prefix, but is
/// otherwise case insensitive.
struct StrVisitor<const N: usize>;

impl<'de, const N: usize> de::Visitor<'de> for StrVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a {} byte hex string stating with `0x`", N)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        hex_str_to_bytes(value).map_err(E::custom)
    }
}

/// Serde Visitor for non-human readable formats
struct ByteVisitor<const N: usize>;

impl<'de, const N: usize> de::Visitor<'de> for ByteVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{N} bytes of binary data")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() != N {
            return Err(E::invalid_length(value.len(), &self));
        }
        let mut result = [0_u8; N];
        result.copy_from_slice(value);
        Ok(result)
    }
}
