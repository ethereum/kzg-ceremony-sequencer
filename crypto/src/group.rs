//! BLS12-381 group elements in ZCash encoding.

use hex_literal::hex;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct G1(pub [u8; 48]);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct G2(pub [u8; 96]);

impl G1 {
    /// The zero element of the group.
    #[must_use]
    pub const fn zero() -> Self {
        Self(hex!("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))
    }

    /// The default generator for the group.
    #[must_use]
    pub const fn one() -> Self {
        Self(hex!("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"))
    }
}

impl G2 {
    /// The zero element of the group.
    #[must_use]
    pub const fn zero() -> Self {
        Self(hex!("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))
    }

    /// The default generator for the group.
    #[must_use]
    pub const fn one() -> Self {
        Self(hex!("93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"))
    }
}

impl Serialize for G1 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        bytes_to_hex::<_, 48, 98>(serializer, self.0)
    }
}

impl<'de> Deserialize<'de> for G1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        hex_to_bytes(deserializer).map(Self)
    }
}

impl Serialize for G2 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        bytes_to_hex::<_, 96, 194>(serializer, self.0)
    }
}

impl<'de> Deserialize<'de> for G2 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        hex_to_bytes(deserializer).map(Self)
    }
}

/// Allocation free hex serializer with `0x` prefix.
///
/// Constant generic `N` is the length of the byte array. The value
/// `M` must be set to `2 + 2 * N`.
fn bytes_to_hex<S: Serializer, const N: usize, const M: usize>(
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
fn hex_to_bytes<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    if deserializer.is_human_readable() {
        deserializer.deserialize_str(StrVisitor::<N>)
    } else {
        deserializer.deserialize_bytes(ByteVisitor::<N>)
    }
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
        let mut result = [0_u8; N];
        if value.len() != 2 + 2 * N {
            return Err(E::invalid_length(value.len(), &self));
        }
        if &value[..2] != "0x" {
            return Err(E::custom("hex string must start with `0x`"));
        }
        if !value[2..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(E::custom(
                "hex string must contain only lower-case hex digits",
            ));
        }
        hex::decode_to_slice(&value[2..], &mut result)
            .map_err(|e| E::custom(format!("hex decoding failed: {}", e)))?;
        Ok(result)
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
