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
    if M != 2 + 2 * N {
        return Err(serde::ser::Error::custom(InvalidLength(M)));
    }
    let mut hex = [0_u8; M];
    hex[0] = b'0';
    hex[1] = b'x';
    hex::encode_to_slice(bytes, &mut hex[2..]).expect("BUG: output buffer is of the correct size");
    let str = std::str::from_utf8(&hex).expect("BUG: hex is valid UTF-8");
    serializer.serialize_str(str)
}

/// Allocation free hex deserializer with `0x` prefix.
pub fn hex_to_bytes<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    deserializer.deserialize_str(StrVisitor::<N>)
}

pub fn optional_hex_to_bytes<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<Option<[u8; N]>, D::Error> {
    deserializer.deserialize_option(OptionalHexStrVisitor::<N>)
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

impl HexDecodingError {
    pub fn to_de_error<'de, E: de::Error>(self, visitor: impl de::Visitor<'de>) -> E {
        match self {
            InvalidLength(len) => E::invalid_length(len, &visitor),
            _ => E::custom(self),
        }
    }
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
        write!(formatter, "a {N} byte hex string stating with `0x`")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        hex_str_to_bytes(value).map_err(E::custom)
    }
}

pub struct OptionalHexStrVisitor<const N: usize>;

impl<'de, const N: usize> de::Visitor<'de> for OptionalHexStrVisitor<N> {
    type Value = Option<[u8; N]>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "a {N} byte hex string starting with `0x`, an empty string, or no value"
        )
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.is_empty() {
            Ok(None)
        } else {
            hex_str_to_bytes::<N>(v)
                .map_err(|e| e.to_de_error(self))
                .map(Some)
        }
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(self)
    }
}

#[cfg(test)]
mod tests {
    use crate::hex_format::{hex_to_bytes, optional_hex_to_bytes};
    use serde::Deserialize;

    #[derive(Eq, PartialEq, Debug)]
    struct OptionalBytes(Option<[u8; 2]>);

    #[derive(Deserialize, Eq, PartialEq, Debug)]
    struct ContainsOptionalBytes {
        option: OptionalBytes,
    }

    impl<'de> Deserialize<'de> for OptionalBytes {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            optional_hex_to_bytes::<_, 2>(deserializer).map(OptionalBytes)
        }
    }

    #[test]
    fn test_optional_hex_deserializer() {
        let from_empty_str = serde_json::from_str::<OptionalBytes>(r#""""#).unwrap();
        assert_eq!(from_empty_str, OptionalBytes(None));
        let from_null = serde_json::from_str::<OptionalBytes>("null").unwrap();
        assert_eq!(from_null, OptionalBytes(None));
        let from_missing_inner = serde_json::from_str::<ContainsOptionalBytes>(r#"{}"#).unwrap();
        assert_eq!(from_missing_inner, ContainsOptionalBytes {
            option: OptionalBytes(None),
        });
        let from_correct_input = serde_json::from_str::<OptionalBytes>(r#""0x1234""#).unwrap();
        assert_eq!(from_correct_input, OptionalBytes(Some([0x12, 0x34])));
        let from_wrong_length = serde_json::from_str::<OptionalBytes>(r#""0x123""#);
        assert!(from_wrong_length.is_err());
        let from_wrong_prefix = serde_json::from_str::<OptionalBytes>(r#""0X1234""#);
        assert!(from_wrong_prefix.is_err());
    }

    #[derive(Eq, PartialEq, Debug)]
    struct Bytes([u8; 2]);

    impl<'de> Deserialize<'de> for Bytes {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            hex_to_bytes::<_, 2>(deserializer).map(Bytes)
        }
    }

    #[test]
    fn test_hex_deserializer() {
        let from_empty_str = serde_json::from_str::<Bytes>(r#""""#);
        assert!(from_empty_str.is_err());
        let from_null = serde_json::from_str::<Bytes>("null");
        assert!(from_null.is_err());
        let from_correct_input = serde_json::from_str::<Bytes>(r#""0x1234""#).unwrap();
        assert_eq!(from_correct_input, Bytes([0x12, 0x34]));
        let from_wrong_length = serde_json::from_str::<Bytes>(r#""0x123""#);
        assert!(from_wrong_length.is_err());
        let from_wrong_prefix = serde_json::from_str::<Bytes>(r#""0X1234""#);
        assert!(from_wrong_prefix.is_err());
    }
}
