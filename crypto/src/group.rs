//! BLS12-381 group elements in ZCash encoding.

use crate::hex_format::{bytes_to_hex, hex_to_bytes};
use hex_literal::hex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

/// A scalar field element.
/// Encoding as little-endian 32-byte array.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Zeroize)]
pub struct F(pub [u8; 32]);

/// A G1 curve point.
/// Encoded in compressed ZCash format.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Zeroize)]
pub struct G1(pub [u8; 48]);

/// A G2 curve point.
/// Encoded in compressed ZCash format.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Zeroize)]
pub struct G2(pub [u8; 96]);

impl F {
    /// The zero element of the group.
    #[must_use]
    pub const fn zero() -> Self {
        Self(hex!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ))
    }

    /// The default generator for the group.
    #[must_use]
    pub const fn one() -> Self {
        Self(hex!(
            "0100000000000000000000000000000000000000000000000000000000000000"
        ))
    }
}

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

impl Serialize for F {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        bytes_to_hex::<_, 32, 66>(serializer, self.0)
    }
}

impl<'de> Deserialize<'de> for F {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        hex_to_bytes(deserializer).map(Self)
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

#[cfg(test)]
pub mod tests {
    use crate::{G1, G2};

    pub const fn invalid_g1() -> G1 {
        G1([0; 48])
    }

    pub const fn invalid_g2() -> G2 {
        G2([0; 96])
    }
}
