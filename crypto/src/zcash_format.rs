use std::ops::Neg;
use ark_bls12_381::Fq;
use ark_ec::{
    models::{ModelParameters, SWModelParameters},
    short_weierstrass_jacobian::GroupAffine,
};
use ark_ff::{
    fields::{Field, FpParameters, PrimeField},
    BigInteger, QuadExtField, QuadExtParameters, ToConstraintField, Zero,
};
use hex::FromHexError;
use thiserror::Error;

#[derive(Clone, Copy, PartialEq, Debug, Error)]
pub enum ParseError {
    #[error("Invalid length of hex string: expected {0} characters, got {1}")]
    InvalidLength(usize, usize),
    #[error("Invalid hex string: expected prefix \"0x\"")]
    MissingPrefix,
    #[error("Invalid hex string: {0}")]
    InvalidHex(#[from] FromHexError),
    #[error("Invalid x coordinate")]
    BigIntError,
    #[error("Point is not compressed")]
    NotCompressed,
    #[error("Point at infinity must have zero x coordinate")]
    InvalidInfinity,
    #[error("Error in extension field component {0}: Number is too large for the prime field")]
    InvalidPrimeField(usize),
    #[error("Error in extension field element")]
    InvalidExtensionField,
    #[error("not a valid x coordinate")]
    InvalidXCoordinate,
    #[error("curve point is not in prime order subgroup")]
    InvalidSubgroup,
}

pub trait ToBasePrimeFieldIterator
where
    Self: Field,
{
    fn base_field_iterator<'a>(
        &'a self,
    ) -> Box<dyn DoubleEndedIterator<Item = &Self::BasePrimeField> + 'a>;
}

impl ToBasePrimeFieldIterator for Fq {
    fn base_field_iterator<'a>(
        &'a self,
    ) -> Box<dyn DoubleEndedIterator<Item = &Self::BasePrimeField> + 'a> {
        Box::new(std::iter::once(self))
    }
}

impl<P: QuadExtParameters> ToBasePrimeFieldIterator for QuadExtField<P>
where
    P::BaseField: ToBasePrimeFieldIterator,
{
    fn base_field_iterator<'a>(
        &'a self,
    ) -> Box<dyn DoubleEndedIterator<Item = &Self::BasePrimeField> + 'a> {
        Box::new(
            self.c0
                .base_field_iterator()
                .chain(self.c1.base_field_iterator()),
        )
    }
}

pub fn parse_hex(hex: &str, out: &mut [u8]) -> Result<(), ParseError> {
    let expected_len = 2 + 2 * out.len();
    if hex.len() != expected_len {
        return Err(ParseError::InvalidLength(expected_len, hex.len()));
    }
    if &hex[0..2] != "0x" {
        return Err(ParseError::MissingPrefix);
    }
    hex::decode_to_slice(&hex[2..], out)?;
    Ok(())
}

/// Serialize a group element into ZCash format.
pub fn write_g<P: SWModelParameters>(point: &GroupAffine<P>) -> String
where
    <P as ModelParameters>::BaseField: ToBasePrimeFieldIterator,
{
    type FieldOf<P> = <P as ModelParameters>::BaseField;
    let ext_degree: usize = FieldOf::<P>::extension_degree().try_into().unwrap();
    let element_size = <<FieldOf<P> as Field>::BasePrimeField as PrimeField>::BigInt::NUM_LIMBS * 8;
    let mut buf = vec![0u8; element_size * ext_degree];
    buf.chunks_exact_mut(element_size)
        .zip(point.x.base_field_iterator().rev())
        .for_each(|(chunk, element)| {
            let repr = element.into_repr();
            let mut writer = &mut chunk[..];
            repr.write_le(&mut writer).unwrap();
            chunk.reverse();
        });
    buf[0] |= 0x80; // compressed
    if point.infinity {
        buf[0] |= 0x40;
    } else if point.y > -point.y {
        buf[0] |= 0x20;
    }
    format!("0x{}", hex::encode(buf))
}

/// Deserialize a ZCash spec encoded group element.
///
/// See <https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#serialization>
pub fn parse_g<P: SWModelParameters>(hex: &str) -> Result<GroupAffine<P>, ParseError> {
    // Create some type aliases for the base extension, field and int types.
    type Extension<P> = <P as ModelParameters>::BaseField;
    type Prime<P> = <Extension<P> as Field>::BasePrimeField;
    type Int<P> = <Prime<P> as PrimeField>::BigInt;
    let modulus = <Prime<P> as PrimeField>::Params::MODULUS;

    // Compute sizes
    let extension: usize = Extension::<P>::extension_degree()
        .try_into()
        .expect("Extension degree should fit usize.");
    let element_size = Int::<P>::NUM_LIMBS * 8;
    let size = extension * element_size;
    let padding_bits = element_size * 8 - modulus.num_bits() as usize;
    assert!(
        padding_bits >= 3,
        "ZCash encoding spec requires three prefix bits, but there is not enough padding."
    );

    // Read hex string
    let mut bytes = vec![0u8; size];
    parse_hex(hex, &mut bytes)?;

    // Read and mask flags
    let compressed = bytes[0] & 0x80 != 0;
    let infinity = bytes[0] & 0x40 != 0;
    let greatest = bytes[0] & 0x20 != 0;
    bytes[0] &= 0x1f;

    // Read x coordinate
    let mut elements = bytes[..]
        .chunks_exact_mut(element_size)
        .enumerate()
        .map(|(i, chunk)| {
            chunk.reverse();
            let mut reader = &chunk[..];
            let mut x = Int::<P>::default();
            x.read_le(&mut reader)
                .map_err(|_| ParseError::BigIntError)?;
            if reader.len() != 0 {
                return Err(ParseError::BigIntError);
            }
            if x >= modulus {
                return Err(ParseError::InvalidPrimeField(i));
            }
            let x = Prime::<P>::from_repr(x).ok_or(ParseError::InvalidPrimeField(i))?;
            Ok(x)
        })
        .collect::<Result<Vec<_>, _>>()?;
    elements.reverse();
    let x = Extension::<P>::from_base_prime_field_elems(&elements)
        .ok_or(ParseError::InvalidExtensionField)?;

    // Construct point
    if !compressed {
        return Err(ParseError::NotCompressed);
    }
    if infinity {
        if greatest || x != Extension::<P>::zero() {
            return Err(ParseError::InvalidInfinity);
        }
        return Ok(GroupAffine::<P>::zero());
    }
    let point =
        GroupAffine::<P>::get_point_from_x(x, greatest).ok_or(ParseError::InvalidXCoordinate)?;
    debug_assert!(point.is_on_curve()); // Always true
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ParseError::InvalidSubgroup);
    }

    Ok(point)
}

#[cfg(test)]
pub mod test {
    use super::*;
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_ec::AffineCurve;

    #[test]
    fn test_parse_g1() {
        assert_eq!(parse_g("0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap(), G1Affine::zero());
        assert_eq!(parse_g("0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb").unwrap(), G1Affine::prime_subgroup_generator());
    }

    #[test]
    fn test_parse_g2() {
        assert_eq!(parse_g("0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap(), G2Affine::zero());
        assert_eq!(parse_g("0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8").unwrap(), G2Affine::prime_subgroup_generator());
    }

    #[test]
    fn test_write_g1() {
        assert_eq!(write_g(&G1Affine::zero()), "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(write_g(&G1Affine::prime_subgroup_generator()), "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");
    }

    #[test]
    fn test_write_g2() {
        assert_eq!(write_g(&G2Affine::zero()), "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(write_g(&G2Affine::prime_subgroup_generator()), "0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8");
    }
}

#[cfg(feature = "bench")]
#[doc(hidden)]
pub mod bench {
    use super::*;
    use ark_bls12_381::{g1, g2};
    use criterion::{black_box, Criterion};

    pub fn group(criterion: &mut Criterion) {
        bench_parse_g1(criterion);
        bench_parse_g2(criterion);
    }

    fn bench_parse_g1(criterion: &mut Criterion) {
        let input = "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
        criterion.bench_function("parse_g1", move |bencher| {
            bencher.iter(|| black_box(parse_g::<g1::Parameters>(black_box(input))))
        });
    }

    fn bench_parse_g2(criterion: &mut Criterion) {
        let input = "0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
        criterion.bench_function("parse_g2", move |bencher| {
            bencher.iter(|| black_box(parse_g::<g2::Parameters>(black_box(input))))
        });
    }
}
