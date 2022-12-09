use crate::{engine::arkworks::ext_field::ToBasePrimeFieldIterator, ParseError, G1, G2};
use ark_bls12_381::{G1Affine, G2Affine};
use ark_ec::{
    models::{ModelParameters, SWModelParameters},
    short_weierstrass_jacobian::GroupAffine,
};
use ark_ff::{
    fields::{Field, FpParameters, PrimeField},
    BigInteger, Zero,
};

impl TryFrom<G1> for G1Affine {
    type Error = ParseError;

    fn try_from(g1: G1) -> Result<Self, Self::Error> {
        let p = parse_g(g1.0)?;
        // We don't do the subgroup check here because it is expensive.
        // if !g1_subgroup_check(&p) {
        //     return Err(ParseError::InvalidSubgroup);
        // }
        Ok(p)
    }
}

impl TryFrom<G2> for G2Affine {
    type Error = ParseError;

    fn try_from(g2: G2) -> Result<Self, Self::Error> {
        let p = parse_g(g2.0)?;
        // We don't do the subgroup check here because it is expensive.
        // if !g2_subgroup_check(&p) {
        //     return Err(ParseError::InvalidSubgroup);
        // }
        Ok(p)
    }
}

impl From<G1Affine> for G1 {
    fn from(g1: G1Affine) -> Self {
        Self(write_g(&g1))
    }
}

impl From<G2Affine> for G2 {
    fn from(g2: G2Affine) -> Self {
        Self(write_g(&g2))
    }
}

/// Serialize a group element into ZCash format.
pub fn write_g<P: SWModelParameters, const N: usize>(point: &GroupAffine<P>) -> [u8; N]
where
    <P as ModelParameters>::BaseField: ToBasePrimeFieldIterator,
{
    type FieldOf<P> = <P as ModelParameters>::BaseField;
    let ext_degree: usize = FieldOf::<P>::extension_degree().try_into().unwrap();
    let element_size = <<FieldOf<P> as Field>::BasePrimeField as PrimeField>::BigInt::NUM_LIMBS * 8;
    assert_eq!(N, element_size * ext_degree);
    let mut buf = [0u8; N];

    if point.infinity {
        buf[0] |= 0x80 | 0x40; // compressed & infinity
        return buf;
    }

    buf.chunks_exact_mut(element_size)
        .zip(point.x.base_field_iterator().rev())
        .for_each(|(chunk, element)| {
            let repr = element.into_repr();
            let mut writer = &mut chunk[..];
            repr.write_le(&mut writer).unwrap();
            chunk.reverse();
        });
    buf[0] |= 0x80; // compressed
    if point.y > -point.y {
        buf[0] |= 0x20;
    }
    buf
}

/// Deserialize a ZCash spec encoded group element.
///
/// See <https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#serialization>
///
/// # Errors
///
/// Returns a [`ParseError`] if the input is not a valid ZCash encoding. See
/// [`ParseError`] for details.
///
/// # Panics
///
/// Panics if the extension degree exceeds `usize::MAX`.
pub fn parse_g<P: SWModelParameters, const N: usize>(
    bytes: [u8; N],
) -> Result<GroupAffine<P>, ParseError> {
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
    assert_eq!(size, N, "Invalid input length");
    assert!(
        padding_bits >= 3,
        "ZCash encoding spec requires three prefix bits, but there is not enough padding."
    );

    // Read and mask flags
    let mut bytes = bytes;
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
            #[allow(clippy::redundant_slicing)]
            let mut reader = &chunk[..];
            let mut x = Int::<P>::default();
            x.read_le(&mut reader)
                .map_err(|_| ParseError::BigIntError)?;
            if !reader.is_empty() {
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

    // Subgroup check is expensive and therefore not done as part of parsing.
    // TODO: A safer API to indicate whether the check is required.
    // if !point.is_in_correct_subgroup_assuming_on_curve() {
    //     return Err(ParseError::InvalidSubgroup);
    // }

    Ok(point)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::arkworks::test::{arb_g1, arb_g2};
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_ec::AffineCurve;
    use hex_literal::hex;
    use proptest::proptest;

    #[test]
    fn test_parse_g1() {
        assert_eq!(parse_g(hex!("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")).unwrap(), G1Affine::zero());
        assert_eq!(parse_g(hex!("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb")).unwrap(), G1Affine::prime_subgroup_generator());
    }

    #[test]
    fn test_parse_g2() {
        assert_eq!(parse_g(hex!("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")).unwrap(), G2Affine::zero());
        assert_eq!(parse_g(hex!("93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8")).unwrap(), G2Affine::prime_subgroup_generator());
    }

    #[test]
    fn test_write_g1() {
        assert_eq!(write_g(&G1Affine::zero()), hex!("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
        assert_eq!(write_g(&G1Affine::prime_subgroup_generator()), hex!("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"));
    }

    #[test]
    fn test_write_g2() {
        assert_eq!(write_g(&G2Affine::zero()), hex!("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
        assert_eq!(write_g(&G2Affine::prime_subgroup_generator()), hex!("93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"));
    }

    #[test]
    fn test_parse_after_write_g1() {
        proptest!(|(g in arb_g1())| {
            assert_eq!(g, parse_g(write_g::<_, 48>(&g)).expect("must be able to parse"));
        });
    }

    #[test]
    fn test_parse_after_write_g2() {
        proptest!(|(g in arb_g2())| {
            assert_eq!(g, parse_g(write_g::<_, 96>(&g)).expect("must be able to parse"));
        });
    }
}

#[cfg(feature = "bench")]
#[cfg(not(tarpaulin_include))]
#[doc(hidden)]
pub mod bench {
    use super::*;
    use ark_bls12_381::{g1, g2};
    use criterion::{black_box, Criterion};
    use hex_literal::hex;

    pub fn group(criterion: &mut Criterion) {
        bench_parse_g1(criterion);
        bench_parse_g2(criterion);
    }

    fn bench_parse_g1(criterion: &mut Criterion) {
        let input = hex!("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");
        criterion.bench_function("parse_g1", move |bencher| {
            bencher.iter(|| black_box(parse_g::<g1::Parameters, 48>(black_box(input))));
        });
    }

    fn bench_parse_g2(criterion: &mut Criterion) {
        let input = hex!("93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8");
        criterion.bench_function("parse_g2", move |bencher| {
            bencher.iter(|| black_box(parse_g::<g2::Parameters, 96>(black_box(input))));
        });
    }
}
