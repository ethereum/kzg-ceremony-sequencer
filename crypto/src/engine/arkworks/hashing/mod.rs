// TODO License

use crate::engine::arkworks::ext_field::ToBasePrimeFieldIterator;
use ark_bls12_381::{g1::Parameters as G1Parameters, Fq, Fr, G1Affine};
use ark_ec::{short_weierstrass_jacobian::GroupAffine, AffineCurve, SWModelParameters};
use ark_ff::{field_new, BigInteger, Field, FpParameters, One, PrimeField, SquareRootField, Zero};
use digest::DynDigest;
use sha2::Sha256;
use std::{marker::PhantomData, ptr::hash};

const LONG_DST_PREFIX: &[u8] = b"H2C-OVERSIZE-DST-";

mod hash_to_field;
mod hash_to_curve;
mod xmd_expander;

fn construct_dst_prime<H: DynDigest + Default>(dst: &[u8]) -> Vec<u8> {
    let mut dst_prime = if dst.len() > 255 {
        let mut hasher = H::default();
        hasher.update(LONG_DST_PREFIX);
        hasher.update(dst);
        hasher.finalize_reset().to_vec()
    } else {
        dst.to_vec()
    };
    dst_prime.push(dst.len() as u8);
    dst_prime
}

fn expand_xmd<H: Default + DynDigest + Clone>(
    msg: &[u8],
    dst: &[u8],
    n: usize,
    block_size: usize,
) -> Vec<u8> {
    let mut hasher = H::default();
    let b_len = hasher.output_size();
    let ell = (n + b_len - 1) / b_len;
    assert!(
        ell <= 255,
        "The ratio of desired output to the output size of hash function is too large!"
    );
    let dst_prime = construct_dst_prime::<H>(dst);
    let z_pad: Vec<u8> = vec![0; block_size];
    assert!(n < (1 << 16), "Length should be smaller than 2^16");
    let lib_str: [u8; 2] = (n as u16).to_be_bytes();
    hasher.update(&z_pad);
    hasher.update(msg);
    hasher.update(&lib_str);
    hasher.update(&[0u8]);
    hasher.update(&dst_prime);
    let b0 = hasher.finalize_reset();

    hasher.update(&b0);
    hasher.update(&[1u8]);
    hasher.update(&dst_prime);
    let mut bi = hasher.finalize_reset();

    let mut uniform_bytes: Vec<u8> = Vec::with_capacity(n);
    uniform_bytes.extend_from_slice(&bi);
    for i in 2..=ell {
        // update the hasher with xor of b_0 and b_i elements
        for (l, r) in b0.iter().zip(bi.iter()) {
            hasher.update(&[*l ^ *r]);
        }
        hasher.update(&[i as u8]);
        hasher.update(&dst_prime);
        bi = hasher.finalize_reset();
        uniform_bytes.extend_from_slice(&bi);
    }
    uniform_bytes[0..n].to_vec()
}

fn get_len_per_elem<F: Field, const SEC_PARAM: usize>() -> usize {
    let base_field_size_in_bits =
        <<F::BasePrimeField as PrimeField>::Params as FpParameters>::MODULUS_BITS as usize;
    let base_field_size_with_security_padding_in_bits = base_field_size_in_bits + SEC_PARAM;
    let bytes_per_base_field_elem =
        ((base_field_size_with_security_padding_in_bits + 7) / 8) as u64;
    bytes_per_base_field_elem as usize
}

//= 128, Fr
fn hash_to_field<F: Field, H: Default + DynDigest + Clone, const SEC_PARAM: usize>(
    message: &[u8],
    dst: &[u8],
    count: usize,
) -> Vec<F> {
    let m = Fr::extension_degree() as usize;
    let len_per_base_elem = get_len_per_elem::<F, SEC_PARAM>();
    let len_in_bytes = count * m * len_per_base_elem;
    let uniform_bytes = expand_xmd::<H>(message, dst, len_in_bytes, len_per_base_elem);

    let mut output = Vec::with_capacity(count);
    let mut base_prime_field_elems = Vec::with_capacity(m);
    for i in 0..count {
        base_prime_field_elems.clear();
        for j in 0..m {
            let elm_offset = len_per_base_elem * (j + i * m);
            let val = F::BasePrimeField::from_be_bytes_mod_order(
                &uniform_bytes[elm_offset..][..len_per_base_elem],
            );
            base_prime_field_elems.push(val);
        }
        let f = F::from_base_prime_field_elems(&base_prime_field_elems).unwrap();
        output.push(f);
    }
    output
}

pub fn parity<F: ToBasePrimeFieldIterator>(element: &F) -> bool {
    element
        .base_field_iterator()
        .find(|x| !x.is_zero())
        .map_or(false, |x| x.into_repr().is_odd())
}

/// Trait defining the necessary parameters for the SWU hash-to-curve method
/// for the curves of Weierstrass form of:
/// y^2 = x^3 + a*x + b where ab != 0. From [\[WB2019\]]
///
/// - [\[WB2019\]] <https://eprint.iacr.org/2019/403>
pub trait SWUParams: SWModelParameters {
    /// An element of the base field that is not a square root see \[WB2019,
    /// Section 4\]. It is also convenient to have $g(b/ZETA * a)$ to be
    /// square. In general we use a `ZETA` with low absolute value
    /// coefficients when they are represented as integers.
    const ZETA: Self::BaseField;
}

impl SWUParams for G1Parameters {
    const ZETA: Self::BaseField = field_new!(Fq, "11");
}

#[derive(Clone, Debug)]
pub enum HashToCurveError {
    /// Curve choice is unsupported by the given HashToCurve method.
    UnsupportedCurveError(String),

    /// Error with map to curve
    MapToCurveError(String),
}

pub struct SWUMap<P: SWUParams> {
    _params: PhantomData<fn() -> P>,
}

impl<P: SWUParams> SWUMap<P>
where
    P::BaseField: ToBasePrimeFieldIterator,
{
    fn new() -> Result<Self, HashToCurveError> {
        // Verifying that ZETA is a non-square
        if P::ZETA.legendre().is_qr() {
            return Err(HashToCurveError::MapToCurveError(
                "ZETA should be a quadratic non-residue for the SWU map".to_string(),
            ));
        }

        // Verifying the prerequisite for applicability  of SWU map
        if P::COEFF_A.is_zero() || P::COEFF_B.is_zero() {
            return Err(HashToCurveError::MapToCurveError(
                "Simplified SWU requires a * b != 0 in the short Weierstrass form of y^2 = x^3 + \
                 a*x + b "
                    .to_string(),
            ));
        }

        Ok(Self {
            _params: PhantomData,
        })
    }

    /// Map an arbitrary base field element to a curve point.
    /// Based on
    /// <https://github.com/zcash/pasta_curves/blob/main/src/hashtocurve.rs>.
    fn map_to_curve(&self, point: P::BaseField) -> Result<GroupAffine<P>, HashToCurveError> {
        // 1. tv1 = inv0(Z^2 * u^4 + Z * u^2)
        // 2. x1 = (-B / A) * (1 + tv1)
        // 3. If tv1 == 0, set x1 = B / (Z * A)
        // 4. gx1 = x1^3 + A * x1 + B
        //
        // We use the "Avoiding inversions" optimization in [WB2019, section 4.2]
        // (not to be confused with section 4.3):
        //
        //   here       [WB2019]
        //   -------    ---------------------------------
        //   Z          ξ
        //   u          t
        //   Z * u^2    ξ * t^2 (called u, confusingly)
        //   x1         X_0(t)
        //   x2         X_1(t)
        //   gx1        g(X_0(t))
        //   gx2        g(X_1(t))
        //
        // Using the "here" names:
        //    x1 = num_x1/div      = [B*(Z^2 * u^4 + Z * u^2 + 1)] / [-A*(Z^2 * u^4 + Z
        // * u^2]   gx1 = num_gx1/div_gx1 = [num_x1^3 + A * num_x1 * div^2 + B *
        // div^3] / div^3
        let a = P::COEFF_A;
        let b = P::COEFF_B;

        let zeta_u2 = P::ZETA * point.square();
        let ta = zeta_u2.square() + zeta_u2;
        let num_x1 = b * (ta + <P::BaseField as One>::one());
        let div = a * if ta.is_zero() { P::ZETA } else { -ta };

        let num2_x1 = num_x1.square();
        let div2 = div.square();
        let div3 = div2 * div;
        let num_gx1 = (num2_x1 + a * div2) * num_x1 + b * div3;

        // 5. x2 = Z * u^2 * x1
        let num_x2 = zeta_u2 * num_x1; // same div

        // 6. gx2 = x2^3 + A * x2 + B  [optimized out; see below]
        // 7. If is_square(gx1), set x = x1 and y = sqrt(gx1)
        // 8. Else set x = x2 and y = sqrt(gx2)
        let gx1_square;
        let gx1;

        assert!(
            !div3.is_zero(),
            "we have checked that neither a or ZETA are zero. Q.E.D."
        );
        let y1: P::BaseField = {
            gx1 = num_gx1 / div3;
            if gx1.legendre().is_qr() {
                gx1_square = true;
                gx1.sqrt()
                    .expect("We have checked that gx1 is a quadratic residue. Q.E.D")
            } else {
                let zeta_gx1 = P::ZETA * gx1;
                gx1_square = false;
                zeta_gx1.sqrt().expect(
                    "ZETA * gx1 is a quadratic residue because legard is multiplicative. Q.E.D",
                )
            }
        };

        // This magic also comes from a generalization of [WB2019, section 4.2].
        //
        // The Sarkar square root algorithm with input s gives us a square root of
        // h * s for free when s is not square, where h is a fixed nonsquare.
        // In our implementation, h = ROOT_OF_UNITY.
        // We know that Z / h is a square since both Z and h are
        // nonsquares. Precompute theta as a square root of Z / ROOT_OF_UNITY.
        //
        // We have gx2 = g(Z * u^2 * x1) = Z^3 * u^6 * gx1
        //                               = (Z * u^3)^2 * (Z/h * h * gx1)
        //                               = (Z * theta * u^3)^2 * (h * gx1)
        //
        // When gx1 is not square, y1 is a square root of h * gx1, and so Z * theta *
        // u^3 * y1 is a square root of gx2. Note that we don't actually need to
        // compute gx2.

        let y2 = zeta_u2 * point * y1;
        let num_x = if gx1_square { num_x1 } else { num_x2 };
        let y = if gx1_square { y1 } else { y2 };

        let x_affine = num_x / div;
        let y_affine = if parity(&y) != parity(&point) { -y } else { y };
        let point_on_curve = GroupAffine::<P>::new(x_affine, y_affine, false);
        assert!(
            point_on_curve.is_on_curve(),
            "swu mapped to a point off the curve"
        );
        Ok(point_on_curve)
    }
}

fn hash_to_curve(dst: &[u8], msg: &[u8]) -> Result<G1Affine, HashToCurveError> {
    // IETF spec of hash_to_curve, from hash_to_field and map_to_curve
    // sub-components
    // 1. u = hash_to_field(msg, 2)
    // 2. Q0 = map_to_curve(u[0])
    // 3. Q1 = map_to_curve(u[1])
    // 4. R = Q0 + Q1              # Point addition
    // 5. P = clear_cofactor(R)
    // 6. return P

    let rand_field_elems = hash_to_field::<Fq, Sha256, 128>(msg, dst, 2);

    let curve_mapper = SWUMap::<G1Parameters>::new()?;

    let rand_curve_elem_0 = curve_mapper.map_to_curve(rand_field_elems[0])?;
    let rand_curve_elem_1 = curve_mapper.map_to_curve(rand_field_elems[1])?;

    let rand_curve_elem = rand_curve_elem_0 + rand_curve_elem_1;
    let rand_subgroup_elem = rand_curve_elem.mul_by_cofactor();

    Ok(rand_subgroup_elem)
}

#[cfg(all(test, feature = "arkworks", feature = "blst"))]
mod tests {
    use crate::{
        engine::arkworks::hashing::{
            hash_to_field::{DefaultFieldHasher, HashToField},
            hash_to_curve::{MapToCurveBasedHasher, WBMap, HashToCurve},
        },
        F, G1,
    };
    use ark_bls12_381::{g1::Parameters as G1Parameters, Fq, Fr, G1Affine};
    use ark_ff::{BigInteger, PrimeField};
    use blst::{blst_hash_to_g1, blst_p1, blst_scalar};
    use sha2::Sha256;

    #[test]
    fn testX() {
        let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
        let m = 1;
        let hasher = <DefaultFieldHasher<Sha256, 128> as HashToField<Fq>>::new(dst);
        let got: Vec<Fq> = hasher.hash_to_field(b"hello world", 2 * m);
        println!("got: {:?}", got);

    }

    #[test]
    fn test() {
        let suite = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
        let m = 1;
        let g1_mapper = MapToCurveBasedHasher::<
            G1Parameters,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<G1Parameters>,
        >::new(suite)
        .unwrap();

        let msg = b"hello world";
        let g1 = g1_mapper.hash(msg).unwrap();
        println!("g1: {:?}", g1);
        let enc1 = G1::from(g1);

        println!("{:?}" , enc1);

        let g2 = unsafe {
            let mut out = blst_p1::default();
            blst_hash_to_g1(&mut out, msg.as_ptr(), msg.len(), suite.as_ptr(), suite.len(), [0 as u8;0].as_ptr(), 0);
            out
        };
        let enc2 = G1::try_from(g2).unwrap();

        println!("{:?}" , enc2);

    }
}
