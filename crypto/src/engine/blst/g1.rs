use crate::{ParseError, G1};
use blst::{
    blst_p1, blst_p1_affine, blst_p1_affine_compress, blst_p1_affine_in_g1, blst_p1_from_affine,
    blst_p1_mult, blst_p1_to_affine, blst_p1_uncompress, blst_p1s_mult_pippenger,
    blst_p1s_mult_pippenger_scratch_sizeof, blst_p1s_to_affine, blst_scalar, limb_t, BLST_ERROR,
};
use std::{mem::size_of, ptr};

impl TryFrom<G1> for blst_p1_affine {
    type Error = ParseError;

    fn try_from(g1: G1) -> Result<Self, Self::Error> {
        let mut p = Self::default();
        let result = unsafe { blst_p1_uncompress(&mut p, g1.0.as_ptr()) };
        if result != BLST_ERROR::BLST_SUCCESS {
            return Err(ParseError::InvalidCompression);
        }
        Ok(p)
    }
}

impl TryFrom<blst_p1_affine> for G1 {
    type Error = ParseError;

    fn try_from(g1: blst_p1_affine) -> Result<Self, Self::Error> {
        unsafe {
            let mut buffer = [0u8; 48];
            blst_p1_affine_compress(buffer.as_mut_ptr(), &g1);
            Ok(Self(buffer))
        }
    }
}

impl TryFrom<blst_p1> for G1 {
    type Error = ParseError;

    fn try_from(g1: blst_p1) -> Result<Self, Self::Error> {
        Self::try_from(p1_to_affine(&g1))
    }
}

pub fn p1_from_affine(a: &blst_p1_affine) -> blst_p1 {
    unsafe {
        let mut p = blst_p1::default();
        blst_p1_from_affine(&mut p, a);
        p
    }
}

pub fn p1_to_affine(a: &blst_p1) -> blst_p1_affine {
    unsafe {
        let mut p = blst_p1_affine::default();
        blst_p1_to_affine(&mut p, a);
        p
    }
}

pub fn p1_mult(p: &blst_p1, s: &blst_scalar) -> blst_p1 {
    unsafe {
        let mut out = blst_p1::default();
        blst_p1_mult(&mut out, p, s.b.as_ptr(), 255);
        out
    }
}

pub fn p1_affine_in_g1(p: &blst_p1_affine) -> bool {
    unsafe { blst_p1_affine_in_g1(p) }
}

pub fn p1s_to_affine(ps: &[blst_p1]) -> Vec<blst_p1_affine> {
    let input = ps.iter().map(|x| x as *const blst_p1).collect::<Vec<_>>();
    let mut out = Vec::<blst_p1_affine>::with_capacity(ps.len());

    unsafe {
        blst_p1s_to_affine(out.as_mut_ptr(), input.as_ptr(), ps.len());
        out.set_len(ps.len());
    }

    out
}

pub fn p1s_mult_pippenger(bases: &[blst_p1_affine], scalars: &[blst_scalar]) -> blst_p1_affine {
    assert_eq!(bases.len(), scalars.len());
    if bases.is_empty() {
        // NOTE: Without this special case the `blst_p1s_mult_pippenger` will
        // SIGSEGV.
        return blst_p1_affine::default();
    }
    if bases.len() == 1 {
        // NOTE: Without this special case the `blst_p1s_mult_pippenger` will
        // SIGSEGV.
        let base = p1_from_affine(&bases[0]);
        let result = p1_mult(&base, &scalars[0]);
        return p1_to_affine(&result);
    }

    let npoints = bases.len();

    // Get vec of pointers to bases
    let points_ptrs = [bases.as_ptr(), ptr::null()];

    // Get vec of pointers to scalars
    assert_eq!(size_of::<blst_scalar>(), 32);
    let scalar_ptrs = [scalars.as_ptr(), ptr::null()];

    let scratch_size = unsafe { blst_p1s_mult_pippenger_scratch_sizeof(npoints) };
    let mut scratch = vec![limb_t::default(); scratch_size / size_of::<limb_t>()];
    let mut msm_result = blst_p1::default();
    let mut ret = blst_p1_affine::default();
    unsafe {
        blst_p1s_mult_pippenger(
            &mut msm_result,
            points_ptrs.as_ptr(),
            npoints,
            scalar_ptrs.as_ptr().cast(),
            256,
            scratch.as_mut_ptr(),
        );
        blst_p1_to_affine(&mut ret, &msm_result);
    }

    ret
}

#[cfg(test)]
mod tests {
    use super::{
        super::scalar::{fr_add, fr_from_scalar, fr_mul, fr_zero, scalar_from_fr},
        *,
    };
    use blst::blst_scalar_from_lendian;
    use proptest::{arbitrary::any, collection::vec as arb_vec, proptest, strategy::Strategy};
    use ruint::{aliases::U256, uint};

    pub fn arb_scalar() -> impl Strategy<Value = blst_scalar> {
        any::<U256>().prop_map(|mut n| {
            n %= uint!(52435875175126190479447740508185965837690552500527637822603658699938581184513_U256);
            let mut scalar = blst_scalar::default();
            unsafe {
                blst_scalar_from_lendian(&mut scalar, n.as_le_slice().as_ptr());
            }
            scalar
        })
    }

    #[test]
    fn test_p1s_mult_pippenger() {
        const SIZES: [usize; 7] = [0, 1, 2, 3, 4, 5, 100];
        for size in SIZES {
            proptest!(|(base in arb_vec(arb_scalar(), size), scalars in arb_vec(arb_scalar(), size))| {
                // Compute expected value
                let sum = base.iter().zip(scalars.iter()).fold(fr_zero(), |a, (l, r)| {
                    let product = fr_mul(&fr_from_scalar(l), &fr_from_scalar(r));
                    fr_add(&a, &product)
                });
                let sum = scalar_from_fr(&sum);
                let one = p1_from_affine(&blst_p1_affine::try_from(G1::one()).unwrap());
                let expected = p1_mult(&one, &sum);

                // Compute base points
                let base = base.iter().map(|s| {
                    p1_to_affine(&p1_mult(&one, s))
                }).collect::<Vec<_>>();

                // Compute dot product
                let result = p1s_mult_pippenger(base.as_slice(), scalars.as_slice());

                // Check result
                assert_eq!(p1_from_affine(&result), expected);
            });
        }
    }
}
