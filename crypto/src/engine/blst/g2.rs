use std::mem::size_of;

use blst::{
    blst_fr, blst_p2, blst_p2_affine, blst_p2_affine_compress, blst_p2_affine_in_g2,
    blst_p2_from_affine, blst_p2_mult, blst_p2_to_affine, blst_p2_uncompress,
    blst_p2s_mult_pippenger, blst_p2s_mult_pippenger_scratch_sizeof, blst_p2s_to_affine,
    blst_scalar, limb_t,
};

use crate::{ParseError, G2};

use super::scalar::scalar_from_fr;

impl TryFrom<G2> for blst_p2_affine {
    type Error = ParseError;

    fn try_from(g2: G2) -> Result<Self, Self::Error> {
        unsafe {
            let mut p = Self::default();
            blst_p2_uncompress(&mut p, g2.0.as_ptr());
            Ok(p)
        }
    }
}

impl TryFrom<blst_p2_affine> for G2 {
    type Error = ParseError;

    fn try_from(g2: blst_p2_affine) -> Result<Self, Self::Error> {
        unsafe {
            let mut buffer = [0u8; 96];
            blst_p2_affine_compress(buffer.as_mut_ptr(), &g2);
            Ok(Self(buffer))
        }
    }
}
pub fn p2_from_affine(a: &blst_p2_affine) -> blst_p2 {
    unsafe {
        let mut p = blst_p2::default();
        blst_p2_from_affine(&mut p, a);
        p
    }
}

pub fn p2_to_affine(a: &blst_p2) -> blst_p2_affine {
    unsafe {
        let mut p = blst_p2_affine::default();
        blst_p2_to_affine(&mut p, a);
        p
    }
}

pub fn p2_mult(p: &blst_p2, s: &blst_scalar) -> blst_p2 {
    unsafe {
        let mut out = blst_p2::default();
        blst_p2_mult(&mut out, p, s.b.as_ptr(), 256);
        out
    }
}

pub fn p2_affine_in_g2(p: &blst_p2_affine) -> bool {
    unsafe { blst_p2_affine_in_g2(p) }
}

pub fn p2s_to_affine(ps: &[blst_p2]) -> Vec<blst_p2_affine> {
    let input = ps.iter().map(|x| x as *const blst_p2).collect::<Vec<_>>();
    let mut out = Vec::<blst_p2_affine>::with_capacity(ps.len());

    unsafe {
        blst_p2s_to_affine(out.as_mut_ptr(), input.as_ptr(), ps.len());
        out.set_len(ps.len());
    }

    out
}

pub fn p2s_mult_pippenger(bases: &[blst_p2_affine], scalars: &[blst_fr]) -> blst_p2_affine {
    assert_eq!(bases.len(), scalars.len());
    if bases.is_empty() {
        // NOTE: Without this special case the `blst_p1s_mult_pippenger` will
        // SIGSEGV.
        return blst_p2_affine::default();
    }
    if bases.len() == 1 {
        // NOTE: Without this special case the `blst_p1s_mult_pippenger` will
        // SIGSEGV.
        let base = p2_from_affine(&bases[0]);
        let scalar = scalar_from_fr(&scalars[0]);
        let result = p2_mult(&base, &scalar);
        return p2_to_affine(&result);
    }

    let npoints = bases.len();

    // Get vec of pointers to bases
    let bases = bases
        .iter()
        .map(|x| x as *const blst_p2_affine)
        .collect::<Vec<_>>();

    // Convert scalars to blst_scalar
    let scalars = scalars.iter().map(scalar_from_fr).collect::<Vec<_>>();

    // Get vec of pointers to scalars
    let scalar_ptrs = scalars.iter().map(|x| x.b.as_ptr()).collect::<Vec<_>>();

    let mut msm_result = blst_p2::default();
    let mut ret = blst_p2_affine::default();

    unsafe {
        let mut scratch = vec![
            limb_t::default();
            blst_p2s_mult_pippenger_scratch_sizeof(npoints) / size_of::<limb_t>()
        ];
        blst_p2s_mult_pippenger(
            &mut msm_result,
            bases.as_ptr(),
            npoints,
            scalar_ptrs.as_ptr(),
            256,
            scratch.as_mut_ptr(),
        );
        blst_p2_to_affine(&mut ret, &msm_result);
    }

    ret
}
