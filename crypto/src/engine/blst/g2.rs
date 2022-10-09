use std::mem::size_of;

use blst::{
    blst_fr, blst_p2, blst_p2_affine, blst_p2_affine_compress, blst_p2_affine_in_g2,
    blst_p2_from_affine, blst_p2_mult, blst_p2_to_affine, blst_p2_uncompress,
    blst_p2s_mult_pippenger, blst_p2s_mult_pippenger_scratch_sizeof, blst_p2s_to_affine,
    blst_scalar,
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
    let npoints = bases.len();
    let bases = bases
        .iter()
        .map(|x| x as *const blst_p2_affine)
        .collect::<Vec<_>>();
    let scalars = scalars
        .iter()
        .map(|x| scalar_from_fr(x).b.as_ptr())
        .collect::<Vec<_>>();
    let mut msm_result = blst_p2::default();
    let mut ret = blst_p2_affine::default();

    unsafe {
        let mut scratch =
            vec![0_u64; blst_p2s_mult_pippenger_scratch_sizeof(npoints) / size_of::<u64>()];
        blst_p2s_mult_pippenger(
            &mut msm_result,
            bases.as_ptr(),
            npoints,
            scalars.as_ptr(),
            256,
            scratch.as_mut_ptr(),
        );
        blst_p2_to_affine(&mut ret, &msm_result);
    }

    ret
}
