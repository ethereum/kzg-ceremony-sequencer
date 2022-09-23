use std::mem::MaybeUninit;

use blst::{
    blst_p2, blst_p2_affine, blst_p2_affine_compress, blst_p2_affine_in_g2, blst_p2_from_affine,
    blst_p2_mult, blst_p2_uncompress, blst_p2s_to_affine, blst_scalar,
};

use crate::{ParseError, G2};

impl TryFrom<G2> for blst_p2_affine {
    type Error = ParseError;

    fn try_from(g2: G2) -> Result<Self, Self::Error> {
        unsafe {
            let mut p = std::mem::MaybeUninit::zeroed();
            blst_p2_uncompress(p.as_mut_ptr(), g2.0.as_ptr());
            Ok(p.as_ptr().read())
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

pub fn p2_from_affine(a: blst_p2_affine) -> blst_p2 {
    unsafe {
        let mut p = std::mem::MaybeUninit::zeroed();
        blst_p2_from_affine(p.as_mut_ptr(), &a);
        p.as_ptr().read()
    }
}

pub fn p2_mult(p: &blst_p2, s: &blst_scalar) -> blst_p2 {
    unsafe {
        let mut out = MaybeUninit::zeroed();
        blst_p2_mult(out.as_mut_ptr(), p, s.b.as_ptr(), 256);
        out.as_ptr().read()
    }
}

pub fn p2_affine_in_g2(p: &blst_p2_affine) -> bool {
    unsafe { blst_p2_affine_in_g2(p) }
}

pub fn p2s_to_affine(ps: &Vec<blst_p2>) -> Vec<blst_p2_affine> {
    let input = ps.iter().map(|x| x as *const blst_p2).collect::<Vec<_>>();
    let mut out = Vec::<blst_p2_affine>::with_capacity(ps.len());

    unsafe {
        blst_p2s_to_affine(out.as_mut_ptr(), input.as_ptr(), ps.len());
        out.set_len(ps.len());
    }

    out
}
