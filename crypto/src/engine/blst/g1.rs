use blst::{
    blst_p1, blst_p1_affine, blst_p1_affine_compress, blst_p1_affine_in_g1, blst_p1_from_affine,
    blst_p1_mult, blst_p1_uncompress, blst_p1s_to_affine, blst_scalar,
};

use crate::{ParseError, G1};

impl TryFrom<G1> for blst_p1_affine {
    type Error = ParseError;

    fn try_from(g1: G1) -> Result<Self, Self::Error> {
        unsafe {
            let mut p = Self::default();
            blst_p1_uncompress(&mut p, g1.0.as_ptr());
            Ok(p)
        }
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

pub fn p1_from_affine(a: &blst_p1_affine) -> blst_p1 {
    unsafe {
        let mut p = blst_p1::default();
        blst_p1_from_affine(&mut p, a);
        p
    }
}

pub fn p1_mult(p: &blst_p1, s: &blst_scalar) -> blst_p1 {
    unsafe {
        let mut out = blst_p1::default();
        blst_p1_mult(&mut out, p, s.b.as_ptr(), 256);
        out
    }
}

pub fn p1_affine_in_g1(p: &blst_p1_affine) -> bool {
    unsafe { blst_p1_affine_in_g1(p) }
}

pub fn p1s_to_affine(ps: &Vec<blst_p1>) -> Vec<blst_p1_affine> {
    let input = ps.iter().map(|x| x as *const blst_p1).collect::<Vec<_>>();
    let mut out = Vec::<blst_p1_affine>::with_capacity(ps.len());

    unsafe {
        blst_p1s_to_affine(out.as_mut_ptr(), input.as_ptr(), ps.len());
        out.set_len(ps.len());
    }

    out
}
