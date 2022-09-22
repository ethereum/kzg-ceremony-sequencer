use std::mem::MaybeUninit;

use blst::{
    blst_p1, blst_p1_affine, blst_p1_affine_compress, blst_p1_affine_in_g1, blst_p1_from_affine,
    blst_p1_mult, blst_p1_to_affine, blst_p1_uncompress, blst_p1s_to_affine,
};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

use crate::{ParseError, G1};

use super::{scalar::ScalarBlst, BLSTAlgebra};

pub struct G1BlstAffine(MaybeUninit<blst_p1_affine>);
pub struct G1BlstProjective(MaybeUninit<blst_p1>);

impl TryFrom<G1> for G1BlstAffine {
    type Error = ParseError;

    fn try_from(g1: G1) -> Result<Self, Self::Error> {
        let mut p = std::mem::MaybeUninit::<blst_p1_affine>::zeroed();
        unsafe {
            blst_p1_uncompress(p.as_mut_ptr(), g1.0.as_ptr());
        }

        Ok(Self(p))
    }
}

impl TryFrom<G1BlstAffine> for G1 {
    type Error = ParseError;

    fn try_from(g1: G1BlstAffine) -> Result<Self, Self::Error> {
        let mut buffer = [0u8; 48];
        unsafe {
            blst_p1_affine_compress(buffer.as_mut_ptr(), g1.0.as_ptr());
        }
        Ok(Self(buffer))
    }
}

impl From<blst_p1_affine> for G1BlstAffine {
    fn from(u: blst_p1_affine) -> Self {
        let mut p = std::mem::MaybeUninit::<blst_p1_affine>::zeroed();
        p.write(u);
        Self(p)
    }
}

impl TryFrom<G1BlstAffine> for G1BlstProjective {
    type Error = ParseError;

    fn try_from(g1: G1BlstAffine) -> Result<Self, Self::Error> {
        let mut p = std::mem::MaybeUninit::<blst_p1>::zeroed();
        unsafe {
            blst_p1_from_affine(p.as_mut_ptr(), g1.0.as_ptr());
        }
        Ok(Self(p))
    }
}

impl TryFrom<G1BlstProjective> for G1BlstAffine {
    type Error = ParseError;

    fn try_from(g1: G1BlstProjective) -> Result<Self, Self::Error> {
        let mut p = std::mem::MaybeUninit::<blst_p1_affine>::zeroed();
        unsafe {
            blst_p1_to_affine(p.as_mut_ptr(), g1.0.as_ptr());
        }
        Ok(Self(p))
    }
}

impl BLSTAlgebra for G1BlstProjective {
    fn mul(&self, scalar: &ScalarBlst) -> Self {
        let mut out = MaybeUninit::<blst_p1>::zeroed();

        unsafe {
            blst_p1_mult(
                out.as_mut_ptr(),
                self.0.as_ptr(),
                (*scalar.0.as_ptr()).b.as_ptr(),
                256,
            );
        }
        Self(out)
    }

    fn is_in_subgroup(&self) -> bool {
        todo!()
    }
}

impl BLSTAlgebra for G1BlstAffine {
    fn mul(&self, scalar: &ScalarBlst) -> Self {
        todo!()
    }

    fn is_in_subgroup(&self) -> bool {
        unsafe { blst_p1_affine_in_g1(self.0.as_ptr()) }
    }
}

pub fn batch_g1_projective_to_affine(ps: &Vec<G1BlstProjective>) -> Vec<G1BlstAffine> {
    let input = ps.iter().map(|x| x.0.as_ptr()).collect::<Vec<_>>();
    let mut out = Vec::<blst_p1_affine>::with_capacity(ps.len());

    unsafe {
        blst_p1s_to_affine(out.as_mut_ptr(), input.as_ptr(), ps.len());
        out.set_len(ps.len());
    }

    out.into_par_iter()
        .map(std::convert::Into::into)
        .collect::<Vec<G1BlstAffine>>()
}
