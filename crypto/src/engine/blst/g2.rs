use std::mem::MaybeUninit;

use blst::{blst_p1_affine, blst_p1, blst_p2_affine, blst_p2, blst_p2_uncompress, blst_p2_affine_compress, blst_p2_to_affine, blst_p2_mult, blst_p2_affine_in_g2, blst_p2s_to_affine, blst_p2_from_affine};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

use crate::{ParseError, G2};

use super::{BLSTAlgebra, scalar::ScalarBlst};

pub struct G2BlstAffine(MaybeUninit<blst_p2_affine>);
pub struct G2BlstProjective(MaybeUninit<blst_p2>);

impl TryFrom<G2> for G2BlstAffine {
    type Error = ParseError;

    fn try_from(g2: G2) -> Result<Self, Self::Error> {
        let mut p = std::mem::MaybeUninit::<blst_p2_affine>::zeroed();
        unsafe {
            blst_p2_uncompress(p.as_mut_ptr(), g2.0.as_ptr());
        }

        Ok(Self(p))
    }
}

impl TryFrom<G2BlstAffine> for G2 {
    type Error = ParseError;

    fn try_from(g2: G2BlstAffine) -> Result<Self, Self::Error> {
        let mut buffer = [0u8; 96];
        unsafe {
            blst_p2_affine_compress(buffer.as_mut_ptr(), g2.0.as_ptr());
        }
        Ok(Self(buffer))
    }
}

impl From<blst_p2_affine> for G2BlstAffine {
    fn from(u: blst_p2_affine) -> Self {
        let mut p = std::mem::MaybeUninit::<blst_p2_affine>::zeroed();
        p.write(u);
        Self(p)
    }
}

impl TryFrom<G2BlstAffine> for G2BlstProjective {
    type Error = ParseError;

    fn try_from(g2: G2BlstAffine) -> Result<Self, Self::Error> {
        let mut p = std::mem::MaybeUninit::<blst_p2>::zeroed();
        unsafe {
            blst_p2_from_affine(p.as_mut_ptr(), g2.0.as_ptr());
        }
        Ok(Self(p))
    }
}

impl TryFrom<G2BlstProjective> for G2BlstAffine {
    type Error = ParseError;

    fn try_from(g2: G2BlstProjective) -> Result<Self, Self::Error> {
        let mut p = std::mem::MaybeUninit::<blst_p2_affine>::zeroed();
        unsafe {
            blst_p2_to_affine(p.as_mut_ptr(), g2.0.as_ptr());
        }
        Ok(Self(p))
    }
}

impl BLSTAlgebra for G2BlstProjective {
    fn mul(&self, scalar: &ScalarBlst) -> Self {
        let mut out = MaybeUninit::<blst_p2>::zeroed();

        unsafe {
            blst_p2_mult(
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

impl BLSTAlgebra for G2BlstAffine {
    fn mul(&self, scalar: &ScalarBlst) -> Self {
        todo!()
    }

    fn is_in_subgroup(&self) -> bool {
        unsafe { blst_p2_affine_in_g2(self.0.as_ptr()) }
    }
}

pub fn batch_g2_projective_to_affine(ps: &Vec<G2BlstProjective>) -> Vec<G2BlstAffine> {
    let input = ps.iter().map(|x| x.0.as_ptr()).collect::<Vec<_>>();
    let mut out = Vec::<blst_p2_affine>::with_capacity(ps.len());

    unsafe {
        blst_p2s_to_affine(out.as_mut_ptr(), input.as_ptr(), ps.len());
        out.set_len(ps.len());
    }

    out.into_par_iter()
        .map(std::convert::Into::into)
        .collect::<Vec<G2BlstAffine>>()
}
