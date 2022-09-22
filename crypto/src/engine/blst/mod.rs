mod g1;
mod g2;
mod scalar;

use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};
use std::iter;

use crate::{CeremonyError, Engine, ParseError, G1, G2};

use self::{
    g1::{batch_g1_projective_to_affine, G1BlstAffine, G1BlstProjective},
    g2::{batch_g2_projective_to_affine, G2BlstAffine, G2BlstProjective},
    scalar::{random_scalar, scalar_mul, ScalarBlst},
};

pub struct BLST;

pub trait BLSTAlgebra {
    fn mul(&self, scalar: &ScalarBlst) -> Self;
    fn is_in_subgroup(&self) -> bool;
}

impl Engine for BLST {
    fn add_entropy_g1(
        entropy: [u8; 32],
        powers: &mut [crate::G1],
    ) -> Result<(), crate::CeremonyError> {
        let tau = ScalarBlst::try_from(random_scalar(entropy))?;
        let one = ScalarBlst::try_from(1u64)?;

        let taus = iter::successors(Some(one), |x| Some(scalar_mul(x, &tau)))
            .take(powers.len())
            .collect::<Vec<_>>();

        let powers_projective = powers
            .par_iter()
            .zip(taus)
            .map(|(&p, tau)| {
                let p = G1BlstAffine::try_from(p).unwrap(); // TODO
                let p = G1BlstProjective::try_from(p).unwrap(); // TODO
                p.mul(&tau)
            })
            .collect::<Vec<_>>();

        let powers_affine = batch_g1_projective_to_affine(&powers_projective);

        powers
            .par_iter_mut()
            .zip(powers_affine)
            .try_for_each(|(p, p_affine)| {
                *p = G1::try_from(p_affine)?;
                Ok(())
            })
    }

    fn add_entropy_g2(
        entropy: [u8; 32],
        powers: &mut [crate::G2],
    ) -> Result<(), crate::CeremonyError> {
        let tau = ScalarBlst::try_from(random_scalar(entropy))?;
        let one = ScalarBlst::try_from(1u64)?;

        let taus = iter::successors(Some(one), |x| Some(scalar_mul(x, &tau)))
            .take(powers.len())
            .collect::<Vec<_>>();

        let powers_projective = powers
            .par_iter()
            .zip(taus)
            .map(|(&p, tau)| {
                let p = G2BlstAffine::try_from(p).unwrap(); // TODO
                let p = G2BlstProjective::try_from(p).unwrap(); // TODO
                p.mul(&tau)
            })
            .collect::<Vec<_>>();

        let powers_affine = batch_g2_projective_to_affine(&powers_projective);

        powers
            .par_iter_mut()
            .zip(powers_affine)
            .try_for_each(|(p, p_affine)| {
                *p = G2::try_from(p_affine)?;
                Ok(())
            })
    }

    fn validate_g1(points: &[crate::G1]) -> Result<(), crate::CeremonyError> {
        points.into_par_iter().enumerate().try_for_each(|(i, p)| {
            let p = G1BlstAffine::try_from(*p)?;
            if !p.is_in_subgroup() {
                return Err(CeremonyError::InvalidG1Power(
                    i,
                    ParseError::InvalidSubgroup,
                ));
            }
            Ok(())
        })
    }

    fn validate_g2(points: &[crate::G2]) -> Result<(), crate::CeremonyError> {
        points.into_par_iter().enumerate().try_for_each(|(i, p)| {
            let p = G2BlstAffine::try_from(*p)?;
            if !p.is_in_subgroup() {
                return Err(CeremonyError::InvalidG2Power(
                    i,
                    ParseError::InvalidSubgroup,
                ));
            }
            Ok(())
        })
    }

    fn verify_pubkey(
        tau: crate::G1,
        previous: crate::G1,
        pubkey: crate::G2,
    ) -> Result<(), crate::CeremonyError> {
        todo!()
    }

    fn verify_g1(powers: &[crate::G1], tau: crate::G2) -> Result<(), crate::CeremonyError> {
        todo!()
    }

    fn verify_g2(g1: &[crate::G1], g2: &[crate::G2]) -> Result<(), crate::CeremonyError> {
        todo!()
    }
}
