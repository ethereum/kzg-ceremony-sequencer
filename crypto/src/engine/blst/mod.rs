mod g1;
mod g2;
mod scalar;

use blst::{
    blst_final_exp, blst_fp12, blst_fr, blst_fr_add, blst_miller_loop, blst_p1_affine,
    blst_p1_generator, blst_p2_affine, blst_p2_affine_generator, blst_p2_generator,
};
use rand::Rng;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};
use std::iter;

use crate::{
    engine::blst::{g1::p1_to_affine, g2::p2s_mult_pippenger},
    CeremonyError, Engine, ParseError, G1, G2,
};

use self::{
    g1::{p1_affine_in_g1, p1_from_affine, p1_mult, p1s_mult_pippenger, p1s_to_affine},
    g2::{p2_affine_in_g2, p2_from_affine, p2_mult, p2_to_affine, p2s_to_affine},
    scalar::{fr_mul, fr_one, random_fr, scalar_from_fr},
};

pub struct BLST;

impl Engine for BLST {
    fn add_entropy_g1(
        entropy: [u8; 32],
        powers: &mut [crate::G1],
    ) -> Result<(), crate::CeremonyError> {
        let tau = random_fr(entropy);
        let one = fr_one();

        let taus = iter::successors(Some(one), |x| Some(fr_mul(x, &tau)))
            .take(powers.len())
            .collect::<Vec<_>>();

        let taus = taus.par_iter().map(scalar_from_fr).collect::<Vec<_>>();

        let powers_projective = powers
            .par_iter()
            .zip(taus)
            .map(|(&p, tau)| {
                let p = blst_p1_affine::try_from(p).unwrap(); // TODO
                let p = p1_from_affine(&p);
                p1_mult(&p, &tau)
            })
            .collect::<Vec<_>>();

        let powers_affine = p1s_to_affine(&powers_projective);

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
        let tau = random_fr(entropy);
        let one = fr_one();

        let taus = iter::successors(Some(one), |x| Some(fr_mul(x, &tau)))
            .take(powers.len())
            .collect::<Vec<_>>();

        let taus = taus.par_iter().map(scalar_from_fr).collect::<Vec<_>>();

        let powers_projective = powers
            .par_iter()
            .zip(taus)
            .map(|(&p, tau)| {
                let p = blst_p2_affine::try_from(p).unwrap(); // TODO
                let p = p2_from_affine(&p);
                p2_mult(&p, &tau)
            })
            .collect::<Vec<_>>();

        let powers_affine = p2s_to_affine(&powers_projective);

        powers
            .par_iter_mut()
            .zip(powers_affine)
            .try_for_each(|(p, p_affine)| {
                *p = G2::try_from(p_affine)?;
                Ok(())
            })
    }

    fn validate_g1(points: &[crate::G1]) -> Result<(), crate::CeremonyError> {
        points.into_par_iter().enumerate().try_for_each(|(i, &p)| {
            let p = blst_p1_affine::try_from(p).unwrap(); // TODO
            if p1_affine_in_g1(&p) {
                return Err(CeremonyError::InvalidG1Power(
                    i,
                    ParseError::InvalidSubgroup,
                ));
            }
            Ok(())
        })
    }

    fn validate_g2(points: &[crate::G2]) -> Result<(), crate::CeremonyError> {
        points.into_par_iter().enumerate().try_for_each(|(i, &p)| {
            let p = blst_p2_affine::try_from(p).unwrap(); // TODO
            if p2_affine_in_g2(&p) {
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
        let tau = blst_p1_affine::try_from(tau)?;
        let previous = blst_p1_affine::try_from(previous)?;
        let pubkey = blst_p2_affine::try_from(pubkey)?;

        unsafe {
            let g2 = *blst_p2_affine_generator();
            if pairing(&tau, &g2) != pairing(&previous, &pubkey) {
                return Err(CeremonyError::PubKeyPairingFailed);
            }
        }
        Ok(())
    }

    fn verify_g1(powers: &[crate::G1], tau: crate::G2) -> Result<(), crate::CeremonyError> {
        // Parse ZCash format
        let powers = powers
            .into_par_iter()
            .map(|p| blst_p1_affine::try_from(*p))
            .collect::<Result<Vec<_>, _>>()?;
        let tau = blst_p2_affine::try_from(tau)?;
        let tau = p2_from_affine(&tau);

        // Compute random linear combination
        let (factors, sum) = random_factors(powers.len() - 1);
        let g2 = unsafe { *blst_p2_generator() };

        let lhs_g1 = p1s_mult_pippenger(&powers[1..], &factors[..]);
        let lhs_g2 = p2_to_affine(&p2_mult(&g2, &scalar_from_fr(&sum)));

        let rhs_g1 = p1s_mult_pippenger(&powers[..factors.len()], &factors[..]);
        let rhs_g2 = p2_to_affine(&p2_mult(&tau, &scalar_from_fr(&sum)));

        // Check pairing
        if pairing(&lhs_g1, &lhs_g2) != pairing(&rhs_g1, &rhs_g2) {
            return Err(CeremonyError::G1PairingFailed);
        }

        Ok(())
    }

    fn verify_g2(g1: &[crate::G1], g2: &[crate::G2]) -> Result<(), crate::CeremonyError> {
        assert!(g1.len() == g2.len());

        // Parse ZCash format
        let g1 = g1
            .into_par_iter()
            .map(|p| blst_p1_affine::try_from(*p))
            .collect::<Result<Vec<_>, _>>()?;

        let g2 = g2
            .into_par_iter()
            .map(|p| blst_p2_affine::try_from(*p))
            .collect::<Result<Vec<_>, _>>()?;

        // Compute random linear combination
        let (factors, sum) = random_factors(g2.len());
        let g1_generator = unsafe { *blst_p1_generator() };
        let g2_generator = unsafe { *blst_p2_generator() };

        let lhs_g1 = p1s_mult_pippenger(&g1, &factors[..]);
        let lhs_g2 = p2_to_affine(&p2_mult(&g2_generator, &scalar_from_fr(&sum)));

        let rhs_g1 = p1_to_affine(&p1_mult(&g1_generator, &scalar_from_fr(&sum)));
        let rhs_g2 = p2s_mult_pippenger(&g2, &factors[..]);

        // Check pairing
        if pairing(&lhs_g1, &lhs_g2) != pairing(&rhs_g1, &rhs_g2) {
            return Err(CeremonyError::G1PairingFailed);
        }

        Ok(())
    }
}

fn pairing(p: &blst_p1_affine, q: &blst_p2_affine) -> blst_fp12 {
    let mut tmp = blst_fp12::default();
    unsafe { blst_miller_loop(&mut tmp, q, p) };

    let mut out = blst_fp12::default();
    unsafe { blst_final_exp(&mut out, &tmp) };

    out
}

fn random_factors(n: usize) -> (Vec<blst_fr>, blst_fr) {
    let mut rng = rand::thread_rng();
    let mut entropy = [0u8; 32];
    rng.fill(&mut entropy);

    let mut sum = blst_fr::default();
    let factors = iter::from_fn(|| {
        let r = random_fr(entropy);
        unsafe { blst_fr_add(&mut sum, &sum, &r) };
        Some(r)
    })
    .take(n)
    .collect::<Vec<_>>();
    (factors, sum)
}
