mod g1;
mod g2;
mod scalar;

use blst::{
    blst_final_exp, blst_fp12, blst_miller_loop, blst_p1_affine, blst_p2_affine,
    blst_p2_affine_generator,
};
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};
use std::iter;

use crate::{
    CeremonyError, Engine, ParseError, G1, G2,
};

use self::{
    g1::{p1_affine_in_g1, p1_from_affine, p1_mult, p1s_to_affine},
    g2::{p2_affine_in_g2, p2_from_affine, p2_mult, p2s_to_affine},
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
        // let powers = powers
        //     .into_par_iter()
        //     .map(|p| blst_p1_affine::try_from(*p))
        //     .collect::<Result<Vec<_>, _>>()?;
        // let tau = blst_p2_affine::try_from(tau)?;
        todo!()
    }

    fn verify_g2(g1: &[crate::G1], g2: &[crate::G2]) -> Result<(), crate::CeremonyError> {
        todo!()
    }
}

fn pairing(p: &blst_p1_affine, q: &blst_p2_affine) -> blst_fp12 {
    let mut tmp = blst_fp12::default();
    unsafe { blst_miller_loop(&mut tmp, q, p) };

    let mut out = blst_fp12::default();
    unsafe { blst_final_exp(&mut out, &tmp) };

    out
}

// fn random_factors(n: usize) -> (Vec<blst_scalar>, blst_scalar) {
//     let mut rng = rand::thread_rng();
//     let mut sum = blst_scalar::default();
//     let factors = iter::from_fn(|| {
//         let r = Fr::rand(&mut rng);
//         sum += r;
//         Some(r.0)
//     })
//     .take(n)
//     .collect::<Vec<_>>();
//     (factors, sum)
// }
