//! Arkworks implementation of [`Engine`].

#![cfg(feature = "arkworks")]

mod endomorphism;
mod zcash_format;

use self::endomorphism::{g1_mul_glv, g1_subgroup_check, g2_subgroup_check};
use super::Engine;
use crate::{CeremonyError, ParseError, G1, G2};
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    msm::VariableBaseMSM, wnaf::WnafContext, AffineCurve, PairingEngine, ProjectiveCurve,
};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use rand::{rngs::StdRng, SeedableRng};
use rayon::prelude::*;
use std::iter;
use tracing::instrument;

/// Arkworks implementation of [`Engine`] with additional endomorphism
/// optimizations.
pub struct Arkworks;

impl Engine for Arkworks {
    #[instrument(level = "info", skip_all, fields(n=points.len()))]
    fn validate_g1(points: &[G1]) -> Result<(), CeremonyError> {
        points.into_par_iter().enumerate().try_for_each(|(i, p)| {
            let p = G1Affine::try_from(*p).map_err(|e| CeremonyError::InvalidG1Power(i, e))?;
            if !g1_subgroup_check(&p) {
                return Err(CeremonyError::InvalidG1Power(
                    i,
                    ParseError::InvalidSubgroup,
                ));
            }
            Ok(())
        })
    }

    #[instrument(level = "info", skip_all, fields(n=points.len()))]
    fn validate_g2(points: &[G2]) -> Result<(), CeremonyError> {
        points.into_par_iter().enumerate().try_for_each(|(i, p)| {
            let p = G2Affine::try_from(*p).map_err(|e| CeremonyError::InvalidG2Power(i, e))?;
            if !g2_subgroup_check(&p) {
                return Err(CeremonyError::InvalidG2Power(
                    i,
                    ParseError::InvalidSubgroup,
                ));
            }
            Ok(())
        })
    }

    #[instrument(level = "info", skip_all)]
    fn verify_pubkey(tau: G1, previous: G1, pubkey: G2) -> Result<(), CeremonyError> {
        let (g1, g2) = Self::verify_pubkey_defer_pairing(tau, previous, pubkey)?;

        let pairing_inputs: Vec<_> = g1
            .iter()
            .zip(g2.iter())
            .map(|(g1, g2)| {
                (
                    <Bls12_381 as PairingEngine>::G1Prepared::from(
                        G1Affine::try_from(*g1).unwrap(),
                    ),
                    <Bls12_381 as PairingEngine>::G2Prepared::from(
                        G2Affine::try_from(*g2).unwrap(),
                    ),
                )
            })
            .collect();

        if !Bls12_381::product_of_pairings(pairing_inputs.as_slice()).is_one() {
            return Err(CeremonyError::PubKeyPairingFailed);
        }
        Ok(())
    }

    #[instrument(level = "info", skip_all)]
    fn verify_pubkey_defer_pairing(
        tau: G1,
        previous: G1,
        pubkey: G2,
    ) -> Result<(Vec<G1>, Vec<G2>), CeremonyError> {
        let neg_tau = -G1Affine::try_from(tau)?;
        Ok((
            vec![
                neg_tau.into(),
                previous,
            ],
            vec![G2Affine::prime_subgroup_generator().into(), pubkey],
        ))
    }

    #[instrument(level = "info", skip_all, fields(n=powers.len()))]
    fn verify_g1(powers: &[G1], tau: G2) -> Result<(), CeremonyError> {
        let (g1, g2) = Self::verify_g1_defer_pairing(powers, tau)?;

        let pairing_inputs: Vec<_> = g1
            .iter()
            .zip(g2.iter())
            .map(|(g1, g2)| {
                (
                    <Bls12_381 as PairingEngine>::G1Prepared::from(
                        G1Affine::try_from(*g1).unwrap(),
                    ),
                    <Bls12_381 as PairingEngine>::G2Prepared::from(
                        G2Affine::try_from(*g2).unwrap(),
                    ),
                )
            })
            .collect();

        // Check pairing
        if !Bls12_381::product_of_pairings(pairing_inputs.as_slice()).is_one() {
            return Err(CeremonyError::G1PairingFailed);
        }
        Ok(())
    }

    #[instrument(level = "info", skip_all, fields(n=powers.len()))]
    fn verify_g1_defer_pairing(
        powers: &[G1],
        tau: G2,
    ) -> Result<(Vec<G1>, Vec<G2>), CeremonyError> {
        // Parse ZCash format
        let powers = powers
            .into_par_iter()
            .map(|p| G1Affine::try_from(*p))
            .collect::<Result<Vec<_>, _>>()?;
        let tau = G2Affine::try_from(tau)?;

        // Compute random linear combination
        let (factors, sum) = random_factors(powers.len() - 1);
        let lhs_g1 =
            -VariableBaseMSM::multi_scalar_mul(&powers[1..], &factors[..]).mul(sum.into_repr());
        let lhs_g2 = G2Affine::prime_subgroup_generator();
        let rhs_g1 = VariableBaseMSM::multi_scalar_mul(&powers[..factors.len()], &factors[..])
            .mul(sum.into_repr());
        let rhs_g2 = tau;

        Ok((
            vec![lhs_g1.into_affine().into(), rhs_g1.into_affine().into()],
            vec![lhs_g2.into(), rhs_g2.into()],
        ))
    }

    #[instrument(level = "info", skip_all, fields(n1=g1.len(), n2=g2.len()))]
    fn verify_g2(g1: &[G1], g2: &[G2]) -> Result<(), CeremonyError> {
        let (g1, g2) = Self::verify_g2_defer_pairing(g1, g2)?;

        let pairing_inputs: Vec<_> = g1
            .iter()
            .zip(g2.iter())
            .map(|(g1, g2)| {
                (
                    <Bls12_381 as PairingEngine>::G1Prepared::from(
                        G1Affine::try_from(*g1).unwrap(),
                    ),
                    <Bls12_381 as PairingEngine>::G2Prepared::from(
                        G2Affine::try_from(*g2).unwrap(),
                    ),
                )
            })
            .collect();
        // Check pairing
        if !Bls12_381::product_of_pairings(pairing_inputs.as_slice()).is_one() {
            return Err(CeremonyError::G2PairingFailed);
        }
        Ok(())
    }

    #[instrument(level = "info", skip_all, fields(n1=g1.len(), n2=g2.len()))]
    fn verify_g2_defer_pairing(g1: &[G1], g2: &[G2]) -> Result<(Vec<G1>, Vec<G2>), CeremonyError> {
        assert!(g1.len() == g2.len());

        // Parse ZCash format
        let g1 = g1
            .into_par_iter()
            .map(|p| G1Affine::try_from(*p))
            .collect::<Result<Vec<_>, _>>()?;
        let g2 = g2
            .into_par_iter()
            .map(|p| G2Affine::try_from(*p))
            .collect::<Result<Vec<_>, _>>()?;

        // Compute random linear combination
        let (factors, sum) = random_factors(g2.len());
        let lhs_g1 = -VariableBaseMSM::multi_scalar_mul(&g1, &factors[..]).mul(sum.into_repr());
        let lhs_g2 = G2Affine::prime_subgroup_generator();
        let rhs_g1 = G1Affine::prime_subgroup_generator().mul(sum);
        let rhs_g2 = VariableBaseMSM::multi_scalar_mul(&g2, &factors[..]);

        Ok((
            vec![lhs_g1.into_affine().into(), rhs_g1.into_affine().into()],
            vec![lhs_g2.into(), rhs_g2.into_affine().into()],
        ))
    }

    #[instrument(level = "info", skip_all, fields(n=powers.len()))]
    fn add_entropy_g1(entropy: [u8; 32], powers: &mut [G1]) -> Result<(), CeremonyError> {
        let tau = random_scalar(entropy);
        let taus = iter::successors(Some(Fr::one()), |x| Some(*x * tau))
            .take(powers.len())
            .collect::<Vec<_>>();
        let mut projective = powers
            .par_iter()
            .zip(taus)
            .map(|(p, tau)| G1Affine::try_from(*p).map(|p| g1_mul_glv(&p, tau)))
            .collect::<Result<Vec<_>, _>>()?;
        G1Projective::batch_normalization(&mut projective);
        for (p, a) in powers.iter_mut().zip(projective) {
            *p = a.into_affine().into();
        }
        Ok(())
    }

    #[instrument(level = "info", skip_all, fields(n=powers.len()))]
    fn add_entropy_g2(entropy: [u8; 32], powers: &mut [G2]) -> Result<(), CeremonyError> {
        let tau = random_scalar(entropy);
        let taus = iter::successors(Some(Fr::one()), |x| Some(*x * tau))
            .take(powers.len())
            .collect::<Vec<_>>();
        let mut projective = powers
            .par_iter()
            .zip(taus)
            .map(|(p, tau)| {
                G2Affine::try_from(*p).map(|p| {
                    let wnaf = WnafContext::new(5);
                    wnaf.mul(p.into(), &tau)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        G2Projective::batch_normalization(&mut projective);
        for (p, a) in powers.iter_mut().zip(projective) {
            *p = a.into_affine().into();
        }
        Ok(())
    }

    fn pairing_products_is_one(g1: &[G1], g2: &[G2]) -> Result<bool, CeremonyError> {
        let len = g1.len();
        assert_eq!(len, g2.len());
        assert_eq!(len & 1, 0);
        assert!(len >= 2);

        // we may take more than 2 pairing products, for which we will need
        // to use random linear combinations to randomize the inputs.
        let mut rng = rand::thread_rng();
        let mut randomizers = vec![Fr::one()];

        randomizers.extend_from_slice(
            (0..len - 1)
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>()
                .as_slice(),
        );

        let g1_proj = g1
            .par_chunks(2)
            .zip(randomizers.into_par_iter())
            .map(|(g, r)| {
                vec![
                    G1Affine::try_from(g[0]).unwrap().mul(r.into_repr()),
                    G1Affine::try_from(g[1]).unwrap().mul(r.into_repr()),
                ]
            })
            .flatten()
            .collect::<Vec<_>>();
        let g1_affine = G1Projective::batch_normalization_into_affine(g1_proj.as_slice());
        let pairing_inputs = g1_affine
            .iter()
            .zip(g2.iter())
            .map(|(&g1, &g2)| {
                (
                    <Bls12_381 as PairingEngine>::G1Prepared::from(g1),
                    <Bls12_381 as PairingEngine>::G2Prepared::from(G2Affine::try_from(g2).unwrap()),
                )
            })
            .collect::<Vec<_>>();
        // Check pairing
        Ok(Bls12_381::product_of_pairings(pairing_inputs.as_slice()).is_one())
    }
}

fn random_factors(n: usize) -> (Vec<<Fr as PrimeField>::BigInt>, Fr) {
    let mut rng = rand::thread_rng();
    let mut sum = Fr::zero();
    let factors = iter::from_fn(|| {
        let r = Fr::rand(&mut rng);
        sum += r;
        Some(r.0)
    })
    .take(n)
    .collect::<Vec<_>>();
    (factors, sum)
}

fn random_scalar(entropy: [u8; 32]) -> Fr {
    // TODO: Use an explicit cryptographic rng.
    let mut rng = StdRng::from_seed(entropy);
    Fr::rand(&mut rng)
}

#[cfg(test)]
pub mod test {
    use super::*;
    use ark_bls12_381::FrParameters;
    use ark_ec::ProjectiveCurve;
    use ark_ff::{BigInteger256, FpParameters};
    use proptest::{arbitrary::any, strategy::Strategy};
    use ruint::aliases::U256;

    #[allow(clippy::missing_panics_doc)]
    pub fn arb_fr() -> impl Strategy<Value = Fr> {
        any::<U256>().prop_map(|mut n| {
            n %= U256::from(FrParameters::MODULUS);
            Fr::from_repr(BigInteger256::from(n)).expect("n is smaller than modulus")
        })
    }

    pub fn arb_g1() -> impl Strategy<Value = G1Affine> {
        arb_fr().prop_map(|s| G1Affine::prime_subgroup_generator().mul(s).into_affine())
    }

    pub fn arb_g2() -> impl Strategy<Value = G2Affine> {
        arb_fr().prop_map(|s| G2Affine::prime_subgroup_generator().mul(s).into_affine())
    }
}

#[cfg(feature = "bench")]
#[doc(hidden)]
pub mod bench {
    use super::{super::bench::bench_engine, *};
    use ark_ec::ProjectiveCurve;
    use criterion::Criterion;

    pub fn group(criterion: &mut Criterion) {
        bench_engine::<Arkworks>(criterion, "arkworks");
        endomorphism::bench::group(criterion);
        zcash_format::bench::group(criterion);
    }

    #[must_use]
    pub fn rand_fr() -> Fr {
        let mut rng = rand::thread_rng();
        Fr::rand(&mut rng)
    }

    pub fn rand_g1() -> G1Affine {
        G1Affine::prime_subgroup_generator()
            .mul(rand_fr())
            .into_affine()
    }

    pub fn rand_g2() -> G2Affine {
        G2Affine::prime_subgroup_generator()
            .mul(rand_fr())
            .into_affine()
    }
}
