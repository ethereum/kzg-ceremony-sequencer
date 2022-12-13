//! Arkworks implementation of [`Engine`].

#![cfg(feature = "arkworks")]

mod endomorphism;
mod ext_field;
mod hashing;
mod zcash_format;

use self::endomorphism::{g1_mul_glv, g1_subgroup_check, g2_subgroup_check};
use super::Engine;
use crate::{
    engine::arkworks::hashing::{
        hash_to_curve::{HashToCurve, MapToCurveBasedHasher, WBMap},
        hash_to_field::DefaultFieldHasher,
    },
    CeremonyError, Entropy, ParseError, Tau, F, G1, G2,
};
use ark_bls12_381::{
    g1::Parameters as G1Parameters, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{
    msm::VariableBaseMSM, wnaf::WnafContext, AffineCurve, PairingEngine, ProjectiveCurve,
};
use ark_ff::{BigInteger, One, PrimeField, UniformRand, Zero};
use digest::Digest;
use hkdf::Hkdf;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use secrecy::{ExposeSecret, Secret, SecretVec};
use sha2::Sha256;
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
        let tau = G1Affine::try_from(tau)?;
        let previous = G1Affine::try_from(previous)?;
        let pubkey = G2Affine::try_from(pubkey)?;
        if Bls12_381::pairing(tau, G2Affine::prime_subgroup_generator())
            != Bls12_381::pairing(previous, pubkey)
        {
            return Err(CeremonyError::PubKeyPairingFailed);
        }
        Ok(())
    }

    #[instrument(level = "info", skip_all, fields(n=powers.len()))]
    fn verify_g1(powers: &[G1], tau: G2) -> Result<(), CeremonyError> {
        // Parse ZCash format
        let powers = powers
            .into_par_iter()
            .map(|p| G1Affine::try_from(*p))
            .collect::<Result<Vec<_>, _>>()?;
        let tau = G2Affine::try_from(tau)?;

        // Compute random linear combination
        let (factors, sum) = random_factors(powers.len() - 1);
        let lhs_g1 = VariableBaseMSM::multi_scalar_mul(&powers[1..], &factors[..]);
        let lhs_g2 = G2Affine::prime_subgroup_generator().mul(sum);
        let rhs_g1 = VariableBaseMSM::multi_scalar_mul(&powers[..factors.len()], &factors[..]);
        let rhs_g2 = tau.mul(sum);

        // Check pairing
        if Bls12_381::pairing(lhs_g1, lhs_g2) != Bls12_381::pairing(rhs_g1, rhs_g2) {
            return Err(CeremonyError::G1PairingFailed);
        }
        Ok(())
    }

    #[instrument(level = "info", skip_all, fields(n1=g1.len(), n2=g2.len()))]
    fn verify_g2(g1: &[G1], g2: &[G2]) -> Result<(), CeremonyError> {
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
        let lhs_g1 = VariableBaseMSM::multi_scalar_mul(&g1, &factors[..]);
        let lhs_g2 = G2Affine::prime_subgroup_generator().mul(sum);
        let rhs_g1 = G1Affine::prime_subgroup_generator().mul(sum);
        let rhs_g2 = VariableBaseMSM::multi_scalar_mul(&g2, &factors[..]);

        // Check pairing
        if Bls12_381::pairing(lhs_g1, lhs_g2) != Bls12_381::pairing(rhs_g1, rhs_g2) {
            return Err(CeremonyError::G2PairingFailed);
        }
        Ok(())
    }

    #[instrument(level = "info", skip_all)]
    fn generate_tau(entropy: &Entropy) -> Tau {
        // Use ChaCha20 CPRNG
        let mut rng = ChaCha20Rng::from_seed(*entropy.expose_secret());

        // Generate tau by reducing 512 bits of entropy modulo prime.
        let mut large = [0_u8; 64];
        rng.fill(&mut large);

        let fr = bls_keygen(large);

        // Convert to Tau
        let le_bytes = fr.into_repr().to_bytes_le();
        assert!(le_bytes.len() == 32);
        let mut tau = [0u8; 32];
        tau.copy_from_slice(&le_bytes[..]);
        Secret::new(F(tau))
    }

    #[instrument(level = "info", skip_all, fields(n=powers.len()))]
    fn add_tau_g1(tau: &Tau, powers: &mut [G1]) -> Result<(), CeremonyError> {
        let taus = powers_of_tau(tau, powers.len());
        let mut projective = powers
            .par_iter()
            .zip(taus.expose_secret())
            .map(|(p, tau)| G1Affine::try_from(*p).map(|p| g1_mul_glv(&p, *tau)))
            .collect::<Result<Vec<_>, _>>()?;
        G1Projective::batch_normalization(&mut projective);
        for (p, a) in powers.iter_mut().zip(projective) {
            *p = a.into_affine().into();
        }
        Ok(())
    }

    #[instrument(level = "info", skip_all, fields(n=powers.len()))]
    fn add_tau_g2(tau: &Tau, powers: &mut [G2]) -> Result<(), CeremonyError> {
        let taus = powers_of_tau(tau, powers.len());
        let mut projective = powers
            .par_iter()
            .zip(taus.expose_secret())
            .map(|(p, tau)| {
                G2Affine::try_from(*p).map(|p| {
                    let wnaf = WnafContext::new(5);
                    wnaf.mul(p.into(), tau)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        G2Projective::batch_normalization(&mut projective);
        for (p, a) in powers.iter_mut().zip(projective) {
            *p = a.into_affine().into();
        }
        Ok(())
    }

    fn sign_message(tau: &Tau, message: &[u8]) -> Option<G1> {
        let mapper = MapToCurveBasedHasher::<
            G1Parameters,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<G1Parameters>,
        >::new(Self::CYPHER_SUITE.as_bytes())
        .ok()?;
        let point = mapper.hash(message).ok()?;
        let sig = point.mul(Fr::from(tau.expose_secret())).into_affine();
        Some(G1::from(sig))
    }

    fn verify_signature(sig: G1, message: &[u8], pk: G2) -> bool {
        let sig = match G1Affine::try_from(sig) {
            Ok(sig) => sig,
            _ => return false,
        };
        if !g1_subgroup_check(&sig) {
            return false;
        }
        let pk = match G2Affine::try_from(pk) {
            Ok(pk) => pk,
            _ => return false,
        };
        if !g2_subgroup_check(&pk) {
            return false;
        }
        let mapper = match MapToCurveBasedHasher::<
            G1Parameters,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<G1Parameters>,
        >::new(Self::CYPHER_SUITE.as_bytes())
        {
            Ok(mapper) => mapper,
            _ => return false,
        };

        let msg = match mapper.hash(message) {
            Ok(msg) => msg,
            _ => return false,
        };

        let c1 = Bls12_381::pairing(msg, pk);
        let c2 = Bls12_381::pairing(sig, G2Affine::prime_subgroup_generator());

        c1 == c2
    }
}

// Implementation of the KeyGen function as specified in
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/
fn bls_keygen(ikm: [u8; 64]) -> Fr {
    // the `L` value, precomputed from the formula given in the spec
    const L: u8 = 48;
    let mut full_ikm = [0u8; 65];
    full_ikm[..64].copy_from_slice(&ikm);
    full_ikm[64] = 0;
    let key_info = [0, L];

    let mut hasher = Sha256::new();
    hasher.update(b"BLS-SIG-KEYGEN-SALT-");
    let mut salt = hasher.finalize();

    loop {
        let hk = Hkdf::<Sha256>::new(Some(&salt), &full_ikm);
        let mut out = [0; L as usize];
        hk.expand(&key_info, &mut out).unwrap();
        let fr = Fr::from_be_bytes_mod_order(&out);
        if fr != Fr::zero() {
            return fr;
        }
        hasher = Sha256::new();
        hasher.update(&salt);
        salt = hasher.finalize();
    }
}

pub fn powers_of_tau(tau: &Tau, n: usize) -> SecretVec<Fr> {
    // Convert tau
    // TODO: Throw error instead of reducing
    let tau = Secret::new(Fr::from(tau.expose_secret()));

    // Compute powers
    Secret::new(
        iter::successors(Some(Fr::one()), |x| Some(*x * tau.expose_secret()))
            .take(n)
            .collect::<Vec<_>>(),
    )
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

impl From<&F> for Fr {
    fn from(f: &F) -> Self {
        Self::from_le_bytes_mod_order(&f.0[..])
    }
}

#[cfg(test)]
impl From<Fr> for F {
    fn from(fr: Fr) -> Self {
        let le_bytes = fr.into_repr().to_bytes_le();
        assert!(le_bytes.len() == 32);
        let mut f = [0u8; 32];
        f.copy_from_slice(&le_bytes[..]);
        Self(f)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use ark_ec::ProjectiveCurve;
    use ark_ff::BigInteger256;
    use proptest::{arbitrary::any, strategy::Strategy};
    use ruint::{aliases::U256, uint};

    #[allow(clippy::missing_panics_doc)]
    pub fn arb_fr() -> impl Strategy<Value = Fr> {
        any::<U256>().prop_map(|mut n| {
            n %= uint!(52435875175126190479447740508185965837690552500527637822603658699938581184513_U256);
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
#[cfg(not(tarpaulin_include))]
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
