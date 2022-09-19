use super::error::CeremonyError;
use crate::{
    crypto::g1_mul_glv,
    g1_subgroup_check, g2_subgroup_check, parse_g,
    zcash_format::{write_g, ParseError},
};
use ark_bls12_381::{g2, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    msm::VariableBaseMSM, short_weierstrass_jacobian::GroupAffine, AffineCurve, PairingEngine,
    ProjectiveCurve, SWModelParameters,
};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{cmp::max, iter};
use thiserror::Error;
use tracing::{error, instrument};
use zeroize::Zeroizing;

pub(super) fn random_factors(n: usize) -> (Vec<<Fr as PrimeField>::BigInt>, Fr) {
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

pub(super) fn read_vector_of_points<P, F>(
    items: &Vec<String>,
    wrap_err: F,
) -> Result<Vec<GroupAffine<P>>, CeremonyError>
where
    P: SWModelParameters,
    F: Fn(usize, ParseError) -> CeremonyError + Sync,
{
    items
        .par_iter()
        .enumerate()
        .map(|(i, str)| parse_g(str).map_err(|err| wrap_err(i, err)))
        .collect()
}
