use super::error::CeremonyError;
use crate::zcash_format::{parse_g, ParseError};
use ark_bls12_381::Fr;
use ark_ec::{short_weierstrass_jacobian::GroupAffine, SWModelParameters};
use ark_ff::{PrimeField, UniformRand, Zero};
use rayon::prelude::*;
use std::iter;

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
