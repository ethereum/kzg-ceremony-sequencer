#![doc = include_str!("../Readme.md")]
#![warn(clippy::all, clippy::pedantic, clippy::cargo, clippy::nursery)]
#![cfg_attr(any(test, feature = "bench"), allow(clippy::wildcard_imports))]

mod contribution;
mod crypto;
mod zcash_format;

pub use contribution::{Contribution, ContributionError, ContributionsError, Transcript};
pub use crypto::{g1_subgroup_check, g2_subgroup_check};
pub use zcash_format::{parse_g, ParseError};

pub const SIZES: [(usize, usize); 4] = [(4096, 65), (8192, 65), (16384, 65), (32768, 65)];

#[cfg(test)]
pub mod test {
    use ark_bls12_381::{Fr, FrParameters, G1Affine, G2Affine};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::{BigInteger256, FpParameters, PrimeField};
    use proptest::{arbitrary::any, strategy::Strategy};
    use ruint::aliases::U256;

    pub fn arb_fr() -> impl Strategy<Value = Fr> {
        any::<U256>().prop_map(|mut n| {
            n %= U256::from(FrParameters::MODULUS);
            Fr::from_repr(BigInteger256::from(n)).unwrap()
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
    use super::*;
    use ark_bls12_381::{Fr, G1Affine, G2Affine};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::UniformRand;
    use criterion::Criterion;

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

    pub fn group(criterion: &mut Criterion) {
        crypto::bench::group(criterion);
        zcash_format::bench::group(criterion);
        contribution::bench::group(criterion);
    }
}
