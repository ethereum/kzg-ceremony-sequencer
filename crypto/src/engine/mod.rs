//! Abstraction over the backend used for cryptographic operations.
//!
//! # To do
//!
//! * Add support for BLST backend.
//! * Better API for passing entropy (`Secret<_>` etc.)

#[cfg(feature = "arkworks")]
mod arkworks;
#[cfg(feature = "blst")]
mod blst;
mod both;

use crate::{CeremonyError, F, G1, G2};
pub use secrecy::Secret;

#[cfg(feature = "arkworks")]
pub use self::arkworks::Arkworks;
#[cfg(feature = "blst")]
pub use self::blst::BLST;
pub use self::both::Both;

pub type Entropy = Secret<[u8; 32]>;
pub type Tau = Secret<F>;

pub trait Engine {
    const CYPHER_SUITE: &'static str = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

    /// Verifies that the given G1 points are valid.
    ///
    /// Valid mean that they are uniquely encoded in compressed ZCash format and
    /// represent curve points in the prime order subgroup.
    ///
    /// # Errors
    /// Returns an error if any of the `points` is not a compressed ZCash format
    /// point on the curve, or if the point is not in the correct prime order
    /// subgroup.
    fn validate_g1(points: &[G1]) -> Result<(), CeremonyError>;

    /// Verifies that the given G2 points are valid.
    ///
    /// Valid mean that they are uniquely encoded in compressed ZCash format and
    /// represent curve points in the prime order subgroup.
    ///
    /// # Errors
    /// Returns an error if any of the `points` is not a compressed ZCash format
    /// point on the curve, or if the point is not in the correct prime order
    /// subgroup.
    fn validate_g2(points: &[G2]) -> Result<(), CeremonyError>;

    /// Verify that the pubkey contains the contribution added
    /// from `previous` to `tau`.
    ///
    /// # Errors
    /// Returns an error if any of the points is invalid, or if the pairing
    /// check fails.
    fn verify_pubkey(tau: G1, previous: G1, pubkey: G2) -> Result<(), CeremonyError>;

    /// Verify that `powers` contains a sequence of powers of `tau`.
    ///
    /// # Errors
    /// Returns an error if any of the points is invalid, or if the points are
    /// not a valid sequence of powers.
    fn verify_g1(powers: &[G1], tau: G2) -> Result<(), CeremonyError>;

    /// Verify that `g1` and `g2` contain the same values.
    ///
    /// # Errors
    /// Returns an error if any of the points is invalid, if `g2` is not a valid
    /// sequence of powers, or if `g1` and `g2` are sequences with different
    /// exponents.
    fn verify_g2(g1: &[G1], g2: &[G2]) -> Result<(), CeremonyError>;

    /// Derive a secret scalar $τ$ from the given entropy.
    fn generate_tau(entropy: &Entropy) -> Tau;

    /// Multiply elements of `powers` by powers of $τ$.
    ///
    /// # Errors
    /// Returns an error if any of `powers` is not a valid curve point.
    fn add_tau_g1(tau: &Tau, powers: &mut [G1]) -> Result<(), CeremonyError>;

    /// Multiply elements of `powers` by powers of $τ$.
    ///
    /// # Errors
    /// Returns an error if any of `powers` is not a valid curve point.
    fn add_tau_g2(tau: &Tau, powers: &mut [G2]) -> Result<(), CeremonyError>;

    /// Sign a message with `CYPHER_SUITE`, using $τ$ as the secret key.
    fn sign_message(tau: &Tau, message: &[u8]) -> Option<G1>;

    /// Verify a `CYPHER_SUITE` signature.
    fn verify_signature(sig: G1, message: &[u8], pk: G2) -> bool;
}

#[cfg(all(test, feature = "arkworks", feature = "blst"))]
pub mod tests {
    use super::*;
    use crate::DefaultEngine;
    use ark_bls12_381::G1Affine;
    use hex_literal::hex;
    use proptest::{arbitrary::any, proptest, strategy::Strategy};
    use secrecy::ExposeSecret;

    pub fn arb_f() -> impl Strategy<Value = F> {
        arkworks::test::arb_fr().prop_map(F::from)
    }

    pub fn arb_g1() -> impl Strategy<Value = G1> {
        arkworks::test::arb_g1().prop_map(G1::from)
    }

    pub fn arb_g2() -> impl Strategy<Value = G2> {
        arkworks::test::arb_g2().prop_map(G2::from)
    }

    pub fn arb_entropy() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    #[test]
    fn test_zeros_in_verify_signature() {
        let r1 = Arkworks::verify_signature(G1::zero(), b"hello", G2::zero());
        let r2 = BLST::verify_signature(G1::zero(), b"hello", G2::zero());
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_generate_tau() {
        proptest!(|(entropy in arb_entropy())| {
            let entropy = Secret::new(entropy);
            let tau1 = Arkworks::generate_tau(&entropy);
            let tau2 = BLST::generate_tau(&entropy);
            assert_eq!(tau1.expose_secret(), tau2.expose_secret());
        });
    }

    fn run_add_tau_test(tau: F, p: G1, require_success: bool) {
        let tau = Secret::new(tau);
        let points1: &mut [G1] = &mut [p; 16];
        let points2: &mut [G1] = &mut [p; 16];

        let result1 = BLST::add_tau_g1(&tau, points1);
        let result2 = Arkworks::add_tau_g1(&tau, points2);
        if require_success {
            assert_eq!(result1, Ok(()));
        }
        assert_eq!(result1, result2);
        assert_eq!(points1, points2);
    }

    #[test]
    fn test_add_tau_g1_zero() {
        let p = G1::from(G1Affine::get_point_from_x(0.into(), false).unwrap());
        run_add_tau_test(F::zero(), p, false);
    }

    #[test]
    fn test_add_tau_g1() {
        proptest!(|(tau in arb_f(), p in arb_g1())| {
            run_add_tau_test(tau, p, true);
        });
    }

    #[test]
    fn test_add_tau_g2() {
        proptest!(|(tau in arb_f(), p in arb_g2())| {
            let tau = Secret::new(tau);
            let points1: &mut [G2] = &mut [p; 16];
            let points2: &mut [G2] = &mut [p; 16];

            BLST::add_tau_g2(&tau, points1).unwrap();
            Arkworks::add_tau_g2(&tau, points2).unwrap();

            assert_eq!(points1, points2);
        });
    }

    #[test]
    fn test_tau_larger_than_modulus() {
        let f = F(hex!(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
        let reduced_f = F(hex!(
            "fdffffff0100000002480300fab78458f54fbcecef4f8c996f05c5ac59b12418"
        ));
        let g1_1 = &mut [G1::one(); 16];
        let g1_2 = &mut [G1::one(); 16];
        DefaultEngine::add_tau_g1(&Secret::new(f), g1_1).unwrap();
        DefaultEngine::add_tau_g1(&Secret::new(reduced_f), g1_2).unwrap();
        assert_eq!(g1_1, g1_2);

        let g2_1 = &mut [G2::one(); 16];
        let g2_2 = &mut [G2::one(); 16];
        DefaultEngine::add_tau_g2(&Secret::new(f), g2_1).unwrap();
        DefaultEngine::add_tau_g2(&Secret::new(reduced_f), g2_2).unwrap();
        assert_eq!(g2_1, g2_2);
    }

    #[test]
    fn test_validate_g1() {
        let g1 = G1([0u8; 48]);
        assert!(BLST::validate_g1(&[g1]).is_err());
        assert!(Arkworks::validate_g1(&[g1]).is_err());
    }

    #[test]
    fn test_validate_g2() {
        let g2 = G2([0u8; 96]);
        assert!(BLST::validate_g2(&[g2]).is_err());
        assert!(Arkworks::validate_g2(&[g2]).is_err());
    }
}

#[cfg(feature = "bench")]
#[cfg(not(tarpaulin_include))]
#[doc(hidden)]
pub mod bench {
    use super::*;
    use criterion::{BatchSize, BenchmarkId, Criterion};
    use rand::Rng;
    use std::iter;

    pub fn group(criterion: &mut Criterion) {
        #[cfg(feature = "arkworks")]
        arkworks::bench::group(criterion);
        #[cfg(feature = "blst")]
        blst::bench::group(criterion);
        #[cfg(all(feature = "arkworks", feature = "blst"))]
        bench_engine::<Both<Arkworks, BLST>>(criterion, "both");
    }

    pub(super) fn bench_engine<E: Engine>(criterion: &mut Criterion, name: &str) {
        bench_validate_g1::<E>(criterion, name);
        bench_validate_g2::<E>(criterion, name);
        bench_verify_pubkey::<E>(criterion, name);
        bench_verify_g1::<E>(criterion, name);
        bench_verify_g2::<E>(criterion, name);
        bench_generate_tau::<E>(criterion, name);
        bench_add_tau_g1::<E>(criterion, name);
        bench_add_tau_g2::<E>(criterion, name);
    }

    const G1_SIZES: [usize; 5] = [1, 4096, 8192, 16384, 32768];
    const G2_SIZES: [usize; 2] = [1, 65];

    fn rand_g1() -> G1 {
        arkworks::bench::rand_g1().into()
    }

    fn rand_g2() -> G2 {
        arkworks::bench::rand_g2().into()
    }

    fn rand_entropy() -> Entropy {
        let mut rng = rand::thread_rng();
        Secret::new(rng.gen())
    }

    fn rand_tau() -> Tau {
        Arkworks::generate_tau(&rand_entropy())
    }

    fn bench_validate_g1<E: Engine>(criterion: &mut Criterion, name: &str) {
        let id = format!("engine/{name}/validate_g1");
        for size in G1_SIZES {
            criterion.bench_with_input(
                BenchmarkId::new(id.clone(), size),
                &size,
                move |bencher, &size| {
                    bencher.iter_batched_ref(
                        || iter::repeat(rand_g1()).take(size).collect::<Vec<_>>(),
                        |points| E::validate_g1(points).unwrap(),
                        BatchSize::LargeInput,
                    );
                },
            );
        }
    }

    fn bench_validate_g2<E: Engine>(criterion: &mut Criterion, name: &str) {
        let id = format!("engine/{name}/validate_g2");
        for size in G2_SIZES {
            criterion.bench_with_input(
                BenchmarkId::new(id.clone(), size),
                &size,
                move |bencher, &size| {
                    bencher.iter_batched_ref(
                        || iter::repeat(rand_g2()).take(size).collect::<Vec<_>>(),
                        |points| E::validate_g2(points).unwrap(),
                        BatchSize::LargeInput,
                    );
                },
            );
        }
    }

    fn bench_verify_pubkey<E: Engine>(criterion: &mut Criterion, name: &str) {
        let id = format!("engine/{name}/verify_pubkey");
        criterion.bench_function(&id, move |bencher| {
            bencher.iter_batched(
                || (rand_g1(), rand_g1(), rand_g2()),
                |(a, b, c)| E::verify_pubkey(a, b, c),
                BatchSize::SmallInput,
            );
        });
    }

    fn bench_verify_g1<E: Engine>(criterion: &mut Criterion, name: &str) {
        let id = format!("engine/{name}/verify_g1");
        for size in G1_SIZES {
            criterion.bench_with_input(
                BenchmarkId::new(id.clone(), size),
                &size,
                move |bencher, &size| {
                    bencher.iter_batched_ref(
                        || {
                            (
                                iter::repeat(rand_g1()).take(size).collect::<Vec<_>>(),
                                rand_g2(),
                            )
                        },
                        |(powers, tau)| E::verify_g1(powers, *tau),
                        BatchSize::LargeInput,
                    );
                },
            );
        }
    }

    fn bench_verify_g2<E: Engine>(criterion: &mut Criterion, name: &str) {
        let id = format!("engine/{name}/verify_g2");
        for size in G2_SIZES {
            criterion.bench_with_input(
                BenchmarkId::new(id.clone(), size),
                &size,
                move |bencher, &size| {
                    bencher.iter_batched_ref(
                        || {
                            (
                                iter::repeat(rand_g1()).take(size).collect::<Vec<_>>(),
                                iter::repeat(rand_g2()).take(size).collect::<Vec<_>>(),
                            )
                        },
                        |(g1, g2)| E::verify_g2(g1, g2),
                        BatchSize::LargeInput,
                    );
                },
            );
        }
    }

    fn bench_generate_tau<E: Engine>(criterion: &mut Criterion, name: &str) {
        let id = format!("engine/{name}/generate_tau");
        criterion.bench_function(&id, move |bencher| {
            bencher.iter_batched_ref(
                rand_entropy,
                |entropy| E::generate_tau(entropy),
                BatchSize::SmallInput,
            );
        });
    }

    fn bench_add_tau_g1<E: Engine>(criterion: &mut Criterion, name: &str) {
        let id = format!("engine/{name}/add_tau_g1");
        for size in G1_SIZES {
            criterion.bench_with_input(
                BenchmarkId::new(id.clone(), size),
                &size,
                move |bencher, &size| {
                    bencher.iter_batched_ref(
                        || {
                            (
                                rand_tau(),
                                iter::repeat(rand_g1()).take(size).collect::<Vec<_>>(),
                            )
                        },
                        |(tau, powers)| E::add_tau_g1(tau, powers).unwrap(),
                        BatchSize::LargeInput,
                    );
                },
            );
        }
    }

    fn bench_add_tau_g2<E: Engine>(criterion: &mut Criterion, name: &str) {
        let id = format!("engine/{name}/add_tau_g2");
        for size in G2_SIZES {
            criterion.bench_with_input(
                BenchmarkId::new(id.clone(), size),
                &size,
                move |bencher, &size| {
                    bencher.iter_batched_ref(
                        || {
                            (
                                rand_tau(),
                                iter::repeat(rand_g2()).take(size).collect::<Vec<_>>(),
                            )
                        },
                        |(tau, powers)| E::add_tau_g2(tau, powers).unwrap(),
                        BatchSize::LargeInput,
                    );
                },
            );
        }
    }
}
