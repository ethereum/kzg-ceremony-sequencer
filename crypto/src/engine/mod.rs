//! Abstraction over the backend used for cryptographic operations.
//!
//! # To do
//!
//! * Add support for BLST backend.
//! * Better API for passing entropy (`Secret<_>` etc.)

#![allow(clippy::missing_errors_doc)] // TODO

#[cfg(feature = "arkworks")]
mod arkworks;
#[cfg(feature = "blst")]
mod blst;

use crate::{CeremonyError, F, G1, G2};
use secrecy::Secret;

#[cfg(feature = "arkworks")]
pub use self::arkworks::Arkworks;
#[cfg(feature = "blst")]
pub use self::blst::BLST;

pub type Entropy = Secret<[u8; 32]>;
pub type Tau = Secret<F>;

pub trait Engine {
    /// Verifies that the given G1 points are valid.
    ///
    /// Valid mean that they are uniquely encoded in compressed ZCash format and
    /// represent curve points in the prime order subgroup.
    fn validate_g1(points: &[G1]) -> Result<(), CeremonyError>;

    /// Verifies that the given G2 points are valid.
    ///
    /// Valid mean that they are uniquely encoded in compressed ZCash format and
    /// represent curve points in the prime order subgroup.
    fn validate_g2(points: &[G2]) -> Result<(), CeremonyError>;

    /// Verify that the pubkey contains the contribution added
    /// from `previous` to `tau`.
    fn verify_pubkey(tau: G1, previous: G1, pubkey: G2) -> Result<(), CeremonyError>;

    /// Verify that `powers` contains a sequence of powers of `tau`.
    fn verify_g1(powers: &[G1], tau: G2) -> Result<(), CeremonyError>;

    /// Verify that `g1` and `g2` contain the same values.
    fn verify_g2(g1: &[G1], g2: &[G2]) -> Result<(), CeremonyError>;

    /// Derive a secret scalar $τ$ from the given entropy.
    fn generate_tau(entropy: &Entropy) -> Tau;

    /// Multiply elements of `powers` by powers of $τ$.
    fn add_tau_g1(tau: &Tau, powers: &mut [G1]) -> Result<(), CeremonyError>;

    /// Multiply elements of `powers` by powers of $τ$.
    fn add_tau_g2(tau: &Tau, powers: &mut [G2]) -> Result<(), CeremonyError>;
}

#[cfg(feature = "bench")]
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
        let id = format!("engine/{}/validate_g1", name);
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
        let id = format!("engine/{}/validate_g2", name);
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
        let id = format!("engine/{}/verify_pubkey", name);
        criterion.bench_function(&id, move |bencher| {
            bencher.iter_batched(
                || (rand_g1(), rand_g1(), rand_g2()),
                |(a, b, c)| E::verify_pubkey(a, b, c),
                BatchSize::SmallInput,
            );
        });
    }

    fn bench_verify_g1<E: Engine>(criterion: &mut Criterion, name: &str) {
        let id = format!("engine/{}/verify_g1", name);
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
        let id = format!("engine/{}/verify_g2", name);
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
        let id = format!("engine/{}/generate_tau", name);
        criterion.bench_function(&id, move |bencher| {
            bencher.iter_batched_ref(
                rand_entropy,
                |entropy| E::generate_tau(entropy),
                BatchSize::SmallInput,
            );
        });
    }

    fn bench_add_tau_g1<E: Engine>(criterion: &mut Criterion, name: &str) {
        let id = format!("engine/{}/add_tau_g1", name);
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
        let id = format!("engine/{}/add_tau_g2", name);
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

#[cfg(all(test, feature = "arkworks", feature = "blst"))]
mod tests {
    use super::*;
    use proptest::{proptest, strategy::Strategy};

    pub fn arb_f() -> impl Strategy<Value = F> {
        arkworks::test::arb_fr().prop_map(F::from)
    }

    pub fn arb_g1() -> impl Strategy<Value = G1> {
        arkworks::test::arb_g1().prop_map(G1::from)
    }

    pub fn arb_g2() -> impl Strategy<Value = G2> {
        arkworks::test::arb_g2().prop_map(G2::from)
    }

    #[test]
    fn test_add_tau_g1() {
        proptest!(|(tau in arb_f(), p in arb_g1())| {
            let tau = Secret::new(tau);
            let points1: &mut [G1] = &mut [p; 16];
            let points2: &mut [G1] = &mut [p; 16];

            BLST::add_tau_g1(&tau, points1).unwrap();
            Arkworks::add_tau_g1(&tau, points2).unwrap();

            assert_eq!(points1, points2);
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
}
