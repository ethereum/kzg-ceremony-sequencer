//! Abstraction over the backend used for cryptographic operations.
//!
//! # To do
//!
//! * Add support for BLST backend.
//! * Better API for passing entropy (`Secret<_>` etc.)

#![allow(clippy::missing_errors_doc)] // TODO

mod arkworks;
mod blst;

use crate::{CeremonyError, G1, G2};

#[cfg(feature = "arkworks")]
pub use self::arkworks::Arkworks;

pub trait Engine {
    /// Verifies that the given G1 points are valid.
    fn validate_g1(points: &[G1]) -> Result<(), CeremonyError>;

    /// Verifies that the given G2 points are valid.
    fn validate_g2(points: &[G2]) -> Result<(), CeremonyError>;

    /// Verify that the pubkey contains the contribution added
    /// from `previous` to `tau`.
    fn verify_pubkey(tau: G1, previous: G1, pubkey: G2) -> Result<(), CeremonyError>;

    /// Verify that `powers` contains a sequence of powers of `tau`.
    fn verify_g1(powers: &[G1], tau: G2) -> Result<(), CeremonyError>;

    /// Verify that `g1` and `g2` contain the same values.
    fn verify_g2(g1: &[G1], g2: &[G2]) -> Result<(), CeremonyError>;

    fn add_entropy_g1(entropy: [u8; 32], powers: &mut [G1]) -> Result<(), CeremonyError>;

    fn add_entropy_g2(entropy: [u8; 32], powers: &mut [G2]) -> Result<(), CeremonyError>;
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
    }

    pub(super) fn bench_engine<E: Engine>(criterion: &mut Criterion, name: &str) {
        bench_validate_g1::<E>(criterion, name);
        bench_validate_g2::<E>(criterion, name);
        bench_verify_pubkey::<E>(criterion, name);
        bench_verify_g1::<E>(criterion, name);
        bench_verify_g2::<E>(criterion, name);
        bench_add_entropy_g1::<E>(criterion, name);
        bench_add_entropy_g2::<E>(criterion, name);
    }

    const G1_SIZES: [usize; 5] = [1, 4096, 8192, 16384, 32768];
    const G2_SIZES: [usize; 2] = [1, 65];

    fn rand_g1() -> G1 {
        arkworks::bench::rand_g1().into()
    }

    fn rand_g2() -> G2 {
        arkworks::bench::rand_g2().into()
    }

    fn rand_entropy() -> [u8; 32] {
        let mut rng = rand::thread_rng();
        rng.gen()
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
                        |points| E::validate_g1(&points).unwrap(),
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
                        |points| E::validate_g2(&points).unwrap(),
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

    fn bench_add_entropy_g1<E: Engine>(criterion: &mut Criterion, name: &str) {
        let id = format!("engine/{}/add_entropy_g1", name);
        for size in G1_SIZES {
            criterion.bench_with_input(
                BenchmarkId::new(id.clone(), size),
                &size,
                move |bencher, &size| {
                    bencher.iter_batched_ref(
                        || {
                            (
                                rand_entropy(),
                                iter::repeat(rand_g1()).take(size).collect::<Vec<_>>(),
                            )
                        },
                        |(entropy, powers)| E::add_entropy_g1(*entropy, powers).unwrap(),
                        BatchSize::LargeInput,
                    );
                },
            );
        }
    }

    fn bench_add_entropy_g2<E: Engine>(criterion: &mut Criterion, name: &str) {
        let id = format!("engine/{}/add_entropy_g2", name);
        for size in G2_SIZES {
            criterion.bench_with_input(
                BenchmarkId::new(id.clone(), size),
                &size,
                move |bencher, &size| {
                    bencher.iter_batched_ref(
                        || {
                            (
                                rand_entropy(),
                                iter::repeat(rand_g2()).take(size).collect::<Vec<_>>(),
                            )
                        },
                        |(entropy, powers)| E::add_entropy_g2(*entropy, powers).unwrap(),
                        BatchSize::LargeInput,
                    );
                },
            );
        }
    }
}

mod tests {
    use super::{*, blst::BLST};

    #[test]
    fn test_g1() {
        let g_e1 = &mut [G1::one(), G1::one(), G1::one()];
        let g_e2 = &mut [G1::one(), G1::one(), G1::one()];
        
        BLST::add_entropy_g1([0; 32], g_e1).unwrap();
        Arkworks::add_entropy_g1([0; 32], g_e2).unwrap();

        assert_eq!(g_e1, g_e2);
    }

    #[test]
    fn test_g2() {
        let g_e1 = &mut [G2::one(), G2::one(), G2::one()];
        let g_e2 = &mut [G2::one(), G2::one(), G2::one()];
        
        BLST::add_entropy_g2([0; 32], g_e1).unwrap();
        Arkworks::add_entropy_g2([0; 32], g_e2).unwrap();

        assert_eq!(g_e1, g_e2);
    }
}



