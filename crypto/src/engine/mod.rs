//! Abstraction over the backend used for cryptographic operations.
//!
//! # To do
//!
//! * Add support for BLST backend.
//! * Better API for passing entropy (`Secret<_>` etc.)

#![allow(clippy::missing_errors_doc)] // TODO

mod arkworks;

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
    use criterion::Criterion;

    pub fn group(criterion: &mut Criterion) {
        #[cfg(feature = "arkworks")]
        arkworks::bench::group(criterion);
    }

    pub(super) fn bench_engine<E: Engine>(_criterion: &mut Criterion) {
        // todo!()
    }

    // fn bench_pow_tau(criterion: &mut Criterion) {
    //     criterion.bench_function("contribution/pow_tau", move |bencher| {
    //         let mut rng = rand::thread_rng();
    //         let tau = Zeroizing::new(Fr::rand(&mut rng));
    //         bencher.iter(||
    // black_box(Contribution::pow_table(black_box(&tau), 32768)));     });
    // }

    // fn bench_add_tau(criterion: &mut Criterion) {
    //     for size in crate::SIZES {
    //         criterion.bench_with_input(
    //             BenchmarkId::new("contribution/add_tau", format!("{:?}",
    // size)),             &size,
    //             move |bencher, (n1, n2)| {
    //                 let mut contrib = Contribution::new(*n1, *n2);
    //                 bencher.iter_batched(
    //                     rand_fr,
    //                     |tau| contrib.add_tau(&tau),
    //                     BatchSize::SmallInput,
    //                 );
    //             },
    //         );
    //     }
    // }

    // fn bench_verify(criterion: &mut Criterion) {
    //     for size in crate::SIZES {
    //         criterion.bench_with_input(
    //             BenchmarkId::new("contribution/verify", format!("{:?}",
    // size)),             &size,
    //             move |bencher, (n1, n2)| {
    //                 let transcript = Transcript::new(*n1, *n2);
    //                 let mut contrib = Contribution::new(*n1, *n2);
    //                 contrib.add_tau(&rand_fr());
    //                 bencher.iter(|| black_box(contrib.verify(&transcript)));
    //             },
    //         );
    //     }
    // }
}
