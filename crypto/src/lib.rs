#![doc = include_str!("../Readme.md")]
#![warn(clippy::all, clippy::pedantic, clippy::cargo, clippy::nursery)]
#![allow(clippy::cast_lossless, clippy::module_name_repetitions)]
#![cfg_attr(any(test, feature = "bench"), allow(clippy::wildcard_imports))]

mod batch_contribution;
mod batch_transcript;
mod contribution;
mod engine;
mod error;
mod group;
mod hex_format;
mod powers;
pub mod signature;
mod transcript;

pub use crate::{
    batch_contribution::BatchContribution,
    batch_transcript::BatchTranscript,
    contribution::Contribution,
    engine::{Engine, Entropy, Tau},
    error::{CeremoniesError, CeremonyError, ErrorCode, ParseError},
    group::{F, G1, G2},
    powers::Powers,
    transcript::Transcript,
};

pub use crate::engine::Both;

#[cfg(feature = "arkworks")]
pub use crate::engine::Arkworks;

#[cfg(feature = "blst")]
pub use crate::engine::BLST;

#[cfg(all(feature = "arkworks", feature = "blst"))]
pub type DefaultEngine = Both<Arkworks, BLST>;

#[cfg(all(feature = "arkworks", not(feature = "blst")))]
pub type DefaultEngine = Arkworks;

#[cfg(all(not(feature = "arkworks"), feature = "blst"))]
pub type DefaultEngine = BLST;

#[cfg(feature = "bench")]
#[doc(hidden)]
pub mod bench {
    use super::*;
    use criterion::Criterion;
    use rand::Rng;
    use secrecy::Secret;

    pub const BATCH_SIZE: [(usize, usize); 4] = [(4096, 65), (8192, 65), (16384, 65), (32768, 65)];

    pub fn group(criterion: &mut Criterion) {
        engine::bench::group(criterion);
        batch_contribution::bench::group(criterion);
        batch_transcript::bench::group(criterion);
    }

    #[must_use]
    pub fn rand_entropy() -> Entropy {
        let mut rng = rand::thread_rng();
        Secret::new(rng.gen())
    }

    #[must_use]
    pub fn rand_tau() -> Tau {
        Arkworks::generate_tau(&rand_entropy())
    }
}
