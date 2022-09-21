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
mod powers;
mod transcript;

pub use crate::{
    batch_contribution::BatchContribution,
    batch_transcript::BatchTranscript,
    contribution::Contribution,
    engine::Engine,
    error::{CeremoniesError, CeremonyError, ParseError},
    group::{G1, G2},
    powers::Powers,
    transcript::Transcript,
};

#[cfg(feature = "arkworks")]
pub use crate::engine::Arkworks;

#[cfg(feature = "bench")]
#[doc(hidden)]
pub mod bench {
    use super::*;
    use criterion::Criterion;

    pub fn group(criterion: &mut Criterion) {
        engine::bench::group(criterion);
    }
}
