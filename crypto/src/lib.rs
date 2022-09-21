#![doc = include_str!("../Readme.md")]
#![warn(clippy::all, clippy::pedantic, clippy::cargo, clippy::nursery)]
#![allow(clippy::cast_lossless, clippy::module_name_repetitions)]
#![cfg_attr(any(test, feature = "bench"), allow(clippy::wildcard_imports))]

mod batch;
mod contribution;
mod engine;
mod error;
mod group;
mod powers;
mod transcript;

pub use crate::{
    batch::{BatchContribution, BatchTranscript},
    contribution::Contribution,
    engine::Engine,
    error::{CeremoniesError, CeremonyError, ParseError},
    group::{G1, G2},
    powers::Powers,
    transcript::Transcript,
};

#[cfg(feature = "atkworks")]
pub use crate::engine::arkworks::Arkworks;

#[cfg(feature = "bench")]
#[doc(hidden)]
pub mod bench {
    use super::*;
    use criterion::Criterion;

    pub fn group(criterion: &mut Criterion) {
        engine::bench::group(criterion);
    }
}
