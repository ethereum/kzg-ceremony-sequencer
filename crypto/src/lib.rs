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
    engine::{Engine, Entropy, Tau},
    error::{CeremoniesError, CeremonyError, ParseError},
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

    pub fn group(criterion: &mut Criterion) {
        engine::bench::group(criterion);
    }
}
