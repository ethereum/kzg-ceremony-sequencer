//! Contribution and Transaction types with serde support

mod contribution;
mod error;
mod group;
mod powers;
mod transcript;

use serde::{Deserialize, Serialize};

pub use self::{
    contribution::Contribution,
    error::{CeremoniesError, CeremonyError},
    group::{G1, G2},
    powers::Powers,
    transcript::Transcript,
};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchContribution {
    pub contributions: Vec<Contribution>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchTranscript {
    pub transcripts: Vec<Transcript>,
}
