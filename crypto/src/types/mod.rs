//! Contribution and Transaction types with serde support

mod contribution;
mod error;
mod group;
mod powers;
mod transcript;

pub use self::{
    contribution::Contribution,
    error::{CeremoniesError, CeremonyError},
    group::{G1, G2},
    powers::Powers,
    transcript::Transcript,
};
use crate::Engine;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchTranscript {
    pub transcripts: Vec<Transcript>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchContribution {
    pub contributions: Vec<Contribution>,
}

impl BatchTranscript {
    pub fn new<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (usize, usize)>,
    {
        Self {
            transcripts: iter
                .into_iter()
                .map(|(num_g1, num_g2)| Transcript::new(num_g1, num_g2))
                .collect(),
        }
    }

    /// Creates the start of a new batch contribution.
    #[must_use]
    pub fn contribution(&self) -> BatchContribution {
        BatchContribution {
            contributions: self.transcripts.iter().map(|t| t.contribution()).collect(),
        }
    }

    /// Adds a batch contribution to the transcript. The contribution must be
    /// valid.
    pub fn verify_add<E: Engine>(
        &mut self,
        contribution: BatchContribution,
    ) -> Result<(), CeremoniesError> {
        // Verify contributions
        if self.transcripts.len() != contribution.contributions.len() {
            return Err(CeremoniesError::UnexpectedNumContributions(
                self.transcripts.len(),
                contribution.contributions.len(),
            ));
        }
        for (i, (transcript, contribution)) in self
            .transcripts
            .iter_mut()
            .zip(&contribution.contributions)
            .enumerate()
        {
            transcript
                .verify::<E>(contribution)
                .map_err(|e| CeremoniesError::InvalidCeremony(i, e))?;
        }

        // Add contributions
        for (transcript, contribution) in self
            .transcripts
            .iter_mut()
            .zip(contribution.contributions.into_iter())
        {
            transcript.add(contribution);
        }

        Ok(())
    }
}
