use crate::{BatchContribution, CeremoniesError, Engine, Transcript};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::instrument;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchTranscript {
    pub transcripts: Vec<Transcript>,
}

impl BatchTranscript {
    pub fn new<'a, I>(iter: I) -> Self
    where
        I: IntoIterator<Item = &'a (usize, usize)> + 'a,
    {
        Self {
            transcripts: iter
                .into_iter()
                .map(|(num_g1, num_g2)| Transcript::new(*num_g1, *num_g2))
                .collect(),
        }
    }

    /// Creates the start of a new batch contribution.
    #[must_use]
    pub fn contribution(&self) -> BatchContribution {
        BatchContribution {
            contributions: self
                .transcripts
                .iter()
                .map(Transcript::contribution)
                .collect(),
        }
    }

    /// Adds a batch contribution to the transcript. The contribution must be
    /// valid.
    #[instrument(level = "info", skip_all, fields(n=contribution.contributions.len()))]
    pub fn verify_add<E: Engine>(
        &mut self,
        contribution: BatchContribution,
    ) -> Result<(), CeremoniesError> {
        // Verify contribution count
        if self.transcripts.len() != contribution.contributions.len() {
            return Err(CeremoniesError::UnexpectedNumContributions(
                self.transcripts.len(),
                contribution.contributions.len(),
            ));
        }

        // Verify contributions in parallel
        self.transcripts
            .par_iter_mut()
            .zip(&contribution.contributions)
            .enumerate()
            .try_for_each(|(i, (transcript, contribution))| {
                transcript
                    .verify::<E>(contribution)
                    .map_err(|e| CeremoniesError::InvalidCeremony(i, e))
            })?;

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
