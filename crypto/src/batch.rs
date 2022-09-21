use crate::{CeremoniesError, Contribution, Engine, Transcript, G2};
use rand::{rngs::StdRng, Rng, SeedableRng};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::instrument;

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

impl BatchContribution {
    #[instrument(level = "info", skip_all, fields(n=self.contributions.len()))]
    pub fn receipt(&self) -> Vec<G2> {
        self.contributions.iter().map(|c| c.pubkey).collect()
    }

    #[instrument(level = "info", skip_all, fields(n=self.contributions.len()))]
    pub fn add_entropy<E: Engine>(&mut self, entropy: [u8; 32]) -> Result<(), CeremoniesError> {
        let entropies = derive_entropy(entropy, self.contributions.len());
        self.contributions
            .par_iter_mut()
            .zip(entropies)
            .enumerate()
            .try_for_each(|(i, (contribution, entropy))| {
                contribution
                    .add_entropy::<E>(entropy)
                    .map_err(|e| CeremoniesError::InvalidCeremony(i, e))
            })
    }
}

fn derive_entropy(entropy: [u8; 32], size: usize) -> Vec<[u8; 32]> {
    let mut rng = StdRng::from_seed(entropy);
    (0..size).map(|_| rng.gen()).collect()
}
