use crate::{
    signature::{identity::Identity, ContributionTypedData, EcdsaSignature},
    BatchContribution, CeremoniesError, Engine, Transcript,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::instrument;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BatchTranscript {
    pub transcripts:                  Vec<Transcript>,
    pub participant_ids:              Vec<Identity>,
    pub participant_ecdsa_signatures: Vec<EcdsaSignature>,
}

impl BatchTranscript {
    pub fn new<'a, I>(iter: I) -> Self
    where
        I: IntoIterator<Item = &'a (usize, usize)> + 'a,
    {
        Self {
            transcripts:                  iter
                .into_iter()
                .map(|(num_g1, num_g2)| Transcript::new(*num_g1, *num_g2))
                .collect(),
            participant_ids:              vec![Identity::None],
            participant_ecdsa_signatures: vec![EcdsaSignature::empty()],
        }
    }

    /// Returns the number of participants that contributed to this transcript.
    #[must_use]
    pub fn num_participants(&self) -> usize {
        self.participant_ids.len() - 1
    }

    /// Creates the start of a new batch contribution.
    #[must_use]
    pub fn contribution(&self) -> BatchContribution {
        BatchContribution {
            contributions:   self
                .transcripts
                .iter()
                .map(Transcript::contribution)
                .collect(),
            ecdsa_signature: EcdsaSignature::empty(),
        }
    }

    /// Adds a batch contribution to the transcript. The contribution must be
    /// valid.
    #[instrument(level = "info", skip_all, fields(n=contribution.contributions.len()))]
    pub fn verify_add<E: Engine>(
        &mut self,
        mut contribution: BatchContribution,
        identity: Identity,
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
                    .verify_contribution::<E>(contribution)
                    .map_err(|e| CeremoniesError::InvalidCeremony(i, e))
            })?;

        self.participant_ecdsa_signatures.push(
            contribution
                .ecdsa_signature
                .prune(&identity, &ContributionTypedData::from(&contribution)),
        );

        // Prune BLS Signatures
        contribution.contributions.iter_mut().for_each(|c| {
            c.bls_signature = c
                .bls_signature
                .prune::<E>(identity.to_string().as_bytes(), c.pot_pubkey);
        });

        // Add contributions
        for (transcript, contribution) in self
            .transcripts
            .iter_mut()
            .zip(contribution.contributions.into_iter())
        {
            transcript.add(contribution);
        }

        self.participant_ids.push(identity);

        Ok(())
    }

    // Verifies an entire batch transcript (including all pairing checks)
    // given a vector of expected (num_g1, num_g2) points
    #[instrument(level = "info", skip_all, fields(n=self.transcripts.len()))]
    pub fn verify_self<E: Engine>(
        &self,
        sizes: Vec<(usize, usize)>,
    ) -> Result<(), CeremoniesError> {
        // Verify transcripts in parallel
        self.transcripts
            .par_iter()
            .zip(&sizes)
            .enumerate()
            .try_for_each(|(i, (transcript, (num_g1, num_g2)))| {
                transcript
                    .verify_self::<E>(*num_g1, *num_g2)
                    .map_err(|e| CeremoniesError::InvalidCeremony(i, e))
            })?;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{
        BatchTranscript, CeremoniesError::UnexpectedNumContributions, DefaultEngine, Identity,
    };

    #[test]
    fn test_verify_add() {
        let mut transcript = BatchTranscript::new([(2, 2), (3, 3)].iter());
        let mut contrib = transcript.contribution();
        contrib.contributions = contrib.contributions[0..1].to_vec();
        let result = transcript
            .verify_add::<DefaultEngine>(contrib, Identity::None)
            .err()
            .unwrap();
        assert_eq!(result, UnexpectedNumContributions(2, 1));
    }
}

#[cfg(feature = "bench")]
#[cfg(not(tarpaulin_include))]
#[doc(hidden)]
pub mod bench {
    use super::*;
    use crate::{
        bench::{rand_entropy, BATCH_SIZE},
        Arkworks, Both, BLST,
    };
    use criterion::{BatchSize, Criterion};

    pub fn group(criterion: &mut Criterion) {
        #[cfg(feature = "arkworks")]
        bench_verify_add::<Arkworks>(criterion, "arkworks");
        #[cfg(feature = "blst")]
        bench_verify_add::<BLST>(criterion, "blst");
        #[cfg(all(feature = "arkworks", feature = "blst"))]
        bench_verify_add::<Both<Arkworks, BLST>>(criterion, "both");
    }

    fn bench_verify_add<E: Engine>(criterion: &mut Criterion, name: &str) {
        // Create a non-trivial transcript
        let transcript = {
            let mut transcript = BatchTranscript::new(BATCH_SIZE.iter());
            let mut contribution = transcript.contribution();
            contribution
                .add_entropy::<E>(&rand_entropy(), &Identity::None)
                .unwrap();
            transcript
                .verify_add::<E>(contribution, Identity::None)
                .unwrap();
            transcript
        };

        criterion.bench_function(
            &format!("batch_transcript/{name}/verify_add"),
            move |bencher| {
                bencher.iter_batched(
                    || {
                        (transcript.clone(), {
                            let mut contribution = transcript.contribution();
                            contribution
                                .add_entropy::<E>(&rand_entropy(), &Identity::None)
                                .unwrap();
                            contribution
                        })
                    },
                    |(mut transcript, contribution)| {
                        transcript
                            .verify_add::<E>(contribution, Identity::None)
                            .unwrap();
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
}
