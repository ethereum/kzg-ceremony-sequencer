mod contribution;
mod error;
mod group;
mod transcript;
mod utils;

use crate::zcash_format::write_g;
use serde::{Deserialize, Serialize};

pub use self::{
    contribution::Contribution,
    error::{CeremoniesError, CeremonyError},
    transcript::Transcript,
};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchContribution {
    pub sub_contributions: Vec<Contribution>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchTranscript {
    pub sub_transcripts: Vec<Transcript>,
}

impl crate::interface::Contribution for BatchContribution {
    type Receipt = Vec<String>;

    fn get_receipt(&self) -> Self::Receipt {
        self.sub_contributions
            .iter()
            .map(|c| write_g(&c.pubkey))
            .collect()
    }
}

impl crate::interface::Transcript for BatchTranscript {
    type ContributionType = BatchContribution;
    type ValidationError = ();

    fn verify_contribution(
        &self,
        contribution: &Self::ContributionType,
    ) -> Result<(), Self::ValidationError> {
        if contribution.sub_contributions.len() != self.sub_transcripts.len() {
            return Err(());
        }

        let any_subgroup_check_failed = contribution
            .sub_contributions
            .iter()
            .any(|c| !Contribution::subgroup_check(c));
        if any_subgroup_check_failed {
            return Err(());
        }

        let any_verification_failed = contribution
            .sub_contributions
            .iter()
            .zip(self.sub_transcripts.iter())
            .any(|(contrib, transcript)| !contrib.verify(transcript));
        if any_verification_failed {
            return Err(());
        }
        Ok(())
    }

    fn update(&self, contribution: &Self::ContributionType) -> Self {
        let sub_transcripts = self
            .sub_transcripts
            .iter()
            .zip(contribution.sub_contributions.iter())
            .map(|(t, c)| {
                let g1_powers = c.g1_powers.clone();
                let g2_powers = c.g2_powers.clone();
                let mut products = t.products.clone();
                products.push(
                    *c.g1_powers
                        .get(1)
                        .expect("Impossible, contribution is checked valid"),
                );
                let mut pubkeys = t.pubkeys.clone();
                pubkeys.push(c.pubkey);
                Transcript {
                    g1_powers,
                    g2_powers,
                    products,
                    pubkeys,
                }
            })
            .collect();
        Self { sub_transcripts }
    }

    fn get_contribution(&self) -> Self::ContributionType {
        BatchContribution {
            sub_contributions: self
                .sub_transcripts
                .iter()
                .map(|st| Contribution {
                    g1_powers: st.g1_powers.clone(),
                    g2_powers: st.g2_powers.clone(),
                    pubkey:    *st
                        .pubkeys
                        .last()
                        .expect("Impossible: invalid initial transcript"),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;

    #[test]
    fn verify() {
        let transcript = Transcript::new(32768, 65);
        let mut contrib = Contribution::new(32768, 65);
        assert!(contrib.verify(&transcript));
        let mut rng = rand::thread_rng();
        contrib.add_tau(&Fr::rand(&mut rng));
        assert!(contrib.verify(&transcript));
    }
}

#[cfg(feature = "bench")]
#[doc(hidden)]
pub mod bench {
    use super::*;
    use criterion::Criterion;

    pub fn group(criterion: &mut Criterion) {
        contribution::bench::group(criterion);
    }
}
