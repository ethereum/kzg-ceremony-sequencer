use super::{
    utils::read_vector_of_points, CeremoniesError, CeremonyError, Contribution, SubContribution,
};
use crate::zcash_format::write_g;
use ark_bls12_381::{G1Affine, G2Affine};
use ark_ec::AffineCurve;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct SubTranscript {
    pub g1_powers: Vec<G1Affine>,
    pub g2_powers: Vec<G2Affine>,
    pub products:  Vec<G1Affine>,
    pub pubkeys:   Vec<G2Affine>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubTranscriptJson {
    pub num_g1_powers: usize,
    pub num_g2_powers: usize,
    pub powers_of_tau: PowersOfTau,
    pub witness:       WitnessJson,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessJson {
    pub running_products: Vec<String>,
    pub pot_pubkeys:      Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(into = "TranscriptJson")]
#[serde(try_from = "TranscriptJson")]
pub struct Transcript {
    pub sub_transcripts: Vec<SubTranscript>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[allow(clippy::module_name_repetitions)]
#[serde(rename_all = "camelCase")]
pub struct TranscriptJson {
    pub sub_transcripts: Vec<SubTranscriptJson>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PowersOfTau {
    pub g1_powers: Vec<String>,
    pub g2_powers: Vec<String>,
}

impl TryFrom<TranscriptJson> for Transcript {
    type Error = CeremoniesError;

    fn try_from(value: TranscriptJson) -> Result<Self, Self::Error> {
        let sub_transcripts: Vec<_> = value
            .sub_transcripts
            .into_iter()
            .enumerate()
            .map(|(i, trans)| {
                SubTranscript::try_from(trans).map_err(|e| CeremoniesError::InvalidCeremony(i, e))
            })
            .collect::<Result<Vec<_>, CeremoniesError>>()?;
        Ok(Self { sub_transcripts })
    }
}

impl From<Transcript> for TranscriptJson {
    fn from(transcripts: Transcript) -> Self {
        Self {
            sub_transcripts: transcripts
                .sub_transcripts
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

impl From<SubTranscript> for SubTranscriptJson {
    fn from(transcript: SubTranscript) -> Self {
        let powers_of_tau = PowersOfTau {
            g1_powers: transcript.g1_powers.par_iter().map(write_g).collect(),
            g2_powers: transcript.g2_powers.par_iter().map(write_g).collect(),
        };
        let witness = WitnessJson {
            pot_pubkeys:      transcript.pubkeys.par_iter().map(write_g).collect(),
            running_products: transcript.pubkeys.par_iter().map(write_g).collect(),
        };
        Self {
            num_g1_powers: transcript.g1_powers.len(),
            num_g2_powers: transcript.g2_powers.len(),
            powers_of_tau,
            witness,
        }
    }
}

impl TryFrom<SubTranscriptJson> for SubTranscript {
    type Error = CeremonyError;

    fn try_from(value: SubTranscriptJson) -> Result<Self, Self::Error> {
        let g1_powers = read_vector_of_points(
            &value.powers_of_tau.g1_powers,
            CeremonyError::InvalidG1Power,
        )?;
        let g2_powers = read_vector_of_points(
            &value.powers_of_tau.g2_powers,
            CeremonyError::InvalidG2Power,
        )?;
        let products = read_vector_of_points(
            &value.witness.running_products,
            CeremonyError::InvalidWitnessProduct,
        )?;
        let pubkeys = read_vector_of_points(
            &value.witness.pot_pubkeys,
            CeremonyError::InvalidWitnessPubKey,
        )?;
        Ok(Self {
            g1_powers,
            g2_powers,
            products,
            pubkeys,
        })
    }
}

impl SubTranscript {
    #[must_use]
    pub fn new(num_g1: usize, num_g2: usize) -> Self {
        Self {
            pubkeys:   vec![G2Affine::prime_subgroup_generator()],
            products:  vec![G1Affine::prime_subgroup_generator()],
            g1_powers: vec![G1Affine::prime_subgroup_generator(); num_g1],
            g2_powers: vec![G2Affine::prime_subgroup_generator(); num_g2],
        }
    }
}

impl crate::interface::Transcript for Transcript {
    type ContributionType = Contribution;
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
            .any(|c| !SubContribution::subgroup_check(c));
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
                SubTranscript {
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
        Contribution {
            sub_contributions: self
                .sub_transcripts
                .iter()
                .map(|st| SubContribution {
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
    use ark_ff::UniformRand;

    use super::*;

    #[test]
    fn verify() {
        let mut transcript = SubTranscript::new(32768, 65);
        let mut contrib = SubContribution::new(32768, 65);
        assert!(contrib.verify(&transcript));
        let mut rng = rand::thread_rng();
        contrib.add_tau(&Fr::rand(&mut rng));
        assert!(contrib.verify(&transcript));
    }
}

#[cfg(feature = "bench")]
#[doc(hidden)]
pub mod bench {
    use ark_ff::UniformRand;
    use criterion::{black_box, BatchSize, BenchmarkId, Criterion};

    use crate::bench::rand_fr;

    use super::*;

    pub fn group(criterion: &mut Criterion) {
        bench_pow_tau(criterion);
        bench_add_tau(criterion);
        bench_verify(criterion);
    }

    fn bench_pow_tau(criterion: &mut Criterion) {
        criterion.bench_function("contribution/pow_tau", move |bencher| {
            let mut rng = rand::thread_rng();
            let tau = Zeroizing::new(Fr::rand(&mut rng));
            bencher.iter(|| black_box(SubContribution::pow_table(black_box(&tau), 32768)));
        });
    }

    fn bench_add_tau(criterion: &mut Criterion) {
        for size in crate::SIZES {
            criterion.bench_with_input(
                BenchmarkId::new("contribution/add_tau", format!("{:?}", size)),
                &size,
                move |bencher, (n1, n2)| {
                    let mut contrib = SubContribution::new(*n1, *n2);
                    bencher.iter_batched(
                        || rand_fr(),
                        |tau| contrib.add_tau(&tau),
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }

    fn bench_verify(criterion: &mut Criterion) {
        for size in crate::SIZES {
            criterion.bench_with_input(
                BenchmarkId::new("contribution/verify", format!("{:?}", size)),
                &size,
                move |bencher, (n1, n2)| {
                    let mut transcript = SubTranscript::new(*n1, *n2);
                    let mut contrib = SubContribution::new(*n1, *n2);
                    contrib.add_tau(&rand_fr());
                    bencher.iter(|| black_box(contrib.verify(&transcript)));
                },
            );
        }
    }
}
