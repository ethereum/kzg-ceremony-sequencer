use super::{
    utils::read_vector_of_points, BatchContribution, CeremoniesError, CeremonyError, Contribution,
};
use crate::zcash_format::write_g;
use ark_bls12_381::{G1Affine, G2Affine};
use ark_ec::AffineCurve;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "TranscriptJson", into = "TranscriptJson")]
#[allow(clippy::module_name_repetitions)]
pub struct Transcript {
    pub g1_powers: Vec<G1Affine>,
    pub g2_powers: Vec<G2Affine>,
    pub products:  Vec<G1Affine>,
    pub pubkeys:   Vec<G2Affine>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TranscriptJson {
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
#[serde(rename_all = "PascalCase")]
pub struct PowersOfTau {
    pub g1_powers: Vec<String>,
    pub g2_powers: Vec<String>,
}

impl From<Transcript> for TranscriptJson {
    fn from(transcript: Transcript) -> Self {
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

impl TryFrom<TranscriptJson> for Transcript {
    type Error = CeremonyError;

    fn try_from(value: TranscriptJson) -> Result<Self, Self::Error> {
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

impl Transcript {
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
