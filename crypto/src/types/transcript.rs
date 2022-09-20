use super::{powers_json::PowersJson, CeremonyError, G1, G2};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "TranscriptJson", into = "TranscriptJson")]
pub struct Transcript {
    pub g1_powers: Vec<G1>,
    pub g2_powers: Vec<G2>,
    pub products:  Vec<G1>,
    pub pubkeys:   Vec<G2>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TranscriptJson {
    witness: WitnessJson,

    #[serde(flatten)]
    powers: PowersJson,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WitnessJson {
    running_products: Vec<G1>,
    pot_pubkeys:      Vec<G2>,
}

impl From<Transcript> for TranscriptJson {
    fn from(transcript: Transcript) -> Self {
        Self {
            witness: WitnessJson {
                pot_pubkeys:      transcript.pubkeys,
                running_products: transcript.products,
            },
            powers:  (transcript.g1_powers, transcript.g2_powers).into(),
        }
    }
}

impl TryFrom<TranscriptJson> for Transcript {
    type Error = CeremonyError;

    fn try_from(value: TranscriptJson) -> Result<Self, Self::Error> {
        let (g1_powers, g2_powers) = value.powers.try_into()?;
        Ok(Self {
            g1_powers,
            g2_powers,
            products: value.witness.running_products,
            pubkeys: value.witness.pot_pubkeys,
        })
    }
}

impl Transcript {
    #[must_use]
    pub fn new(num_g1: usize, num_g2: usize) -> Self {
        Self {
            pubkeys:   vec![G2::default()],
            products:  vec![G1::default()],
            g1_powers: vec![G1::default(); num_g1],
            g2_powers: vec![G2::default(); num_g2],
        }
    }
}
