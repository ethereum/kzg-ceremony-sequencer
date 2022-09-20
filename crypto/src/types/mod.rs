mod contribution;
mod error;
mod transcript;
mod utils;

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
