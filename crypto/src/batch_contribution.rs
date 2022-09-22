use crate::{CeremoniesError, Contribution, Engine, G2};
use rand::{rngs::StdRng, Rng, SeedableRng};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::instrument;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchContribution {
    pub contributions: Vec<Contribution>,
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

    // TODO: Sanity check the batch contribution. Besides checking the individual
    // contributions, we should also check that there are no repeated values between
    // contributions. This prevents problems where a participant contributes the same
    // tau value for each contribution.

}

fn derive_entropy(entropy: [u8; 32], size: usize) -> Vec<[u8; 32]> {
    let mut rng = StdRng::from_seed(entropy);
    (0..size).map(|_| rng.gen()).collect()
}
