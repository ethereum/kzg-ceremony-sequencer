use crate::{CeremoniesError, Contribution, Engine, G2};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use zeroize::Zeroize;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchContribution {
    pub contributions: Vec<Contribution>,
}

impl BatchContribution {
    #[instrument(level = "info", skip_all, fields(n=self.contributions.len()))]
    pub fn receipt(&self) -> Vec<G2> {
        self.contributions.iter().map(|c| c.pot_pubkey).collect()
    }

    #[instrument(level = "info", skip_all, fields(n=self.contributions.len()))]
    pub fn add_entropy<E: Engine>(&mut self, mut entropy: [u8; 32]) -> Result<(), CeremoniesError> {
        // make sure that the entropy passed in is not prior zeroized
        assert_ne!(entropy, [0; 32]);

        let mut entropies = derive_entropy(entropy, self.contributions.len());
        let res = self
            .contributions
            .par_iter_mut()
            .zip(&mut entropies)
            .enumerate()
            .try_for_each(|(i, (contribution, entropy))| {
                let res = contribution
                    .add_entropy::<E>(entropy)
                    .map_err(|e| CeremoniesError::InvalidCeremony(i, e));
                // make sure the entropy has been zeroized
                assert_eq!(*entropy, [0; 32]);
                res
            });

        // zeroize the toxic waste
        entropy.zeroize();
        res
    }

    // TODO: Sanity check the batch contribution. Besides checking the individual
    // contributions, we should also check that there are no repeated values between
    // contributions. This prevents problems where a participant contributes the
    // same tau value for each contribution.
}

fn derive_entropy(entropy: [u8; 32], size: usize) -> Vec<[u8; 32]> {
    let mut rng = ChaCha20Rng::from_seed(entropy);
    (0..size).map(|_| rng.gen()).collect()
}
