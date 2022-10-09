use crate::{CeremoniesError, Contribution, Engine, Entropy, Tau, G2};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use secrecy::{ExposeSecret, Secret};
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
        self.contributions.iter().map(|c| c.pot_pubkey).collect()
    }

    #[instrument(level = "info", skip_all, fields(n=self.contributions.len()))]
    pub fn add_entropy<E: Engine>(&mut self, entropy: &Entropy) -> Result<(), CeremoniesError> {
        let mut taus = derive_taus::<E>(entropy, self.contributions.len());
        let res = self
            .contributions
            .par_iter_mut()
            .zip(&mut taus)
            .enumerate()
            .try_for_each(|(i, (contribution, tau))| {
                contribution
                    .add_tau::<E>(tau)
                    .map_err(|e| CeremoniesError::InvalidCeremony(i, e))
            });
        res
    }

    // TODO: Sanity check the batch contribution. Besides checking the individual
    // contributions, we should also check that there are no repeated values between
    // contributions. This prevents problems where a participant contributes the
    // same tau value for each contribution.
}

fn derive_taus<E: Engine>(entropy: &Entropy, size: usize) -> Vec<Tau> {
    // TODO: ChaCha20Rng does not implement Zeroize.
    let mut rng = ChaCha20Rng::from_seed(*entropy.expose_secret());

    (0..size)
        .map(|_| {
            let entropy = Secret::new(rng.gen());
            E::generate_tau(&entropy)
        })
        .collect()
}
