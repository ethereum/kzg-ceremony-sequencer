use crate::{
    signature::{identity::Identity, EcdsaSignature},
    CeremoniesError, Contribution, Engine, Entropy, Tau, G2,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use tracing::instrument;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BatchContribution {
    pub contributions:   Vec<Contribution>,
    pub ecdsa_signature: EcdsaSignature,
}

impl BatchContribution {
    #[instrument(level = "info", skip_all, fields(n=self.contributions.len()))]
    pub fn receipt(&self) -> Vec<G2> {
        self.contributions.iter().map(|c| c.pot_pubkey).collect()
    }

    #[instrument(level = "info", skip_all, fields(n=self.contributions.len()))]
    pub fn add_entropy<E: Engine>(
        &mut self,
        entropy: &Entropy,
        identity: &Identity,
    ) -> Result<(), CeremoniesError> {
        let taus = derive_taus::<E>(entropy, self.contributions.len());
        let res = self
            .contributions
            .par_iter_mut()
            .zip(&taus)
            .enumerate()
            .try_for_each(|(i, (contribution, tau))| {
                contribution
                    .add_tau::<E>(tau, identity)
                    .map_err(|e| CeremoniesError::InvalidCeremony(i, e))
            });
        res
    }

    #[instrument(level = "info", skip_all, fields(n=self.contributions.len()))]
    pub fn validate<E: Engine>(&mut self) -> Result<(), CeremoniesError> {
        let res =
            self.contributions
                .par_iter_mut()
                .enumerate()
                .try_for_each(|(i, contribution)| {
                    contribution
                        .validate::<E>()
                        .map_err(|e| CeremoniesError::InvalidCeremony(i, e))
                });
        res
    }
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

#[must_use]
pub fn get_pot_pubkeys<E: Engine>(entropy: &Entropy) -> Vec<G2> {
    let taus = derive_taus::<E>(entropy, 4);
    let result: Vec<G2> = taus
        .into_par_iter()
        .map(|tau| {
            let mut temp = [G2::one(), G2::one()];
            E::add_tau_g2(&tau, &mut temp).unwrap();
            temp[1]
        })
        .collect();
    result
}

#[cfg(test)]
pub mod tests {
    use crate::{
        batch_contribution::derive_taus,
        contribution::test::{invalid_g2_contribution, valid_contribution},
        engine::tests::arb_entropy,
        get_pot_pubkeys,
        signature::EcdsaSignature,
        BatchContribution, CeremoniesError, DefaultEngine, G2,
    };
    use ark_bls12_381::{Fr, G2Affine};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use proptest::proptest;
    use secrecy::{ExposeSecret, Secret};

    #[test]
    fn test_validate() {
        let mut invalid = BatchContribution {
            contributions:   vec![
                valid_contribution(),
                invalid_g2_contribution(),
                valid_contribution(),
            ],
            ecdsa_signature: EcdsaSignature::empty(),
        };
        assert!(matches!(
            invalid.validate::<DefaultEngine>(),
            Err(CeremoniesError::InvalidCeremony(1, _))
        ));

        let mut valid = BatchContribution {
            contributions:   vec![valid_contribution(), valid_contribution()],
            ecdsa_signature: EcdsaSignature::empty(),
        };
        assert!(valid.validate::<DefaultEngine>().is_ok());
    }

    #[test]
    fn test_get_pot_pubkeys() {
        proptest!(|(entropy in arb_entropy())| {
            let secret = Secret::new(entropy);
            let result = get_pot_pubkeys::<DefaultEngine>(&secret);
            let taus = derive_taus::<DefaultEngine>(&secret, 4)
                .into_iter()
                .map(|tau| tau.expose_secret().clone())
                .collect::<Vec<_>>();
            let expected: Vec<_> = taus
                .into_iter()
                .map(|tau| {
                    let fr = Fr::from(&tau);
                    let g2 = G2Affine::prime_subgroup_generator()
                        .mul(fr)
                        .into_affine();
                    G2::from(g2)
                })
                .collect();
            assert_eq!(result, expected);
        })
    }
}

#[cfg(feature = "bench")]
#[cfg(not(tarpaulin_include))]
#[doc(hidden)]
pub mod bench {
    use super::*;
    use crate::{
        bench::{rand_entropy, BATCH_SIZE},
        signature::identity::Identity,
        Arkworks, BatchTranscript, Both, BLST,
    };
    use criterion::{BatchSize, Criterion};

    pub fn group(criterion: &mut Criterion) {
        #[cfg(feature = "arkworks")]
        bench_add_tau::<Arkworks>(criterion, "arkworks");
        #[cfg(feature = "blst")]
        bench_add_tau::<BLST>(criterion, "blst");
        #[cfg(all(feature = "arkworks", feature = "blst"))]
        bench_add_tau::<Both<Arkworks, BLST>>(criterion, "both");
    }

    fn bench_add_tau<E: Engine>(criterion: &mut Criterion, name: &str) {
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
            &format!("batch_contribution/{name}/add_tau"),
            move |bencher| {
                bencher.iter_batched(
                    || (transcript.contribution(), rand_entropy()),
                    |(mut contribution, entropy)| {
                        contribution
                            .add_entropy::<E>(&entropy, &Identity::None)
                            .unwrap();
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
}
