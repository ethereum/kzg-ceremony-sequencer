use crate::{CeremonyError, Engine, Powers, G1, G2};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::instrument;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Contribution {
    #[serde(flatten)]
    pub powers: Powers,

    pub pubkey: G2,
}

impl Contribution {
    /// Check if the contribution has any entropy added.
    #[must_use]
    pub fn has_entropy(&self) -> bool {
        self.pubkey != G2::one()
    }

    /// Adds entropy to this contribution. Can be called multiple times.
    #[instrument(level = "info", skip_all, , fields(n1=self.powers.g1.len(), n2=self.powers.g2.len()))]
    pub fn add_entropy<E: Engine>(&mut self, entropy: [u8; 32]) -> Result<(), CeremonyError> {
        // Basic checks
        self.sanity_check()?;

        // Validate points
        E::validate_g1(&self.powers.g1)?;
        E::validate_g2(&self.powers.g2)?;
        E::validate_g2(&[self.pubkey])?;

        // Add entropy
        E::add_entropy_g1(entropy, &mut self.powers.g1)?;
        E::add_entropy_g2(entropy, &mut self.powers.g2)?;
        let mut temp = [G2::zero(), self.pubkey];
        E::add_entropy_g2(entropy, &mut temp)?;
        self.pubkey = temp[1];

        Ok(())
    }

    /// Sanity checks based on equality constraints and zero/one values.
    ///
    /// Note that these checks require the point encoding to be a bijection.
    /// This must be checked by the cryptographic [`Engine`].
    #[instrument(level = "info", skip_all, , fields(n1=self.powers.g1.len(), n2=self.powers.g2.len()))]
    pub fn sanity_check(&self) -> Result<(), CeremonyError> {
        // Check that the number of powers is sensible
        if self.powers.g1.len() < 2 {
            return Err(CeremonyError::UnsupportedNumG1Powers(self.powers.g1.len()));
        }
        if self.powers.g2.len() < 2 {
            return Err(CeremonyError::UnsupportedNumG2Powers(self.powers.g2.len()));
        }

        // Zero values are never allowed
        if self.pubkey == G2::zero() {
            return Err(CeremonyError::ZeroPubkey);
        }
        for (i, g1) in self.powers.g1.iter().enumerate() {
            if *g1 == G1::zero() {
                return Err(CeremonyError::ZeroG1(i));
            }
        }
        for (i, g2) in self.powers.g2.iter().enumerate() {
            if *g2 == G2::zero() {
                return Err(CeremonyError::ZeroG2(i));
            }
        }

        // First values must be the generator
        if self.powers.g1[0] != G1::one() {
            return Err(CeremonyError::InvalidG1FirstValue);
        }
        if self.powers.g2[0] != G2::one() {
            return Err(CeremonyError::InvalidG2FirstValue);
        }

        // If there is no entropy yet, all values must be one.
        if self.pubkey == G2::one()
            && self.powers.g1.iter().all(|g1| *g1 == G1::one())
            && self.powers.g2.iter().all(|g2| *g2 == G2::one())
        {
            return Ok(());
        }

        // All g1 values must be unique
        let mut set = HashMap::<G1, usize>::new();
        for (i, g1) in self.powers.g1.iter().enumerate().skip(1) {
            if *g1 == G1::one() {
                return Err(CeremonyError::InvalidG1One(i));
            }
            if let Some(j) = set.get(g1) {
                return Err(CeremonyError::DuplicateG1(*j, i));
            }
            set.insert(*g1, i);
        }

        // All g2 values must be unique, but if this is the first contribution, g2[1]
        // may match pubkey.
        let mut set = HashMap::<G2, usize>::new();
        for (i, g2) in self.powers.g2.iter().enumerate().skip(1) {
            if *g2 == G2::one() {
                return Err(CeremonyError::InvalidG2One(i));
            }
            if i > 1 && *g2 == self.pubkey {
                return Err(CeremonyError::InvalidG2Pubkey(i));
            }
            if let Some(j) = set.get(g2) {
                return Err(CeremonyError::DuplicateG2(*j, i));
            }
            set.insert(*g2, i);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn contribution_json() {
        let value = Contribution {
            powers: Powers::new(2, 4),
            pubkey: G2::one(),
        };
        let json = serde_json::to_value(&value).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
            "numG1Powers": 2,
            "numG2Powers": 4,
            "powersOfTau": {
                "G1Powers": [
                "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
                "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
                ],
                "G2Powers": [
                "0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
                "0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
                "0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
                "0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
                ]
            },
            "pubkey": "0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
            })
        );
        let deser = serde_json::from_value::<Contribution>(json).unwrap();
        assert_eq!(deser, value);
    }
}

#[cfg(feature = "bench")]
#[doc(hidden)]
pub mod bench {
    use crate::{Arkworks, Transcript};
    use criterion::{BatchSize, Criterion};
    use rand::Rng;

    pub fn group(criterion: &mut Criterion) {
        bench_sanity_check(criterion);
    }

    fn bench_sanity_check(criterion: &mut Criterion) {
        criterion.bench_function("contribution/sanity_check", |b| {
            let mut rng = rand::thread_rng();
            let transcript = Transcript::new(32768, 65);
            b.iter_batched_ref(
                || {
                    let mut contribution = transcript.contribution();
                    contribution.add_entropy::<Arkworks>(rng.gen()).unwrap();
                    contribution
                },
                |contribution| contribution.sanity_check().unwrap(),
                BatchSize::LargeInput,
            );
        });
    }
}
