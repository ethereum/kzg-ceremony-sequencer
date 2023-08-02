use super::{CeremonyError, Contribution, Powers, G1, G2};
use crate::{engine::Engine, signature::BlsSignature};
use serde::{Deserialize, Serialize};
use rayon::iter::{ParallelIterator, IntoParallelRefIterator, IndexedParallelIterator};
use tracing::instrument;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Transcript {
    #[serde(flatten)]
    pub powers: Powers,

    pub witness: Witness,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Witness {
    #[serde(rename = "runningProducts")]
    pub products: Vec<G1>,

    #[serde(rename = "potPubkeys")]
    pub pubkeys: Vec<G2>,

    #[serde(rename = "blsSignatures")]
    pub signatures: Vec<BlsSignature>,
}

impl Transcript {
    /// Create a new transcript for a ceremony of a given size.
    ///
    /// # Panics
    ///
    /// There must be at least two g1 and two g2 points, and there must be at
    /// least as many g1 as g2 points.
    #[must_use]
    pub fn new(num_g1: usize, num_g2: usize) -> Self {
        assert!(num_g1 >= 2);
        assert!(num_g2 >= 2);
        assert!(num_g1 >= num_g2);
        Self {
            powers:  Powers::new(num_g1, num_g2),
            witness: Witness {
                products:   vec![G1::one()],
                pubkeys:    vec![G2::one()],
                signatures: vec![BlsSignature::empty()],
            },
        }
    }

    /// Returns the number of participants that contributed to this transcript.
    #[must_use]
    pub fn num_participants(&self) -> usize {
        self.witness.pubkeys.len() - 1
    }

    /// True if there is at least one contribution.
    #[must_use]
    pub fn has_entropy(&self) -> bool {
        self.num_participants() > 0
    }

    /// Creates the start of a new contribution.
    #[must_use]
    pub fn contribution(&self) -> Contribution {
        Contribution {
            powers:        self.powers.clone(),
            pot_pubkey:    G2::one(),
            bls_signature: BlsSignature::empty(),
        }
    }

    // Verifies that it is a valid transcript itself
    pub fn verify_self<E: Engine>(
        &self,
        num_g1: usize,
        num_g2: usize,
    ) -> Result<(), CeremonyError> {
        // Sanity checks on provided num_g1 and num_g2
        assert!(num_g1 >= 2);
        assert!(num_g2 >= 2);
        assert!(num_g1 >= num_g2);

        // Num powers checks
        // Note: num_g1_powers and num_g2_powers checked in TryFrom<PowersJson>
        if num_g1 != self.powers.g1.len() {
            return Err(CeremonyError::UnexpectedNumG1Powers(
                num_g1,
                self.powers.g1.len(),
            ));
        }
        if num_g2 != self.powers.g2.len() {
            return Err(CeremonyError::UnexpectedNumG2Powers(
                num_g2,
                self.powers.g2.len(),
            ));
        }

        // Sanity checks on num pubkeys & products
        if self.witness.products.len() != self.witness.pubkeys.len() {
            return Err(CeremonyError::WitnessLengthMismatch(
                self.witness.products.len(),
                self.witness.pubkeys.len(),
            ));
        }

        // Point sanity checks (encoding and subgroup checks).
        E::validate_g1(&self.powers.g1)?;
        E::validate_g2(&self.powers.g2)?;
        E::validate_g1(&self.witness.products)?;
        E::validate_g2(&self.witness.pubkeys)?;

        // Non-zero checks
        if self
            .witness
            .pubkeys
            .par_iter()
            .any(|pubkey| *pubkey == G2::zero())
        {
            return Err(CeremonyError::ZeroPubkey);
        }

        // Pairing check all pubkeys
        // TODO: figure out how to do this with some kind of batched pairings
        if self
            .witness
            .products
            .par_iter()
            .enumerate()
            .filter(|(i, _)| i >=  &self.witness.products.len())
            .any(|(i, product)|
                E::verify_pubkey(
                    *product,
                    self.witness.products[i - 1],
                    self.witness.pubkeys[i],
                ).is_err()
            )
        {
            return Err(CeremonyError::PubKeyPairingFailed);
        }

        // Verify powers match final witness product
        if self.powers.g1[1] != self.witness.products[self.witness.products.len() - 1] {
            return Err(CeremonyError::G1ProductMismatch);
        }

        // Verify powers are correctly constructed
        E::verify_g1(&self.powers.g1, self.powers.g2[1])?;
        E::verify_g2(&self.powers.g1[..self.powers.g2.len()], &self.powers.g2)?;

        Ok(())
    }

    /// Verifies a contribution.
    #[instrument(level = "info", skip_all, fields(n1=self.powers.g1.len(), n2=self.powers.g2.len()))]
    pub fn verify_contribution<E: Engine>(
        &self,
        contribution: &Contribution,
    ) -> Result<(), CeremonyError> {
        // Compatibility checks
        if self.powers.g1.len() != contribution.powers.g1.len() {
            return Err(CeremonyError::UnexpectedNumG1Powers(
                self.powers.g1.len(),
                contribution.powers.g1.len(),
            ));
        }
        if self.powers.g2.len() != contribution.powers.g2.len() {
            return Err(CeremonyError::UnexpectedNumG2Powers(
                self.powers.g2.len(),
                contribution.powers.g2.len(),
            ));
        }

        // Verify the contribution points (encoding and subgroup checks).
        E::validate_g1(&contribution.powers.g1)?;
        E::validate_g2(&contribution.powers.g2)?;
        E::validate_g2(&[contribution.pot_pubkey])?;

        // Non-zero check
        if contribution.pot_pubkey == G2::zero() {
            return Err(CeremonyError::ZeroPubkey);
        }

        // Verify pairings.
        E::verify_pubkey(
            contribution.powers.g1[1],
            self.powers.g1[1],
            contribution.pot_pubkey,
        )?;
        E::verify_g1(&contribution.powers.g1, contribution.powers.g2[1])?;
        E::verify_g2(
            &contribution.powers.g1[..contribution.powers.g2.len()],
            &contribution.powers.g2,
        )?;

        // Accept
        Ok(())
    }

    /// Adds a contribution to the transcript. The contribution must be
    /// verified.
    pub fn add(&mut self, contribution: Contribution) {
        self.witness.products.push(contribution.powers.g1[1]);
        self.witness.pubkeys.push(contribution.pot_pubkey);
        self.witness.signatures.push(contribution.bls_signature);
        self.powers = contribution.powers;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        CeremonyError::{
            G1PairingFailed, G2PairingFailed, InvalidG1Power, InvalidG2Power, PubKeyPairingFailed,
            UnexpectedNumG1Powers, UnexpectedNumG2Powers,
        },
        DefaultEngine,
        ParseError::InvalidSubgroup,
    };
    use ark_bls12_381::{Fr, G1Affine, G2Affine};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use hex_literal::hex;

    #[test]
    fn transcript_json() {
        let t = Transcript::new(4, 2);
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
            "numG1Powers": 4,
            "numG2Powers": 2,
            "powersOfTau": {
                "G1Powers": [
                "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
                "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
                "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
                "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
                ],
                "G2Powers": [
                "0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
                "0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
                ],
            },
            "witness": {
                "runningProducts": [
                    "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
                ],
                "potPubkeys": [
                    "0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
                ],
                "blsSignatures": [""],
            }
            })
        );
        let deser = serde_json::from_value::<Transcript>(json).unwrap();
        assert_eq!(deser, t);
    }

    #[test]
    fn test_verify_g1_not_in_subgroup() {
        let transcript = Transcript::new(2, 2);
        let point_not_in_g1 = G1(hex!("800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
        let bad_g1_contribution = Contribution {
            powers:        Powers {
                g1: vec![point_not_in_g1, point_not_in_g1],
                g2: vec![G2::zero(), G2::zero()],
            },
            pot_pubkey:    G2::zero(),
            bls_signature: BlsSignature::empty(),
        };
        let result = transcript
            .verify_contribution::<DefaultEngine>(&bad_g1_contribution)
            .err()
            .unwrap();
        assert!(matches!(result, InvalidG1Power(_, InvalidSubgroup)));
    }

    #[test]
    fn test_verify_g2_not_in_subgroup() {
        let transcript = Transcript::new(2, 2);
        let point_not_in_g2 = G2(hex!("a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002"));

        let bad_g2_contribution = Contribution {
            powers:        Powers {
                g1: vec![G1::zero(), G1::zero()],
                g2: vec![point_not_in_g2, point_not_in_g2],
            },
            pot_pubkey:    G2::zero(),
            bls_signature: BlsSignature::empty(),
        };
        let result = transcript
            .verify_contribution::<DefaultEngine>(&bad_g2_contribution)
            .err()
            .unwrap();
        assert!(matches!(result, InvalidG2Power(_, InvalidSubgroup)));
    }

    #[test]
    fn test_verify_wrong_pubkey() {
        let transcript = Transcript::new(2, 2);

        let secret = Fr::from(42);
        let bad_secret = Fr::from(43);
        let g1_gen = G1::from(G1Affine::prime_subgroup_generator());
        let g1_elem = G1::from(
            G1Affine::prime_subgroup_generator()
                .mul(secret)
                .into_affine(),
        );
        let g2_gen = G2::from(G2Affine::prime_subgroup_generator());
        let g2_elem = G2::from(
            G2Affine::prime_subgroup_generator()
                .mul(secret)
                .into_affine(),
        );
        let pubkey = G2::from(
            G2Affine::prime_subgroup_generator()
                .mul(bad_secret)
                .into_affine(),
        );
        let bad_pot_pubkey = Contribution {
            powers:        Powers {
                g1: vec![g1_gen, g1_elem],
                g2: vec![g2_gen, g2_elem],
            },
            pot_pubkey:    pubkey,
            bls_signature: BlsSignature::empty(),
        };
        assert_eq!(
            transcript
                .verify_contribution::<DefaultEngine>(&bad_pot_pubkey)
                .err()
                .unwrap(),
            PubKeyPairingFailed
        );
    }

    #[test]
    fn test_verify_wrong_g1_powers() {
        let transcript = Transcript::new(3, 2);
        let g1_1 = G1Affine::prime_subgroup_generator();
        let g1_2 = G1Affine::prime_subgroup_generator()
            .mul(Fr::from(2))
            .into_affine();
        let g1_3 = G1Affine::prime_subgroup_generator()
            .mul(Fr::from(3))
            .into_affine();
        let g2_1 = G2Affine::prime_subgroup_generator();
        let g2_2 = G2Affine::prime_subgroup_generator()
            .mul(Fr::from(2))
            .into_affine();
        let contribution = Contribution {
            powers:        Powers {
                // Pretend Tau is 2, but make the third element g1^3 instead of g1^4.
                g1: vec![G1::from(g1_1), G1::from(g1_2), G1::from(g1_3)],
                g2: vec![G2::from(g2_1), G2::from(g2_2)],
            },
            pot_pubkey:    G2::from(g2_2),
            bls_signature: BlsSignature::empty(),
        };
        assert_eq!(
            transcript
                .verify_contribution::<DefaultEngine>(&contribution)
                .err()
                .unwrap(),
            G1PairingFailed
        );
    }

    #[test]
    fn test_verify_wrong_g2_powers() {
        let transcript = Transcript::new(3, 3);
        let g1_1 = G1Affine::prime_subgroup_generator();
        let g1_2 = G1Affine::prime_subgroup_generator()
            .mul(Fr::from(2))
            .into_affine();
        let g1_4 = G1Affine::prime_subgroup_generator()
            .mul(Fr::from(4))
            .into_affine();
        let g2_1 = G2Affine::prime_subgroup_generator();
        let g2_2 = G2Affine::prime_subgroup_generator()
            .mul(Fr::from(2))
            .into_affine();
        let g2_3 = G2Affine::prime_subgroup_generator()
            .mul(Fr::from(3))
            .into_affine();
        let contribution = Contribution {
            powers:        Powers {
                g1: vec![G1::from(g1_1), G1::from(g1_2), G1::from(g1_4)],
                // Pretend Tau is 2, but make the third element g2^3 instead of g2^4.
                g2: vec![G2::from(g2_1), G2::from(g2_2), G2::from(g2_3)],
            },
            pot_pubkey:    G2::from(g2_2),
            bls_signature: BlsSignature::empty(),
        };
        assert_eq!(
            transcript
                .verify_contribution::<DefaultEngine>(&contribution)
                .err()
                .unwrap(),
            G2PairingFailed
        );
    }

    #[test]
    fn test_verify_wrong_g1_point_count() {
        let transcript = Transcript::new(3, 3);
        let mut contribution = transcript.contribution();
        contribution.powers.g1 = contribution.powers.g1[0..2].to_vec();
        let result = transcript
            .verify_contribution::<DefaultEngine>(&contribution)
            .err()
            .unwrap();
        assert_eq!(result, UnexpectedNumG1Powers(3, 2));
    }

    #[test]
    fn test_verify_wrong_g2_point_count() {
        let transcript = Transcript::new(3, 3);
        let mut contribution = transcript.contribution();
        contribution.powers.g2 = contribution.powers.g2[0..2].to_vec();
        let result = transcript
            .verify_contribution::<DefaultEngine>(&contribution)
            .err()
            .unwrap();
        assert_eq!(result, UnexpectedNumG2Powers(3, 2));
    }
}
