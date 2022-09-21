use crate::{CeremonyError, Engine, Powers, G2};
use serde::{Deserialize, Serialize};
use tracing::instrument;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Contribution {
    #[serde(flatten)]
    pub powers: Powers,

    pub pubkey: G2,
}

impl Contribution {
    #[instrument(level = "info", skip_all, , fields(n1=self.powers.g1.len(), n2=self.powers.g2.len()))]
    pub fn add_entropy<E: Engine>(&mut self, entropy: [u8; 32]) -> Result<(), CeremonyError> {
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
