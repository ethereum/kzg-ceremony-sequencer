use super::{CeremonyError, Contribution, Powers, G1, G2};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Transcript {
    #[serde(flatten)]
    pub powers: Powers,

    pub witness: Witness,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
pub struct Witness {
    #[serde(rename = "runningProducts")]
    pub products: Vec<G1>,

    #[serde(rename = "potPubkeys")]
    pub pubkeys: Vec<G2>,
}

impl Transcript {
    #[must_use]
    pub fn new(num_g1: usize, num_g2: usize) -> Self {
        Self {
            powers:  Powers::new(num_g1, num_g2),
            witness: Witness::default(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn transcript_json() {
        let t = Transcript::new(2, 4);
        let json = serde_json::to_value(&t).unwrap();
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
            "witness": {
                "runningProducts": [],
                "potPubkeys": []
            }
            })
        );
        let deser = serde_json::from_value::<Transcript>(json).unwrap();
        assert_eq!(deser, t);
    }
}
