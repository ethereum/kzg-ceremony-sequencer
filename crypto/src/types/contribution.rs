use super::{powers_json::PowersJson, CeremonyError, G1, G2};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "ContributionJson", into = "ContributionJson")]
pub struct Contribution {
    pub pubkey:    G2,
    pub g1_powers: Vec<G1>,
    pub g2_powers: Vec<G2>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContributionJson {
    pot_pubkey: G2,

    #[serde(flatten)]
    powers: PowersJson,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct PowersOfTau {
    g1_powers: Vec<G1>,
    g2_powers: Vec<G2>,
}

impl From<Contribution> for ContributionJson {
    fn from(contribution: Contribution) -> Self {
        Self {
            powers:     (contribution.g1_powers, contribution.g2_powers).into(),
            pot_pubkey: contribution.pubkey,
        }
    }
}

impl TryFrom<ContributionJson> for Contribution {
    type Error = CeremonyError;

    fn try_from(value: ContributionJson) -> Result<Self, Self::Error> {
        let (g1_powers, g2_powers) = value.powers.try_into()?;
        Ok(Contribution {
            pubkey: value.pot_pubkey,
            g1_powers,
            g2_powers,
        })
    }
}
