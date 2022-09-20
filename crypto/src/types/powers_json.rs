use super::{CeremonyError, G1, G2};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PowersJson {
    num_g1_powers: usize,
    num_g2_powers: usize,
    powers_of_tau: PowersOfTau,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct PowersOfTau {
    g1_powers: Vec<G1>,
    g2_powers: Vec<G2>,
}

impl From<(Vec<G1>, Vec<G2>)> for PowersJson {
    fn from((g1_powers, g2_powers): (Vec<G1>, Vec<G2>)) -> Self {
        Self {
            num_g1_powers: g1_powers.len(),
            num_g2_powers: g2_powers.len(),
            powers_of_tau: PowersOfTau {
                g1_powers,
                g2_powers,
            },
        }
    }
}

impl TryFrom<PowersJson> for (Vec<G1>, Vec<G2>) {
    type Error = CeremonyError;

    fn try_from(value: PowersJson) -> Result<Self, Self::Error> {
        if value.powers_of_tau.g1_powers.len() != value.num_g1_powers {
            return Err(CeremonyError::InconsistentNumG1Powers(
                value.num_g1_powers,
                value.powers_of_tau.g1_powers.len(),
            ));
        }
        if value.powers_of_tau.g2_powers.len() != value.num_g2_powers {
            return Err(CeremonyError::InconsistentNumG2Powers(
                value.num_g2_powers,
                value.powers_of_tau.g2_powers.len(),
            ));
        }
        Ok((value.powers_of_tau.g1_powers, value.powers_of_tau.g2_powers))
    }
}
