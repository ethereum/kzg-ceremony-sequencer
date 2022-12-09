use super::{CeremonyError, G1, G2};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "PowersJson", into = "PowersJson")]
pub struct Powers {
    pub g1: Vec<G1>,
    pub g2: Vec<G2>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PowersJson {
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

impl From<Powers> for PowersJson {
    fn from(powers: Powers) -> Self {
        Self {
            num_g1_powers: powers.g1.len(),
            num_g2_powers: powers.g2.len(),
            powers_of_tau: PowersOfTau {
                g1_powers: powers.g1,
                g2_powers: powers.g2,
            },
        }
    }
}

impl TryFrom<PowersJson> for Powers {
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
        Ok(Self {
            g1: value.powers_of_tau.g1_powers,
            g2: value.powers_of_tau.g2_powers,
        })
    }
}

impl Powers {
    /// Construct a new `Powers` object initialized to identity elements.
    #[must_use]
    pub fn new(num_g1: usize, num_g2: usize) -> Self {
        Self {
            g1: vec![G1::one(); num_g1],
            g2: vec![G2::one(); num_g2],
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn test_invalid_powers_json() {
        let g1 = "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let g2 = "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let wrong_number_g1_powers = json!({
            "numG1Powers": 1,
            "numG2Powers": 1,
            "powersOfTau": {
                "G1Powers": [g1, g1],
                "G2Powers": [g2],
            },
        });
        let result = serde_json::from_value::<super::Powers>(wrong_number_g1_powers)
            .err()
            .unwrap();
        assert!(format!("{}", result).contains("Inconsistent number of G1 powers"));

        let wrong_number_g2_powers = json!({
            "numG1Powers": 1,
            "numG2Powers": 1,
            "powersOfTau": {
                "G1Powers": [g1],
                "G2Powers": [g2, g2],
            },
        });
        let result = serde_json::from_value::<super::Powers>(wrong_number_g2_powers)
            .err()
            .unwrap();
        assert!(format!("{}", result).contains("Inconsistent number of G2 powers"));
    }
}
