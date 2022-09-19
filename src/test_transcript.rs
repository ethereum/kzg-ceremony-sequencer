#![cfg(test)]

use kzg_ceremony_crypto::interface::{Contribution, Transcript};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum TestContribution {
    ValidContribution(i64),
    InvalidContribution(i64),
}

impl Contribution for TestContribution {
    type Receipt = i64;

    fn get_receipt(&self) -> Self::Receipt {
        match self {
            Self::InvalidContribution(i) | Self::ValidContribution(i) => *i,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct TestTranscript {
    pub initial:       TestContribution,
    pub contributions: Vec<TestContribution>,
}

impl Default for TestTranscript {
    fn default() -> Self {
        Self {
            initial:       TestContribution::ValidContribution(0),
            contributions: vec![],
        }
    }
}

impl Transcript for TestTranscript {
    type ContributionType = TestContribution;
    type ValidationError = ();

    fn verify_contribution(&self, contribution: &TestContribution) -> Result<(), ()> {
        match contribution {
            TestContribution::ValidContribution(_) => Ok(()),
            TestContribution::InvalidContribution(_) => Err(()),
        }
    }

    fn update(&self, contribution: &TestContribution) -> Self {
        let mut new_contributions = self.contributions.clone();
        new_contributions.push(contribution.clone());
        Self {
            initial:       self.initial.clone(),
            contributions: new_contributions,
        }
    }

    fn get_contribution(&self) -> TestContribution {
        self.contributions.last().unwrap_or(&self.initial).clone()
    }
}
