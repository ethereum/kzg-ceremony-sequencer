use crate::test_transcript::TestContribution::ValidContribution;
use crate::Transcript;
use serde::{Deserialize, Serialize};
use crate::data::transcript::Contribution;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TestContribution {
    ValidContribution(i64),
    InvalidContribution(i64),
}

impl Contribution for TestContribution {
    type Receipt = i64;

    fn get_receipt(&self) -> Self::Receipt {
        match self {
            TestContribution::ValidContribution(i) => *i,
            TestContribution::InvalidContribution(i) => *i,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TestTranscript {
    initial: TestContribution,
    contributions: Vec<TestContribution>,
}

impl Default for TestTranscript {
    fn default() -> Self {
        TestTranscript {
            initial: ValidContribution(0),
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
        let mut new_contributions = self.contributions.to_vec();
        new_contributions.push(contribution.clone());
        TestTranscript {
            initial: self.initial.clone(),
            contributions: new_contributions,
        }
    }

    fn get_contribution(&self) -> TestContribution {
        self.contributions.last().unwrap_or(&self.initial).clone()
    }
}
