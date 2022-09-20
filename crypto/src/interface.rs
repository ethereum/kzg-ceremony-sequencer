use core::result::Result;
use serde::{de::DeserializeOwned, ser::Serialize};

pub trait Contribution: Serialize + DeserializeOwned {
    type Receipt: Serialize;

    fn get_receipt(&self) -> Self::Receipt;
}

pub trait Transcript: Serialize + DeserializeOwned {
    type ContributionType: Contribution;
    type ValidationError: Serialize;

    /// # Errors
    ///
    /// When validation fails.
    fn verify_contribution(
        &self,
        contribution: &Self::ContributionType,
    ) -> Result<(), Self::ValidationError>;

    #[must_use]
    fn update(&self, contribution: &Self::ContributionType) -> Self;

    fn get_contribution(&self) -> Self::ContributionType;
}
