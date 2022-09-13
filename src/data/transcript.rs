use core::result::Result;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::path::Path;

pub trait Contribution: Serialize + DeserializeOwned {
    type Receipt: Serialize;
    fn get_receipt(&self) -> Self::Receipt;
}

pub trait Transcript {
    type ContributionType: Contribution;
    type ValidationError: Serialize;

    fn verify_contribution(
        &self,
        contribution: &Self::ContributionType,
    ) -> Result<(), Self::ValidationError>;

    fn update(&self, contribution: &Self::ContributionType) -> Self;

    fn get_contribution(&self) -> Self::ContributionType;
}

pub async fn read_trancscript_file<T: Transcript>(path: &Path) -> Result<T, std::io::Error> {
    let f = tokio::fs::File::open(path).await?;
    let reader = tokio::io::BufReader::new(f);
    serde_json::from_reader(reader);
    Ok(todo!())
}
