use core::result::Result;
use std::path::{Path, PathBuf};

use crate::SharedTranscript;
use serde::{de::DeserializeOwned, ser::Serialize};

pub trait Contribution: Serialize + DeserializeOwned {
    type Receipt: Serialize;
    fn get_receipt(&self) -> Self::Receipt;
}

pub trait Transcript: Serialize + DeserializeOwned {
    type ContributionType: Contribution;
    type ValidationError: Serialize;

    fn verify_contribution(
        &self,
        contribution: &Self::ContributionType,
    ) -> Result<(), Self::ValidationError>;

    fn update(&self, contribution: &Self::ContributionType) -> Self;

    fn get_contribution(&self) -> Self::ContributionType;
}

pub async fn read_trancscript_file<T: DeserializeOwned + Send + 'static>(path: PathBuf) -> T {
    let handle = tokio::task::spawn_blocking::<_, T>(|| {
        let f = std::fs::File::open(path).expect("can't access transcript file.");
        let reader = std::io::BufReader::new(f);
        serde_json::from_reader::<_, T>(reader).expect("unreadable transcript")
    });
    handle.await.expect("can't read transcript")
}

pub async fn write_transcript_file<T: Transcript + Send + Sync + 'static>(
    path: PathBuf,
    transcript: SharedTranscript<T>,
) {
    let handle = tokio::task::spawn_blocking(move || {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("Can't access transcript file.");
        let transcript = transcript.blocking_read();
        serde_json::to_writer_pretty(&f, &*transcript).expect("Cannot write transcript");
    });
    handle.await.expect("Cannot write transcript");
}
