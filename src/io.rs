use crate::{Engine, SharedTranscript};
use eyre::eyre;
use kzg_ceremony_crypto::BatchTranscript;
use serde::{de::DeserializeOwned, Serialize};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Represents a size constraint on a batch transcript
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CeremonySizes {
    sizes: Vec<(usize, usize)>,
}

impl CeremonySizes {
    /// Parses a size constraint from command line format. The format accepted
    /// is a `:`-separated list of `,`-separated pairs denoting the expected
    /// number of, respectively, G1 and G2 points in consecutive ceremonies.
    /// For example, `1,2:3,4:5,6` denotes 3 ceremonies, the first containing
    /// 1 G1 point and 2 G2 points.
    ///
    /// # Errors
    ///
    /// Returns an error if there are no ceremonies specified, or if there is
    /// an parse error.
    pub fn parse_from_cmd(cmd: &str) -> eyre::Result<Self> {
        let ceremonies = cmd.split(':');
        let parsed_ceremonies: Vec<_> = ceremonies
            .map(|ceremony| {
                let parts = ceremony.split(',').collect::<Vec<_>>();
                if parts.len() == 2 {
                    Ok((parts[0].parse()?, parts[1].parse()?))
                } else {
                    Err(eyre!("Invalid ceremony sizes description {ceremony}"))
                }
            })
            .collect::<eyre::Result<_>>()?;
        if parsed_ceremonies.is_empty() {
            return Err(eyre!("Must specify at least one ceremony"));
        }
        Ok(Self {
            sizes: parsed_ceremonies,
        })
    }

    /// Validates a batch transcript against this shape description
    ///
    /// # Errors:
    /// - when the transcript does not conform to the required shape
    fn validate_batch_transcript(&self, transcript: &BatchTranscript) -> eyre::Result<()> {
        let defined_ceremonies = transcript.transcripts.len();
        let expected_ceremonies = self.sizes.len();
        if defined_ceremonies != expected_ceremonies {
            return Err(eyre!(
                "Wrong number of transcripts in the batch: expected {expected_ceremonies} but got \
                 {defined_ceremonies}."
            ));
        }
        self.sizes
            .iter()
            .enumerate()
            .zip(transcript.transcripts.iter())
            .try_for_each(|((i, (expected_num_g1, expected_num_g2)), transcript)| {
                let actual_num_g1 = &transcript.powers.g1.len();
                if actual_num_g1 != expected_num_g1 {
                    return Err(eyre!(
                        "Wrong number of G1 points in transcript #{i}: expected \
                         {expected_num_g1}, but got {actual_num_g1}"
                    ));
                }
                let actual_num_g2 = &transcript.powers.g2.len();
                if actual_num_g2 != expected_num_g2 {
                    return Err(eyre!(
                        "Wrong number of G2 points in transcript #{i}: expected \
                         {expected_num_g2}, but got {actual_num_g2}"
                    ));
                }
                Ok(())
            })?;
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum TranscriptIoError {
    #[error("Failed to access file {0}")]
    IoError(std::io::Error),
    #[error("Failed to marshall transcript {0}")]
    SerializationError(serde_json::Error),
    #[error("Task error {0}")]
    TaskError(tokio::task::JoinError),
}

/// Reads a transcript file from disk, or creates it, if it doesn't exist.
///
/// # Errors
///
/// - when the transcript exists, but does not conform to the required shape.
pub async fn read_or_create_transcript(
    path: PathBuf,
    work_path: PathBuf,
    ceremony_sizes: &CeremonySizes,
) -> eyre::Result<SharedTranscript> {
    if path.exists() {
        info!(?path, "Opening transcript file");
        let transcript = read_json_file::<BatchTranscript>(path).await?;
        ceremony_sizes.validate_batch_transcript(&transcript)?;
        let sizes = ceremony_sizes.sizes.clone();
        transcript.verify_self::<Engine>(sizes)?;
        Ok(Arc::new(RwLock::new(transcript)))
    } else {
        warn!(?path, "No transcript found, creating new transcript file");
        let transcript = BatchTranscript::new(&ceremony_sizes.sizes);
        let shared_transcript = Arc::new(RwLock::new(transcript));
        write_json_file(path, work_path, shared_transcript.clone()).await?;
        Ok(shared_transcript)
    }
}

/// Asynchronously reads a JSON file from disk.
///
/// # Errors
/// If the file does not exist, or if it does not contain correct transcript
/// data.
pub async fn read_json_file<T: DeserializeOwned + Send + 'static>(
    path: PathBuf,
) -> Result<T, TranscriptIoError> {
    let handle = tokio::task::spawn_blocking(|| {
        let f = std::fs::File::open(path).map_err(TranscriptIoError::IoError)?;
        let reader = std::io::BufReader::new(f);
        serde_json::from_reader::<_, T>(reader).map_err(TranscriptIoError::SerializationError)
    });
    handle.await.map_err(TranscriptIoError::TaskError)?
}

/// Asynchroniously writes a JSON file to disk using a tempfile.
///
/// # Errors
/// If either file cannot be written.
pub async fn write_json_file<T: Serialize + Send + Sync + 'static>(
    target_path: PathBuf,
    work_path: PathBuf,
    data: Arc<RwLock<T>>,
) -> Result<(), TranscriptIoError> {
    let handle = tokio::task::spawn_blocking(move || {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&work_path)
            .map_err(TranscriptIoError::IoError)?;
        let guard = data.blocking_read();
        serde_json::to_writer_pretty(&f, &*guard).map_err(TranscriptIoError::SerializationError)?;
        std::fs::rename(&work_path, &target_path).map_err(TranscriptIoError::IoError)?;
        Ok(())
    });
    handle.await.map_err(TranscriptIoError::TaskError)?
}
