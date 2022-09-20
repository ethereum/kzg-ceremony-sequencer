use crate::SharedTranscript;
use clap::Parser;
use serde::de::DeserializeOwned;
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Parser)]
pub struct Options {
    #[clap(long, env, default_value = "./transcript.json")]
    pub transcript_file: PathBuf,

    #[clap(long, env, default_value = "./transcript.json.next")]
    pub transcript_in_progress_file: PathBuf,
}

pub async fn read_transcript_file<T: DeserializeOwned + Send + 'static>(path: PathBuf) -> T {
    let handle = tokio::task::spawn_blocking::<_, T>(|| {
        let f = std::fs::File::open(path).expect("can't access transcript file.");
        let reader = std::io::BufReader::new(f);
        serde_json::from_reader::<_, T>(reader).expect("unreadable transcript")
    });
    handle.await.expect("can't read transcript")
}

pub async fn write_transcript_file<
    T: kzg_ceremony_crypto::interface::Transcript + Send + Sync + 'static,
>(
    options: Options,
    transcript: SharedTranscript<T>,
) {
    let handle = tokio::task::spawn_blocking(move || {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&options.transcript_in_progress_file)
            .expect("Can't access transcript file.");
        let transcript = transcript.blocking_read();
        serde_json::to_writer_pretty(&f, &*transcript).expect("Cannot write transcript");
        std::fs::rename(
            &options.transcript_in_progress_file,
            &options.transcript_file,
        )
        .unwrap();
    });
    handle.await.expect("Cannot write transcript");
}
