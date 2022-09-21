use std::path::PathBuf;
use serde::de::DeserializeOwned;
use crate::SharedTranscript;

pub async fn read_json_file<T: DeserializeOwned + Send + 'static>(path: PathBuf) -> T {
    let handle = tokio::task::spawn_blocking::<_, T>(|| {
        let f = std::fs::File::open(path).expect("can't access transcript file.");
        let reader = std::io::BufReader::new(f);
        serde_json::from_reader::<_, T>(reader).expect("unreadable transcript")
    });
    handle.await.expect("can't read transcript")
}

pub async fn write_transcript_file(
    target_path: PathBuf,
    work_path: PathBuf,
    transcript: SharedTranscript,
) {
    let handle = tokio::task::spawn_blocking(move || {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&work_path)
            .expect("Can't access transcript file.");
        let transcript = transcript.blocking_read();
        serde_json::to_writer_pretty(&f, &*transcript).expect("Cannot write transcript");
        std::fs::rename(&work_path, &target_path).unwrap();
    });
    handle.await.expect("Cannot write transcript");
}
