// TODO: Error handling

use serde::{de::DeserializeOwned, Serialize};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::RwLock;

/// Asynchronously reads a JSON file from disk.
pub async fn read_json_file<T: DeserializeOwned + Send + 'static>(path: PathBuf) -> T {
    let handle = tokio::task::spawn_blocking::<_, T>(|| {
        let f = std::fs::File::open(path).expect("can't access transcript file.");
        let reader = std::io::BufReader::new(f);
        serde_json::from_reader::<_, T>(reader).expect("unreadable transcript")
    });
    handle.await.expect("can't read transcript")
}

/// Asynchroniously writes a JSON file to disk using a tempfile.
pub async fn write_json_file<T: Serialize + Send + Sync + 'static>(
    target_path: PathBuf,
    work_path: PathBuf,
    data: Arc<RwLock<T>>,
) {
    let handle = tokio::task::spawn_blocking(move || {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&work_path)
            .expect("Can't access work file.");
        let guard = data.blocking_read();
        serde_json::to_writer_pretty(&f, &*guard).expect("Cannot write transcript");
        std::fs::rename(&work_path, &target_path).unwrap();
    });
    handle.await.expect("Cannot write transcript");
}
