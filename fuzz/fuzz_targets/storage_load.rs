#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use storage::{Filesystem, StorageError, Store};

struct FuzzFilesystem {
    files: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl FuzzFilesystem {
    fn new(files: BTreeMap<String, Vec<u8>>) -> Self {
        Self {
            files: Mutex::new(files),
        }
    }
}

impl Filesystem for FuzzFilesystem {
    fn read(&self, name: &str) -> Result<Vec<u8>, StorageError> {
        self.files
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or(StorageError::FileNotFound)
    }

    fn write_atomic(&self, name: &str, data: &[u8]) -> Result<(), StorageError> {
        self.files
            .lock()
            .unwrap()
            .insert(name.to_string(), data.to_vec());
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<(), StorageError> {
        if self.files.lock().unwrap().remove(name).is_some() {
            Ok(())
        } else {
            Err(StorageError::FileNotFound)
        }
    }

    fn list(&self) -> Result<Vec<String>, StorageError> {
        Ok(self.files.lock().unwrap().keys().cloned().collect())
    }
}

fuzz_target!(|data: &[u8]| {
    let mut files = BTreeMap::new();

    if !data.is_empty() {
        let sidecar_len = usize::from(data[0]) % data.len();
        let sidecar_end = 1 + sidecar_len.min(data.len().saturating_sub(1));
        files.insert(".peer-state.v1".to_string(), data[1..sidecar_end].to_vec());

        let remainder = &data[sidecar_end..];
        if !remainder.is_empty() {
            let name_len = remainder.len().min(content::CONTENT_ID_LEN);
            files.insert(hex::encode(&remainder[..name_len]), remainder.to_vec());
        }
    }

    let fs: Arc<dyn Filesystem> = Arc::new(FuzzFilesystem::new(files));
    let master = keys::derive_master_priv("fuzz-storage-load");
    let _ = Store::new_with_time_source(fs, &master, Arc::new(clock::SystemClock));
});
