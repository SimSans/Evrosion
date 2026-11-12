use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

pub struct TempDirectory(pub PathBuf);

impl TempDirectory {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ev host tests {} {} with spaces",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("create isolated fixture directory");
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
