//! Crash-safe file replacement, shared by the auth state and the UI settings.

use ring::rand::{SecureRandom, SystemRandom};
use std::io::Write;
use std::path::Path;

#[derive(Debug, PartialEq)]
pub enum SaveOutcome {
    Durable,
    /// The new file replaced the old one, but the directory entry may not
    /// have reached the disk yet.
    DirectoryNotSynced,
}

/// Returns 32 random lowercase hex characters, for file names that a
/// restart or a crash leftover cannot collide with.
pub fn random_hex() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "cannot generate a random file name".to_string())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Replaces `path` with `bytes`. The data goes to a new private file next to
/// it, which is synced and then renamed over `path`, so a reader sees either
/// the old or the new content. Error messages hold no file content.
pub fn replace_file(path: &Path, bytes: &[u8]) -> Result<SaveOutcome, String> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(parent).map_err(|e| format!("cannot create data dir: {e}"))?;
    let mut temp = path.as_os_str().to_owned();
    temp.push(format!(".{}.tmp", random_hex()?));
    let temp = Path::new(&temp);
    let mut file =
        create_private_file(temp).map_err(|e| format!("cannot create temporary file: {e}"))?;
    let result = file
        .write_all(bytes)
        .map_err(|e| format!("cannot write temporary file: {e}"))
        .and_then(|()| {
            file.sync_all()
                .map_err(|e| format!("cannot sync temporary file: {e}"))
        })
        .and_then(|()| {
            std::fs::rename(temp, path).map_err(|e| format!("cannot replace file: {e}"))
        });
    drop(file);
    if let Err(error) = result {
        let _ = std::fs::remove_file(temp);
        return Err(error);
    }
    // The rename only survives a power loss once the directory is synced.
    // The new file is already in place if this fails, so the save counts.
    match std::fs::File::open(parent).and_then(|dir| dir.sync_all()) {
        Ok(()) => Ok(SaveOutcome::Durable),
        Err(_) => Ok(SaveOutcome::DirectoryNotSynced),
    }
}

/// Deletes the temporary files `replace_file` leaves next to `path` when a
/// crash interrupts a save. They can hold a full copy of the saved data.
pub fn remove_temp_files(path: &Path) {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let entry_name = entry.file_name();
        let id = entry_name
            .to_str()
            .and_then(|entry_name| entry_name.strip_prefix(name))
            .and_then(|rest| rest.strip_prefix('.'))
            .and_then(|rest| rest.strip_suffix(".tmp"));
        if id.is_some_and(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Creates a new owner-only file. `create_new` fails if anything already
/// exists at `path`, including a symlink, so it never writes through one.
fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "ddns-persist-test-{}-{}",
                std::process::id(),
                random_hex().unwrap()
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn security_temp_file_cannot_follow_attacker_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new();
        let victim = dir.0.join("synthetic-victim");
        std::fs::write(&victim, "unchanged").unwrap();
        let planted = dir.0.join("state.json.planted.tmp");
        std::os::unix::fs::symlink(&victim, &planted).unwrap();
        assert!(create_private_file(&planted).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "unchanged");
        let missing = dir.0.join("synthetic-missing");
        let dangling = dir.0.join("state.json.dangling.tmp");
        std::os::unix::fs::symlink(&missing, &dangling).unwrap();
        assert!(create_private_file(&dangling).is_err());
        assert!(!missing.exists());
        let fresh = dir.0.join("state.json.fresh.tmp");
        create_private_file(&fresh).unwrap();
        assert_eq!(
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn replacement_is_complete_and_leaves_no_temporary_file() {
        let dir = TestDir::new();
        let path = dir.0.join("settings.json");
        std::fs::write(&path, b"old").unwrap();
        assert_eq!(replace_file(&path, b"new"), Ok(SaveOutcome::Durable));
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(replace_file(&path, b"newer").is_err());
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
    }
}
