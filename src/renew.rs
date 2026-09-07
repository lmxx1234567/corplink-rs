//! One-shot request consumed only when opted in by the systemd startup command.
use anyhow::{bail, Context, Result};
use std::path::Path;

pub const CONTROL_CAPABILITIES: &str = if cfg!(unix) { "renew-marker-v1" } else { "" };

pub fn consume_request() -> Result<Option<String>> {
    #[cfg(unix)]
    {
        consume_at(Path::new("/run/corplink-rs/renew-request.json"), 0)
    }
    #[cfg(not(unix))]
    {
        bail!("renew requests require Unix")
    }
}

#[cfg(unix)]
fn consume_at(path: &Path, owner: u32) -> Result<Option<String>> {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("cannot inspect renew request"),
    };
    if !meta.file_type().is_file()
        || meta.uid() != owner
        || meta.mode() & 0o077 != 0
        || meta.len() > 1024
    {
        bail!("unsafe renew request");
    }
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path)?).context("invalid renew request")?;
    let id = raw
        .get("operation_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if id.len() != 32 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
        bail!("invalid renew operation id");
    }
    std::fs::remove_file(path).context("cannot consume renew request")?;
    Ok(Some(id.to_owned()))
}

/// Receipt binds a successful authentication/connect attempt to its operation and process.
pub fn write_completed(operation_id: &str) -> Result<()> {
    write_completed_at(
        Path::new("/run/corplink-rs/renew-completed.json"),
        operation_id,
    )
}

fn write_completed_at(path: &Path, operation_id: &str) -> Result<()> {
    let temporary = path.with_extension(format!(
        "{}.{:032x}.tmp",
        std::process::id(),
        rand::random::<u128>()
    ));
    publish_completed(path, &temporary, operation_id)
}

fn publish_completed(path: &Path, temporary: &Path, operation_id: &str) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // Only clean up after we have successfully created and own this file.
    let mut file = options
        .open(temporary)
        .context("cannot create renewal completion receipt")?;
    let result = (|| -> Result<()> {
        serde_json::to_writer(
            &mut file,
            &serde_json::json!({
                "operation_id": operation_id,
                "process_id": std::process::id()
            }),
        )?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(temporary, path)?;
        Ok(())
    })();
    drop(file);
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result.context("cannot publish renewal completion receipt")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn stale_receipts_do_not_block_publication_or_get_deleted() {
        let dir = std::env::temp_dir().join(format!("corplink-receipt-{}", rand::random::<u128>()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("completed.json");
        let stale = path.with_extension(format!("{}.tmp", std::process::id()));
        std::fs::write(&stale, "stale receipt").unwrap();
        write_completed_at(&path, "0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(std::fs::read_to_string(&stale).unwrap(), "stale receipt");
        let receipt = std::fs::read(&path).unwrap();
        assert!(publish_completed(&path, &stale, "different-operation").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), receipt);
        assert_eq!(std::fs::read_to_string(&stale).unwrap(), "stale receipt");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_publication_cleans_up_owned_temporary_file() {
        let dir =
            std::env::temp_dir().join(format!("corplink-receipt-fail-{}", rand::random::<u128>()));
        std::fs::create_dir(&dir).unwrap();
        let temporary = dir.join("owned.tmp");
        // A directory cannot be replaced by the receipt file.
        assert!(publish_completed(&dir, &temporary, "0123456789abcdef0123456789abcdef").is_err());
        assert!(!temporary.exists());
        assert!(dir.is_dir());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn request_is_one_shot_and_rejects_unsafe_files() {
        let dir = std::env::temp_dir().join(format!(
            "corplink-renew-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("request.json");
        let uid = unsafe { libc::geteuid() };
        assert!(consume_at(&path, uid).unwrap().is_none());
        std::fs::write(
            &path,
            r#"{"operation_id":"0123456789abcdef0123456789abcdef"}"#,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(consume_at(&path, uid).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            consume_at(&path, uid).unwrap().as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert!(consume_at(&path, uid).unwrap().is_none());
        let receipt = dir.join("completed.json");
        write_completed_at(&receipt, "0123456789abcdef0123456789abcdef").unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
        assert_eq!(value["process_id"], std::process::id());
        assert_eq!(value["operation_id"], "0123456789abcdef0123456789abcdef");
        assert_eq!(
            std::fs::metadata(&receipt).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let target = dir.join("target");
        std::fs::write(&target, "{}").unwrap();
        symlink(&target, &path).unwrap();
        assert!(consume_at(&path, uid).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;

    #[test]
    fn capabilities_match_platform_support() {
        #[cfg(unix)]
        assert_eq!(CONTROL_CAPABILITIES, "renew-marker-v1");
        #[cfg(not(unix))]
        {
            assert!(CONTROL_CAPABILITIES.is_empty());
            assert!(consume_request().is_err());
        }
    }
}
