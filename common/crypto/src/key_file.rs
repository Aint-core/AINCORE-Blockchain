//! Local Ed25519 key files used by the node and the CLI.
use ed25519_dalek::SigningKey;
use std::fs;
use std::io::{self, ErrorKind, Write};
use std::path::Path;
use zeroize::Zeroizing;

/// Read a 32-byte Ed25519 seed or its 64 hexadecimal digits with optional whitespace.
pub fn read_ed25519(path: &Path) -> io::Result<SigningKey> {
    let bytes = Zeroizing::new(fs::read(path)?);
    if let Ok(raw) = <&[u8; 32]>::try_from(bytes.as_slice()) {
        return Ok(SigningKey::from_bytes(raw));
    }
    let mut raw = Zeroizing::new([0u8; 32]);
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "expected a raw or hexadecimal key"))?;
    hex::decode_to_slice(text.trim(), raw.as_mut_slice()).map_err(|_| {
        io::Error::new(ErrorKind::InvalidData, "expected a 32-byte hexadecimal key")
    })?;
    Ok(SigningKey::from_bytes(&raw))
}

/// Publish complete bytes at a new destination and return AlreadyExists if another
/// initializer installed it first. The caller can then read the installed identity.
pub fn publish_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // NamedTempFile starts at most 0600. Ensure even a restrictive umask
        // leaves the owner able to reopen the key after publication.
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(path).map_err(|e| e.error)?;
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}
