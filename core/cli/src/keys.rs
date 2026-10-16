use anyhow::{Context, Result};
use keystore::KeyManager;
use std::io::Write;
use std::path::Path;

pub struct KeysCmd;

/// B328: where a keystore goes: `out`, or `$HOME/.aincore/keys`. It went to
/// `./keys` in the working directory (a checkout of a public repository),
/// which no ignore file covered.
pub fn out_dir(out: Option<String>) -> Result<String> {
    match out {
        Some(out) => Ok(out),
        None => {
            let home = std::env::var("HOME")
                .map_err(|_| anyhow::anyhow!("no HOME: name the directory with --out"))?;
            Ok(format!("{home}/.aincore/keys"))
        }
    }
}

/// B328/B350: the directory a keystore goes in, private before the keystore
/// is written: a new one is made only its owner can enter (from its first
/// moment: it was made with the umask's mode and narrowed after the file was
/// written), and one that already exists open to others is refused, never
/// narrowed (`--out /tmp` as root made /tmp unusable).
fn private_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir)?;
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir)?.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "{} is open to other users (mode {:o}): keep keystores in a private \
                 directory (chmod 700 it, or name another with --out)",
                dir.display(),
                mode & 0o777
            );
        }
    }
    Ok(())
}

/// B328: the keystore only its owner can read (eth-keystore writes it with
/// the umask's mode; the private directory already keeps others out).
fn restrict(file: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| anyhow::anyhow!("{} could not be made owner-only: {e}", file.display()))?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

impl KeysCmd {
    pub fn generate(out_dir: &str) -> Result<()> {
        let dir = Path::new(out_dir);
        private_dir(dir)?;

        println!("🔐 Creating new encrypted keystore in '{}'", out_dir);
        let password = Self::prompt_password(true)?;

        println!("⏳ Generating key...");
        // B328: the key is not printed: the keystore and its password are the
        // backup (a plaintext key on the terminal ends up in scrollback and
        // logs, which the encryption was there to keep it out of).
        let (_private_key, uuid) = KeyManager::create(dir, &password)?;

        let path = dir.join(&uuid);
        restrict(&path)?;
        println!("✅ Key generated successfully!");
        println!("📄 File: {} (back it up with its password)", path.display());

        Ok(())
    }

    pub fn import(out_dir: &str) -> Result<()> {
        let dir = Path::new(out_dir);
        private_dir(dir)?;

        println!("🔐 Importing key into encrypted keystore in '{}'", out_dir);
        // SECURITY (audit H-6): the private key MUST NOT be a CLI argument — process
        // args (`ps`, /proc/<pid>/cmdline) and shell history leak the plaintext secret
        // before it is ever encrypted. Read it from a no-echo prompt instead.
        print!("🔑 Enter private key to import (hex, input hidden): ");
        std::io::stdout().flush()?;
        let private_key = rpassword::read_password().context("Failed to read private key")?;
        let private_key = private_key.trim().to_string();
        if private_key.is_empty() {
            anyhow::bail!("No private key entered");
        }
        let password = Self::prompt_password(true)?;

        println!("⏳ Encrypting key...");
        let uuid = KeyManager::import(dir, &private_key, &password)?;

        let path = dir.join(&uuid);
        restrict(&path)?;
        println!("✅ Key imported successfully!");
        println!("📄 File: {}", path.display());

        Ok(())
    }

    fn prompt_password(confirm: bool) -> Result<String> {
        print!("🔑 Enter password: ");
        std::io::stdout().flush()?;
        let password = rpassword::read_password().context("Failed to read password")?;

        if confirm {
            print!("🔑 Confirm password: ");
            std::io::stdout().flush()?;
            let confirm_pass = rpassword::read_password().context("Failed to read confirmation")?;

            if password != confirm_pass {
                anyhow::bail!("❌ Passwords do not match!");
            }
        }

        Ok(password)
    }
}

#[cfg(test)]
mod tests {
    /// B328/B350 witness: a keystore goes to `$HOME/.aincore/keys` unless
    /// named, never the working directory; a new directory is private from
    /// its first moment, one open to others is refused and left as it was
    /// (it was chmodded, `--out /tmp` included), and the keystore is
    /// owner-only.
    #[test]
    fn a_keystore_is_kept_out_of_the_checkout_and_owner_only() {
        let home = std::env::var("HOME").expect("HOME");
        assert_eq!(
            super::out_dir(None).unwrap(),
            format!("{home}/.aincore/keys")
        );
        assert_eq!(super::out_dir(Some("x".into())).unwrap(), "x");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode =
                |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            let base = std::env::temp_dir().join(format!("b350_keys_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            let fresh = base.join("new");
            super::private_dir(&fresh).unwrap();
            assert_eq!(mode(&fresh), 0o700, "a new directory is open to others");
            let open = base.join("open");
            std::fs::create_dir_all(&open).unwrap();
            std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(
                super::private_dir(&open).is_err(),
                "an open directory was taken"
            );
            assert_eq!(mode(&open), 0o755, "an existing directory was changed");
            let file = fresh.join("0d0b1a2c-uuid");
            std::fs::write(&file, b"{}").unwrap();
            super::restrict(&file).unwrap();
            assert_eq!(mode(&file), 0o600, "the keystore is readable by others");
            let _ = std::fs::remove_dir_all(&base);
        }
    }
}
