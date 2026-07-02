use anyhow::{Context, Result};
use keystore::KeyManager;
use std::io::Write;
use std::path::Path;

pub struct KeysCmd;

impl KeysCmd {
    pub fn generate(out_dir: &str) -> Result<()> {
        let dir = Path::new(out_dir);
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
        }

        println!("🔐 Creating new encrypted keystore in '{}'", out_dir);
        let password = Self::prompt_password(true)?;

        println!("⏳ Generating key...");
        let (private_key, uuid) = KeyManager::create(dir, &password)?;

        let path = dir.join(&uuid);
        println!("✅ Key generated successfully!");
        println!("📄 File: {}", path.display());
        println!("🔑 Address (derived from key): [Hidden]"); // In real CLI we would derive public key/address here if needed
        // KeyManager::create returns the key wrapped in zeroize::Zeroizing (memory
        // hygiene); deref to &str to print it. Showing the key once so the operator
        // can save it is the whole point of this command.
        println!(
            "⚠️  Private Key (SAVE THIS SAFELY): {}",
            private_key.as_str()
        );

        Ok(())
    }

    pub fn import(out_dir: &str) -> Result<()> {
        let dir = Path::new(out_dir);
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
        }

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
