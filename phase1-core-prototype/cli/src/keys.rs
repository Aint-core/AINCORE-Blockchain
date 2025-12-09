use keystore::KeyManager;
use std::path::Path;
use anyhow::{Context, Result};
use std::io::Write;

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
        println!("⚠️  Private Key (SAVE THIS SAFELY): {}", private_key);
        
        Ok(())
    }

    pub fn import(private_key: &str, out_dir: &str) -> Result<()> {
        let dir = Path::new(out_dir);
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
        }

        println!("🔐 Importing key into encrypted keystore in '{}'", out_dir);
        let password = Self::prompt_password(true)?;
        
        println!("⏳ Encrypting key...");
        let uuid = KeyManager::import(dir, private_key, &password)?;
        
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
