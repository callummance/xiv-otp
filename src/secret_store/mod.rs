mod linux_oo7;

use anyhow::Result;

/// Backend used to store a single OTP secret.
pub enum SecretStore {
    Oo7(linux_oo7::LinuxSecretStore),
}

impl SecretStore {
    pub async fn get_provider(opts: Option<SecretProviderOpts>) -> Result<SecretStore> {
        let opts = opts.unwrap_or(SecretProviderOpts::Oo7Opts);
        Ok(match opts {
            SecretProviderOpts::Oo7Opts => {
                SecretStore::Oo7(linux_oo7::LinuxSecretStore::init().await?)
            }
        })
    }

    pub async fn delete_secret(&self) -> Result<()> {
        match self {
            SecretStore::Oo7(linux_secret_store) => linux_secret_store.delete_totp().await,
        }
    }

    pub async fn secret_exists(&self) -> Result<bool> {
        Ok(match self {
            SecretStore::Oo7(linux_secret_store) => linux_secret_store.load_totp().await?.is_some(),
        })
    }

    pub async fn get_secret(&self) -> Result<Option<String>> {
        match self {
            SecretStore::Oo7(linux_secret_store) => linux_secret_store.load_totp().await,
        }
    }

    pub async fn write_secret(&self, content: &str) -> Result<()> {
        tracing::trace!("Writing secret");
        match self {
            SecretStore::Oo7(linux_secret_store) => linux_secret_store.save_totp(content).await,
        }
    }
}

pub enum SecretProviderOpts {
    //TODO: Add default impl with OS detection
    Oo7Opts,
}
