use anyhow::Result;
use tokio_stream::StreamExt;
use zeroize::Zeroize;

const DEFAULT_ATTRIBUTES: [(&'static str, &'static str); 1] = [("application", "XIV-OTP")];

pub struct LinuxSecretStore {
    keyring_handle: oo7::Keyring,
    attributes: Vec<(String, String)>,
}

impl LinuxSecretStore {
    pub async fn init() -> Result<Self> {
        let keyring_handle = oo7::Keyring::new().await?;
        let attributes =
            Vec::from_iter(DEFAULT_ATTRIBUTES.map(|(a, b)| (a.to_string(), b.to_string())));

        Ok(Self {
            keyring_handle,
            attributes,
        })
    }

    pub async fn delete_totp(&self) -> Result<()> {
        tracing::debug!("Deleting TOTP");
        self.keyring_handle.delete(&self.attributes).await?;
        Ok(())
    }

    pub async fn save_totp(&self, totp_url: &str) -> Result<()> {
        tracing::debug!("Saving TOTP");
        let secret = totp_url.as_bytes();
        self.keyring_handle
            .create_item("XIV-OTP", &self.attributes, secret, true)
            .await?;

        Ok(())
    }

    pub async fn load_totp(&self) -> Result<Option<String>> {
        let val = self.keyring_handle.search_items(&self.attributes).await?;
        let mut candidates: Vec<String> = tokio_stream::iter(val)
            .then(async |item| item.secret().await)
            .filter_map(|secret| {
                secret
                    .map_err(|e| tracing::warn!(error = ?e, "Failed to retrieve secret"))
                    .ok()
            })
            .filter_map(|secret| {
                std::str::from_utf8(secret.as_bytes())
                    .map(String::from)
                    .ok()
            })
            .collect()
            .await;

        let otp_url = if candidates.len() > 1 {
            tracing::warn!(
                "More than 1 possible value found in secrets store, choosing the first..."
            );
            tracing::debug!(?candidates);

            Some(candidates[0].to_string())
        } else if candidates.is_empty() {
            tracing::warn!("No matching otp URLs found in secrets store.");
            None
        } else {
            Some(candidates[0].to_string())
        };

        candidates.zeroize();

        Ok(otp_url)
    }
}
