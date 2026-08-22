use anyhow::Result;

pub struct XlSender {
    base_url: url::Url,
}
impl XlSender {
    /// Creates a new sender instance which can be used to submit OTP tokens to the specified
    /// XIVLauncher instance
    pub fn init(base_url: &str) -> Result<Self> {
        let base_url = url::Url::parse(base_url)?;
        Ok(Self { base_url })
    }

    /// Sends the provided OTP token to the relevant endpoint
    pub async fn send_otp(&self, otp: &str) -> Result<()> {
        let mut tgt_url = self.base_url.clone();
        tgt_url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("Target base URL {} was invalid.", self.base_url))?
            .clear()
            .push("ffxivlauncher")
            .push(otp);
        let resp = reqwest::get(tgt_url).await?;
        let _status = resp.status();
        let resp_body = resp.text().await?;
        tracing::trace!(response_body=?resp_body, "Submitted OTP to XIVLauncher");

        Ok(())
    }
}
