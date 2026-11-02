use std::env;

use anyhow::Result;

#[async_trait::async_trait]
pub trait OtpSender {
    async fn send_otp(&self, otp: &str) -> Result<()>;
}

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
}

#[async_trait::async_trait]
impl OtpSender for XlSender {
    /// Sends the provided OTP token to the relevant endpoint
    async fn send_otp(&self, otp: &str) -> Result<()> {
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

pub struct ClipboardSender;

#[async_trait::async_trait]
impl OtpSender for ClipboardSender {
    async fn send_otp(&self, otp: &str) -> Result<()> {
        if cfg!(target_os = "linux") {
            std::process::Command::new(env::current_exe()?)
                .arg("__INTERNAL_DAEMONIZE_WLCLIPBOARD")
                .arg(otp)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .current_dir("/")
                .spawn()?;
        } else {
            arboard::Clipboard::new()?.set_text(otp)?;
        }

        Ok(())
    }
}
