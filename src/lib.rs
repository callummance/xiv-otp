pub mod config;
pub mod monitor;
pub mod secret_store;
pub mod xl_send;

use anyhow::Result;
use futures::TryFutureExt;
use zeroize::Zeroize;

pub fn run(opts: &config::XivOtpOpts) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .thread_name("xiv-otp")
        .enable_io()
        .enable_time()
        .build()
        .expect("Failed to start async runtime.");

    let _res: Result<()> = rt.block_on(async move {
        let app = XivOtpApp::init(opts).await?;
        match opts.command {
            config::XivOtpCommands::Oneshot { wait } => app.run_oneshot(wait).await?,
            config::XivOtpCommands::Delete {} => app.run_delete().await?,
            config::XivOtpCommands::Monitor {} => app.run_monitor().await?,
            config::XivOtpCommands::SetSecret {} => app.set_secret().await?,
        }

        Ok(())
    });
}

pub struct XivOtpApp {
    opts: config::XivOtpOpts,
    secrets: secret_store::SecretStore,
    launcher: xl_send::XlSender,
}

impl XivOtpApp {
    pub async fn init(opts: &config::XivOtpOpts) -> Result<Self> {
        let opts = opts.clone();
        let secrets = secret_store::SecretStore::get_provider((&opts.secret_opts).into()).await?;
        let launcher = xl_send::XlSender::init(&opts.target_opts.addr)?;

        Ok(Self {
            opts,
            secrets,
            launcher,
        })
    }

    /// Delete any stored keys in secrets store
    pub async fn run_delete(&self) -> Result<()> {
        self.secrets.delete_secret().await
    }

    pub async fn set_secret(&self) -> Result<()> {
        self.run_delete().await?;
        let mut secret = Self::request_secret_input().await?;
        self.secrets.write_secret(&secret).await?;
        secret.zeroize();
        Ok(())
    }

    /// Loads secret from secret store if possible, otherwise asks user to enter it. Immediately
    /// generates an otp key and sends it to the standard XIVLauncher endpoint on the local machine.
    pub async fn run_oneshot(&self, wait: bool) -> Result<()> {
        // Try to load secret from store
        let mut generator = self.get_generator().await?;
        // Wait for listener if requested
        if wait {
            self.wait_for_listener().await?
        }
        // Generate OTP
        let token = generator.generate_current();
        generator.zeroize();
        tracing::debug!(?token, "Generated OTP");
        // Send request to listener
        self.launcher.send_otp(&token.to_string()).await?;
        Ok(())
    }

    /// Loads secret from secret store if possible, otherwise asks user to enter it.
    /// Once we have the secret, constantly waits for a listening XIVLauncher instance and
    /// generates then submits an OTP whenever one is found.
    pub async fn run_monitor(&self) -> Result<()> {
        let generator = self.get_generator().await?;
        loop {
            self.wait_for_listener().await?;

            let token = generator.generate_current();
            tracing::debug!(?token, "Generated OTP");
            self.launcher.send_otp(&token.to_string()).await?;
        }
    }

    async fn wait_for_listener(&self) -> Result<()> {
        let interval = std::time::Duration::from_secs(self.opts.monitor_opts.check_period);
        let proc_found_interval =
            std::time::Duration::from_secs(self.opts.monitor_opts.check_period_port);
        monitor::wait_until_listening(&interval, &proc_found_interval, 4646, "XIVLauncher").await
    }

    async fn get_generator(&self) -> Result<totp_rs::Totp> {
        let res: totp_rs::Totp = self
            .secrets
            .get_secret()
            .and_then(|secret| async move {
                if let Some(s) = secret {
                    let totp_key = s.parse::<OtpSecret>()?;
                    totp_key.to_otp_generator().inspect_err(|_e| tracing::error!("Saved TOTP secret seems to be invalid. Please delete the saved value and try again."))
                } else {
                    // Ask for totp url if we don't have one
                    let totp_key_str = Self::request_secret_input().await?;
                    let totp_key = totp_key_str.parse::<OtpSecret>()?;
                    let generator = totp_key.to_otp_generator().inspect_err(|_e| tracing::error!("That TOTP secret seems to be invalid. Please check you have copied the correct value and try again."))?;
                    // Store totp url if needed
                    if let Err(e) = self.secrets.write_secret(&totp_key_str).await {
                        tracing::warn!(cause=?e, "Failed to write TOTP key to secrets store, continuing with provided key...");
                    }
                    Ok(generator)
                }
            })
            .or_else(|e| async move {
                tracing::warn!(cause=?e, "Failed to load secret from secrets store");
                let totp_key_str = Self::request_secret_input().await?;
                let totp_key = totp_key_str.parse::<OtpSecret>()?;
                let generator = totp_key.to_otp_generator().inspect_err(|_e| tracing::error!("That TOTP secret seems to be invalid. Please check you have copied the correct value and try again."))?;
                Ok(generator)
            }).map_err(|_e: anyhow::Error| anyhow::anyhow!("Failed to obtain TOTP url from both system secrets store or user input, cannot continue."))
            .await?;

        Ok(res)
    }

    async fn request_secret_input() -> Result<String> {
        Ok(tokio::task::spawn_blocking(|| {
            dialoguer::Password::new()
                .with_prompt("Please enter your FFXIV authenticator key.")
                .interact()
        })
        .await??)
    }
}

#[derive(zeroize::Zeroize)]
pub enum OtpSecret {
    OtpauthUrl(String),
    Base32(String),
}

impl std::str::FromStr for OtpSecret {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        //Try as otpauth url
        let as_url = url::Url::parse(s);
        Ok(
            if let Ok(url) = as_url
                && url.scheme() == "otpauth"
            {
                tracing::debug!("Provided secret seems to be an otpauth url");
                Self::OtpauthUrl(s.to_string())
            } else {
                tracing::debug!(
                    "Provided secret does not seem to be an otpauth url, trying b32..."
                );
                let as_b32str = s.split_whitespace().collect::<Vec<_>>().join("");
                if as_b32str
                    .chars()
                    .all(|c| matches!(c, 'A'..='Z' | '0'..='7'))
                {
                    tracing::debug!("Provided secret seems to be base32 encoded data");
                    Self::Base32(as_b32str)
                } else {
                    tracing::debug!("Provided secret does not seem to be base32 encoded data");
                    anyhow::bail!(
                        "Provided string was neither an otpauth url nor a base32 encoded string."
                    )
                }
            },
        )
    }
}

impl OtpSecret {
    pub fn to_otp_generator(mut self) -> Result<totp_rs::Totp> {
        let res = match self {
            OtpSecret::OtpauthUrl(ref s) => totp_rs::Totp::from_url(s)?,
            OtpSecret::Base32(ref s) => {
                let secret = totp_rs::Secret::try_from_base32(s)?;
                totp_rs::Builder::new()
                    .with_secret(secret)
                    .with_step_duration(30)
                    .with_algorithm(totp_rs::Algorithm::SHA1)
                    .with_issuer(Some("Square Enix ID"))
                    .build()?
            }
        };

        self.zeroize();
        Ok(res)
    }
}
