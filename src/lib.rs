pub mod config;
pub mod monitor;
pub mod secret_store;
pub mod xl_send;

use anyhow::Result;
use futures::TryFutureExt;
use zeroize::Zeroize;

#[cfg(target_os = "linux")]
use arboard::SetExtLinux;

pub fn run(opts: &config::XivOtpOpts) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .thread_name("xiv-otp")
        .enable_io()
        .enable_time()
        .build()
        .expect("Failed to start async runtime.");

    let res: Result<()> = rt.block_on(async move {
        let mut app = XivOtpApp::init(opts).await?;
        match opts.command {
            config::XivOtpCommands::Oneshot { wait, copy: _ } => app.run_oneshot(wait).await?,
            config::XivOtpCommands::Delete {} => app.run_delete().await?,
            config::XivOtpCommands::Monitor {} => app.run_monitor().await?,
            config::XivOtpCommands::SetSecret {} => app.set_secret().await?,
            config::XivOtpCommands::Internal(ref xiv_internal_commands) => {
                match xiv_internal_commands {
                    config::XivInternalCommands::Clipboard { otp } => {
                        // Daemonize if needed for clipboard
                        let mut clipboard = arboard::Clipboard::new()
                            .expect("Failed to interact with system clipboard.");
                        clipboard
                            .set()
                            .wait()
                            .text(otp)
                            .expect("Failed to write to system clipboard");
                    }
                }
            }
        }

        Ok(())
    });

    if let Err(e) = res {
        tracing::error!(?e, "Something failed, exiting...")
    }
}

pub struct XivOtpApp {
    opts: config::XivOtpOpts,
    secrets: secret_store::SecretStore,
    monitor: monitor::ProcMonitor,
}

impl XivOtpApp {
    pub async fn init(opts: &config::XivOtpOpts) -> Result<Self> {
        let opts = opts.clone();
        let secrets = secret_store::SecretStore::get_provider((&opts.secret_opts).into()).await?;
        let monitor = monitor::ProcMonitor::new();

        Ok(Self {
            opts,
            secrets,
            monitor,
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
    pub async fn run_oneshot(&mut self, wait: bool) -> Result<()> {
        // Try to load secret from store
        let mut generator = self.get_generator().await?;
        // Wait for listener if requested
        if wait {
            println!("Waiting for XIVLauncher instance...");
            let _pid = self.wait_for_listener().await?;
        }
        // Generate OTP
        let token = generator.generate_current();
        generator.zeroize();
        // Send request to listener
        println!("Sending token...");
        tracing::debug!(?token, "Generated OTP");
        let sender = self.get_sender().await?;
        self.send_otp(&token.to_string(), sender.as_ref()).await?;
        Ok(())
    }

    /// Loads secret from secret store if possible, otherwise asks user to enter it.
    /// Once we have the secret, constantly waits for a listening XIVLauncher instance and
    /// generates then submits an OTP whenever one is found.
    pub async fn run_monitor(&mut self) -> Result<()> {
        let generator = self.get_generator().await?;
        let sender = self.get_sender().await?;
        loop {
            println!("Waiting for XIVLauncher instance...");
            let _pid = self.wait_for_listener().await?;

            let token = generator.generate_current();
            println!("Sending token...");
            tracing::debug!(?token, "Generated OTP");
            self.send_otp(&token.to_string(), sender.as_ref()).await?;
        }
    }

    async fn get_sender(&self) -> Result<Box<dyn xl_send::OtpSender>> {
        Ok(
            if let config::XivOtpCommands::Oneshot { copy, .. } = self.opts.command
                && copy
            {
                // copy-only mode
                Box::new(xl_send::ClipboardSender)
            } else {
                Box::new(xl_send::XlSender::init(&self.opts.target_opts.addr)?)
            },
        )
    }

    async fn send_otp(&mut self, tok: &str, sender: &dyn xl_send::OtpSender) -> Result<()> {
        if self.opts.target_opts.show {
            println!("{}", tok);
        }
        sender.send_otp(tok).await?;
        Ok(())
    }

    async fn wait_for_listener(&mut self) -> Result<i32> {
        let interval = std::time::Duration::from_secs(self.opts.monitor_opts.check_period);
        let proc_found_interval =
            std::time::Duration::from_secs(self.opts.monitor_opts.check_period_port);
        self.monitor
            .wait_until_listening(&interval, &proc_found_interval, 4646, "XIVLauncher")
            .await
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
