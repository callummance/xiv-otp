#[derive(Debug, Clone, clap::Parser)]
#[command(name = "xiv-otp")]
#[command(about = "Automatic OTP generation for XIVLauncher")]
pub struct XivOtpOpts {
    #[command(subcommand)]
    pub command: XivOtpCommands,

    #[command(flatten)]
    pub secret_opts: XivSecretStoreOpts,
    #[command(flatten)]
    pub target_opts: XivOtpTargetOpts,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum XivOtpCommands {
    /// Deletes the saved OTP key
    Delete {},
    /// Immediately generates OTP and send it to XIVLauncher
    Oneshot {
        #[arg(long)]
        /// Wait for an XIVLauncher instance to start listening before sending OTP
        wait: bool,
    },
}

#[derive(Debug, Clone, clap::Args)]
pub struct XivSecretStoreOpts {}

#[derive(Debug, Clone, clap::Args)]
pub struct XivOtpTargetOpts {
    #[arg(short, long)]
    #[arg(default_value = "http://localhost:4646")]
    /// Address of the target XIVLauncher instance
    pub addr: String,
}
