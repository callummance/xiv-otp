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
    #[command(flatten)]
    pub monitor_opts: XivLauncherMonitorOpts,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum XivOtpCommands {
    /// Deletes the saved OTP key
    Delete {},
    /// Asks for your OTP secret, overwriting any previously-saved value
    SetSecret {},
    /// Immediately generates OTP and send it to XIVLauncher
    Oneshot {
        #[arg(long)]
        /// Wait for an XIVLauncher instance to start listening before sending OTP
        wait: bool,
    },
    /// Constantly waits for XIVLauncher instances to start listening on the provided port,
    /// generating and sending OTPs
    Monitor {},
}

#[derive(Debug, Clone, clap::Args)]
pub struct XivLauncherMonitorOpts {
    #[arg(short = 't', long)]
    #[arg(default_value_t = 30)]
    /// Interval in seconds to check for XIVLauncher instances
    pub check_period: u64,

    #[arg(short = 'p', long)]
    #[arg(default_value_t = 1)]
    /// Interval in seconds to check for open port once XIVLauncher instance has been found
    pub check_period_port: u64,
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
