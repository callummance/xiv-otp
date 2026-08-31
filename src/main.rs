use clap::Parser;

fn main() {
    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::WARN.into())
        .from_env_lossy();
    let log_subscriber = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .finish();
    tracing::subscriber::set_global_default(log_subscriber).expect("Failed to initialize logger");

    let opts = xiv_otp::config::XivOtpOpts::parse();

    xiv_otp::run(&opts);
}
