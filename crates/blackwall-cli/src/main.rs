use blackwall_cli::{run_cli, Cli};
use clap::Parser;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match run_cli(cli).await {
        Ok(code) => ExitCode::from((code & 0xff) as u8),
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}
