//! Cryptod - Cryptographic Services Daemon
//!
//! A daemon that provides cryptographic operations over Unix domain sockets
//! using the SOCK_SEQPACKET protocol.

use clap::Parser;
use std::path::PathBuf;
use tracing::{info, error};

mod server;
mod session;
mod handler;
mod context_store;
mod proto;

/// Cryptographic services daemon
#[derive(Parser, Debug)]
#[command(name = "cryptod")]
#[command(about = "Cryptographic services daemon providing crypto operations over Unix socket")]
struct Args {
    /// Path to the Unix domain socket
    #[arg(short, long, default_value = "/tmp/cryptod.sock")]
    socket: PathBuf,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_level.parse().unwrap_or_else(|_| "info".into()))
        )
        .init();

    info!("Starting cryptod daemon");
    info!("Socket path: {}", args.socket.display());

    // Run the server
    if let Err(e) = server::run(&args.socket).await {
        error!("Server error: {}", e);
        return Err(e.into());
    }

    Ok(())
}
