mod auth;
mod cloudflare;
mod config;
mod ddns;
mod http;
mod pp;
mod routes;

use crate::auth::{LoginLimiter, PasswordHash, SessionStore};
use crate::cloudflare::CloudflareClient;
use crate::config::Config;
use crate::pp::PP;
use crate::routes::AppState;
use std::sync::Arc;
use tokio::signal;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main(flavor = "current_thread")]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    println!("cloudflare-ddns-webui v{VERSION}");

    // Load configuration from environment
    let cfg = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ {e}");
            std::process::exit(1);
        }
    };

    let ppfmt = PP::new(cfg.emoji, cfg.quiet);
    config::print_config_summary(&cfg, &ppfmt);

    // Hash the admin password once at boot; the plaintext is dropped.
    let password = PasswordHash::from_password(&cfg.admin_password);
    let cfg = Config {
        admin_password: String::new(), // do not keep plaintext in memory
        ..cfg
    };

    let state = Arc::new(AppState {
        cf: CloudflareClient::new(&cfg.api_token, cfg.update_timeout, cfg.api_base.as_deref()),
        sessions: SessionStore::new(cfg.session_ttl),
        limiter: LoginLimiter::new(),
        password,
        pp: ppfmt,
        cfg,
    });

    let listen = state.cfg.listen.clone();
    let listener = match tokio::net::TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            ppfmt.errorf(
                pp::EMOJI_ERROR,
                &format!("failed to bind {listen}: {e}"),
            );
            std::process::exit(1);
        }
    };
    ppfmt.successf(
        pp::EMOJI_GLOBE,
        &format!("Web UI listening on http://{listen}"),
    );

    let handler_state = state.clone();
    let handler = Arc::new(move |req: http::Request| {
        let state = handler_state.clone();
        Box::pin(async move { routes::handle(state, req).await })
            as std::pin::Pin<Box<dyn std::future::Future<Output = http::Response> + Send>>
    });

    let shutdown = Box::pin(async {
        let _ = signal::ctrl_c().await;
        println!("Stopping...");
    });

    if let Err(e) = http::serve(listener, handler, shutdown).await {
        ppfmt.errorf(pp::EMOJI_ERROR, &format!("server error: {e}"));
        std::process::exit(1);
    }
}
