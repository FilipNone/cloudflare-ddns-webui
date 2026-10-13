mod auth;
mod bind;
mod cloudflare;
mod config;
mod customize;
mod ddns;
mod http;
mod pp;
mod routes;
mod totp;

use crate::auth::Auth;
use crate::cloudflare::CloudflareClient;
use crate::customize::UiStore;
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

    let cfg = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ {e}");
            std::process::exit(1);
        }
    };

    let ppfmt = PP::new(cfg.emoji, cfg.quiet);
    config::print_config_summary(&cfg, &ppfmt);

    let state_path = format!("{}/state.json", cfg.data_dir);
    let auth = match Auth::new(cfg.session_ttl, &state_path) {
        Ok(auth) => auth,
        Err(error) => {
            ppfmt.errorf(pp::EMOJI_ERROR, &format!("cannot load auth state: {error}"));
            std::process::exit(1);
        }
    };
    if !auth.is_configured() {
        ppfmt.warningf(
            pp::EMOJI_LOCK,
            "No admin password set yet - open the web UI to create one on first access.",
        );
    }

    let state = Arc::new(AppState {
        cf: CloudflareClient::new(&cfg.api_token, cfg.update_timeout, cfg.api_base.as_deref()),
        auth,
        ui: UiStore::new(&cfg.data_dir),
        pp: ppfmt,
        ddns_running: std::sync::atomic::AtomicBool::new(false),
        cfg,
    });

    let listen = state.cfg.listen.clone();
    let listener = match tokio::net::TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            ppfmt.errorf(pp::EMOJI_ERROR, &format!("failed to bind {listen}: {e}"));
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
