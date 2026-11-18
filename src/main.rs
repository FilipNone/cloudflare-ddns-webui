mod auth;
mod bind;
mod cloudflare;
mod config;
mod customize;
mod ddns;
mod http;
mod persist;
mod pp;
mod routes;
mod totp;

use crate::auth::Auth;
use crate::cloudflare::CloudflareClient;
use crate::customize::UiStore;
use crate::ddns::Detector;
use crate::pp::PP;
use crate::routes::AppState;
use std::future::Future;
use std::sync::Arc;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // The configuration decides emoji and quiet mode, so messages before it
    // loads use the defaults.
    let early = PP::new(true, false);
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        early.errorf(pp::EMOJI_ERROR, "Failed to install rustls crypto provider");
        std::process::exit(1);
    }

    early.infof(
        "",
        format_args!("cloudflare-ddns-webui v{}", routes::VERSION),
    );

    let cfg = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            early.errorf(pp::EMOJI_ERROR, e);
            std::process::exit(1);
        }
    };

    let ppfmt = PP::new(cfg.emoji, cfg.quiet);
    config::print_config_summary(&cfg, &ppfmt);

    let state_path = format!("{}/state.json", cfg.data_dir);
    let auth = match Auth::new_with_origin(
        cfg.session_ttl,
        &state_path,
        ppfmt,
        cfg.public_origin.as_ref(),
    ) {
        Ok(auth) => auth,
        Err(error) => {
            ppfmt.errorf(
                pp::EMOJI_ERROR,
                format_args!("cannot load auth state: {error}"),
            );
            std::process::exit(1);
        }
    };
    if !auth.is_configured() {
        ppfmt.warningf(
            pp::EMOJI_LOCK,
            "No admin password set yet - open the web UI to create one on first access.",
        );
    }
    if auth.has_legacy_backup_hashes() {
        ppfmt.warningf(
            pp::EMOJI_LOCK,
            "Some 2FA backup codes use the older hash format without a random salt - disable and re-enable 2FA to issue new codes.",
        );
    }
    if !auth.passkey_supported() {
        ppfmt.infof(
            pp::EMOJI_LOCK,
            "Passkeys disabled - set PUBLIC_ORIGIN to the exact HTTPS origin (HTTP is allowed on localhost).",
        );
    }

    let cf =
        match CloudflareClient::new(&cfg.api_token, cfg.update_timeout, cfg.api_base.as_deref()) {
            Ok(cf) => cf,
            Err(error) => {
                ppfmt.errorf(pp::EMOJI_ERROR, error);
                std::process::exit(1);
            }
        };
    let detector = match Detector::new(cfg.detection_timeout) {
        Ok(detector) => detector,
        Err(error) => {
            ppfmt.errorf(pp::EMOJI_ERROR, error);
            std::process::exit(1);
        }
    };
    let ui = match UiStore::new(&cfg.data_dir, ppfmt) {
        Ok(ui) => ui,
        Err(error) => {
            ppfmt.errorf(
                pp::EMOJI_ERROR,
                format_args!("cannot load UI settings: {error}"),
            );
            std::process::exit(1);
        }
    };

    let state = Arc::new(AppState {
        cf,
        detector,
        auth,
        ui,
        pp: ppfmt,
        ddns_running: std::sync::atomic::AtomicBool::new(false),
        cfg,
    });

    // Register the signal handlers before binding, so a stop request during
    // startup is not lost.
    let shutdown = shutdown_signal(ppfmt);

    let listen = state.cfg.listen;
    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => {
            ppfmt.errorf(
                pp::EMOJI_ERROR,
                format_args!("failed to bind {listen}: {e}"),
            );
            std::process::exit(1);
        }
    };
    ppfmt.successf(
        pp::EMOJI_GLOBE,
        format_args!("Web UI listening on http://{listen}"),
    );

    let handler_state = state.clone();
    let handler: http::Handler = Arc::new(move |req| {
        let state = handler_state.clone();
        Box::pin(routes::handle(state, req))
    });

    http::serve(listener, handler, shutdown, ppfmt).await;
}

/// Resolves on SIGINT or SIGTERM. `docker stop` sends SIGTERM, and PID 1 in
/// a container ignores it unless a handler is installed.
#[cfg(unix)]
fn shutdown_signal(log: PP) -> impl Future<Output = ()> {
    use tokio::signal::unix::SignalKind;
    let interrupt = signal_received(SignalKind::interrupt(), "SIGINT", log);
    let terminate = signal_received(SignalKind::terminate(), "SIGTERM", log);
    async move {
        tokio::select! {
            () = interrupt => {}
            () = terminate => {}
        }
        log.infof(pp::EMOJI_STOP, "Stopping...");
    }
}

/// Installs the handler now and returns a future that resolves when the
/// signal arrives. If the handler cannot be installed, the error is logged
/// and the future never resolves, so the server keeps running and can still
/// stop on the other signal.
#[cfg(unix)]
fn signal_received(
    kind: tokio::signal::unix::SignalKind,
    name: &'static str,
    log: PP,
) -> impl Future<Output = ()> {
    let handler = tokio::signal::unix::signal(kind);
    if let Err(error) = &handler {
        log.errorf(
            pp::EMOJI_ERROR,
            format_args!("cannot handle {name}: {error}"),
        );
    }
    async move {
        match handler {
            Ok(mut handler) => {
                handler.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    }
}

#[cfg(not(unix))]
fn shutdown_signal(log: PP) -> impl Future<Output = ()> {
    async move {
        if let Err(error) = tokio::signal::ctrl_c().await {
            log.errorf(
                pp::EMOJI_ERROR,
                format_args!("cannot handle Ctrl+C: {error}"),
            );
            std::future::pending::<()>().await;
        }
        log.infof(pp::EMOJI_STOP, "Stopping...");
    }
}
