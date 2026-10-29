//! `iccp-sim` — a config-driven ICCP/TASE.2 SERVER simulator.
//!
//! Serves as the "called" role so a real OpenICCP client can associate,
//! enumerate the domain/points/datasets, read `TASE2_Version` and
//! `Supported_Features`, claim a DS transfer set, and receive
//! condition-monitoring reports. Everything is driven by a JSON config file;
//! no recompile is needed to change what the simulator advertises.
//!
//! ```bash
//! iccp-sim -c config.json
//! ```

mod client_sim;
mod config;
mod provider;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use config::{build_model, load_config_file, mutation_value, Mode, SimModel};
use provider::SimProvider;
use tase2::{
    AssocConfig, DataProvider, DefaultLoggingHandler, Identifier, ObjectName, ServeOptions,
    Tase2Server, TransferSetManager,
};

struct Cli {
    config: PathBuf,
    port: Option<u16>,
}

fn parse_args() -> Result<Cli, String> {
    let mut config = None;
    let mut port = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => {
                config = Some(PathBuf::from(args.next().ok_or("--config needs a value")?));
            }
            "--port" => {
                let v = args.next().ok_or("--port needs a value")?;
                port = Some(v.parse().map_err(|_| format!("bad --port {v:?}"))?);
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option {other:?}"));
            }
            other => {
                // Bare positional = config file.
                if config.is_none() {
                    config = Some(PathBuf::from(other));
                } else {
                    return Err(format!("unexpected argument {other:?}"));
                }
            }
        }
    }
    Ok(Cli {
        config: config
            .ok_or("missing -c/--config <file> (a JSON config)")?,
        port,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    let cli = parse_args()?;
    let mut cfg = load_config_file(&cli.config).map_err(|e| e.to_string())?;

    // Dispatch on role. `--port` overrides the active role's port.
    match cfg.mode {
        Mode::Client => {
            if let Some(p) = cli.port {
                cfg.client.port = p;
            }
            return client_sim::run(&cfg.client).await.map_err(|e| e.into());
        }
        Mode::Server => {
            if let Some(p) = cli.port {
                cfg.port = p;
            }
            run_server(&cfg).await
        }
    }
}

/// The server (called) role: bind, accept, and serve associations.
async fn run_server(cfg: &config::SimConfig) -> Result<(), Box<dyn std::error::Error>> {
    let model = build_model(cfg).map_err(|e| e.to_string())?;

    // Bind. The address comes from the config `ip` field (default 0.0.0.0 =
    // all interfaces); port 102 may need elevation on some OSes, and a CLI
    // --port override lets the operator pick an alternate port without
    // editing the config.
    let addr: SocketAddr = (model.bind_ip, model.port).into();
    let server = Tase2Server::bind(addr, AssocConfig::default()).await?;
    tracing::info!(%addr, domain = %model.domain, "iccp-sim listening");

    // Shared serve state.
    let provider = model.provider.clone();
    let bilateral = model.bilateral.clone();
    let manager = Arc::new(TransferSetManager::new(provider.clone()));

    // Optional self-mutation loop driving OBJECT_CHANGE reports.
    if model.mutation.interval_secs > 0 && !model.mutation.points.is_empty() {
        tokio::spawn(spawn_mutation_task(model, manager.clone()));
    }

    // Accept loop: serve each association in its own task so multiple (or
    // sequential) OpenICCP clients can connect in turn.
    loop {
        let conn = match server.accept_with(DefaultLoggingHandler).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(%e, "accept failed");
                continue;
            }
        };
        let peer = conn.peer_addr();
        tracing::info!(%peer, "association up; serving");

        let provider = provider.clone();
        let manager = manager.clone();
        let bilateral = bilateral.clone();
        tokio::spawn(async move {
            let mut conn = conn;
            let options = ServeOptions::<SimProvider>::new()
                .with_transfer_sets(manager)
                .with_access(bilateral)
                .with_poll_ceiling(Duration::from_millis(200));
            if let Err(e) = tase2::serve_connection_opts(&mut conn, provider, options).await {
                tracing::warn!(%e, "connection error");
            }
            tracing::info!("association closed");
        });
    }
}

/// Background task that steps each configured point through its value list on a
/// timer, writing the new value and notifying the transfer-set manager so any
/// enabled DS transfer set emits an OBJECT_CHANGE report.
async fn spawn_mutation_task(model: SimModel, manager: Arc<TransferSetManager<SimProvider>>) {
    let interval = Duration::from_secs(model.mutation.interval_secs);
    let mut idx = 0usize;
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip the immediate first tick.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            idx += 1;
            for mp in &model.mutation.points {
                // build_model already rejects empty value lists at startup;
                // this guard keeps the modulo total even if the check is ever
                // bypassed (idx % 0 would panic).
                if mp.values.is_empty() {
                    continue;
                }
                let raw = match mp.values.get(idx % mp.values.len()) {
                    Some(v) => v,
                    None => continue,
                };
                let Some(value) = mutation_value(&model, &mp.name, raw) else {
                    continue;
                };
                let Some(name) = domain_point_name(&model, &mp.name) else {
                    continue;
                };
                if let Err(e) = model.provider.write(&name, value).await {
                    tracing::warn!(point = %mp.name, %e, "mutation write failed");
                    continue;
                }
                manager.notify_point_changed(&name);
            }
        }
    });
}

/// Reconstruct the domain-specific [`ObjectName`] for a point item name.
fn domain_point_name(model: &SimModel, item: &str) -> Option<ObjectName> {
    let domain = Identifier::new(&model.domain).ok()?;
    let item = Identifier::new(item).ok()?;
    Some(ObjectName::DomainSpecific { domain, item })
}
