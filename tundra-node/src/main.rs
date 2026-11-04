use anyhow::Context;
use config::{Command, NodeConfig};
use futures::StreamExt;
use metrics::Metrics;
use nix::sys::resource::{Resource, getrlimit, setrlimit};
use node::{
    Node,
    docker::{ContainerEvent, DockerAdapter},
    identity::Identity,
};
use remote::{RemoteClient, SyncEvent};
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

mod config;
mod metrics;
mod net;
mod node;
mod pinning;
mod remote;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_COMMIT: &str = env!("CARGO_GIT_COMMIT");
const GIT_BRANCH: &str = env!("CARGO_GIT_BRANCH");
const TARGET: &str = env!("CARGO_TARGET");

const SNAPSHOT_QUEUE: usize = 8;
const BOOTSTRAP_RETRY: Duration = Duration::from_secs(5);
const BOOTSTRAP_RETRY_MAX: Duration = Duration::from_secs(60);
const WANTED_NOFILE: u64 = 64 * 1024;
const DOCKER_EVENTS_RETRY: Duration = Duration::from_secs(2);

#[cfg(target_os = "linux")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(target_os = "linux")]
const MALLOC_CONF: &std::ffi::CStr = c"background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0,narenas:4,tcache_nslots_small_max:20,tcache_max:4096";

#[cfg(target_os = "linux")]
#[unsafe(export_name = "_rjem_malloc_conf")]
static MALLOC_CONF_PTR: Option<&'static std::ffi::c_char> =
    // SAFETY: MALLOC_CONF is a 'static nul-terminated C string, which is what
    // jemalloc reads this symbol as during its initialization.
    Some(unsafe { &*MALLOC_CONF.as_ptr() });

fn full_version() -> String {
    if GIT_BRANCH == "unknown" {
        VERSION.to_string()
    } else {
        format!("{VERSION}:{GIT_COMMIT}@{GIT_BRANCH}")
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();

    let config_path = match config::command_from_args()? {
        Command::Run(path) => path,
        Command::Restart(path) => {
            let config = NodeConfig::open(&path)?;
            let pid = node::restart::signal_running(&config.data_dir)?;
            println!("asked tundra-node (pid {pid}) to restart in place");
            return Ok(());
        }
    };

    tracing::info!("tundra-node {} ({TARGET})", full_version());
    tracing::info!("github.com/calagopus/tundra#{}", GIT_COMMIT);

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    raise_file_limit();

    let mut blob_unusable = false;
    let inherited = match node::restart::exec::resume_fd()? {
        Some(fd) => {
            let inherited = node::restart::resume::inherit(fd);
            blob_unusable = inherited.is_none();
            inherited
        }
        None => None,
    };

    let config = Arc::new(NodeConfig::open(&config_path)?);
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let remote = Arc::new(RemoteClient::new(
        Arc::clone(&config),
        Arc::clone(&provider),
    )?);

    let identity = match &inherited {
        Some(inherited) => match Identity::from_disk(&config.data_dir, inherited.node_uuid) {
            Ok(identity) => identity,
            Err(err) => {
                tracing::warn!(
                    "failed to load a usable identity from disk, bootstrapping from the panel: {:?}",
                    err
                );
                bootstrap(&config, &remote).await?
            }
        },
        None => bootstrap(&config, &remote).await?,
    };

    tracing::info!(
        node = %identity.uuid,
        fingerprint = %identity.cert_sha256,
        "node identity established"
    );

    let applied = metrics::Applied::load(config.loaded_sha256)?;
    let metrics = Arc::new(Metrics::new_with_applied(applied));

    let docker = match DockerAdapter::new() {
        Ok(d) => Some(d),
        Err(err) => {
            tracing::warn!(
                "docker is unavailable; Docker container references cannot be adopted, but process-backed references remain available: {:?}",
                err
            );
            None
        }
    };

    let handover = Arc::new(node::restart::Handover::new(
        exec_target(&config),
        std::env::args_os().skip(1).collect(),
        inherited.as_ref().map_or(0, |h| h.generation),
        config.restart.drain_timeout(),
        config.restart.peer_resume_timeout(),
    ));
    if let Some(inherited) = &inherited {
        handover.mark_triggered(inherited.triggered_unix_ms);
    }
    if blob_unusable {
        handover
            .counters
            .blob_unusable
            .store(1, std::sync::atomic::Ordering::Relaxed);
    }

    let (refresh_tx, refresh_rx) = mpsc::channel(1);
    let node = Node::new(
        Arc::clone(&config),
        identity,
        Arc::clone(&remote),
        Arc::clone(&metrics),
        Arc::clone(&provider),
        docker.clone(),
        Arc::new(node::frontend::binder::NetnsBinder),
        handover,
        refresh_tx,
    );

    node::restart::write_pidfile(&config.data_dir)?;

    let resuming = if let Some(inherited) = inherited {
        let old_instance = inherited.old_instance;
        node.restart.begin();
        node.seed_index(inherited.snapshot);
        node.gate.pause_all();
        node::frontend::adopt(&node, inherited.frontends, inherited.next_frontend_id);

        let peers: Vec<_> = inherited.peers.keys().copied().collect();
        *node.carried.lock() = inherited.peers;
        tracing::info!(
            generation = node.restart.generation,
            old_instance,
            new_instance = node.restart.instance_id,
            peers = peers.len(),
            "resuming from the previous image"
        );

        Some(peers)
    } else {
        None
    };

    let server = node::quic::server_config(&node.identity, node.pins(), provider, None)?;
    node.set_endpoint(node::quic::endpoint(config.tunnel_bind, server)?);
    tracing::info!(
        bind = %config.tunnel_bind,
        "tunnel endpoint listening"
    );

    let (events_tx, mut events_rx) = mpsc::channel(SNAPSHOT_QUEUE);
    tokio::spawn(remote::sync_loop(
        remote,
        events_tx,
        Arc::clone(&metrics),
        refresh_rx,
    ));
    tokio::spawn(node::accept_loop(Arc::clone(&node)));
    tokio::spawn(node::maintenance_loop(Arc::clone(&node)));
    tokio::spawn(node::restart::takeover::signal_loop(Arc::clone(&node)));

    if let Some(peers) = resuming {
        tokio::spawn(node::restart::resume::run(Arc::clone(&node), peers));
    }

    let metrics_bind = config.metrics_bind;
    tokio::spawn({
        let metrics = Arc::clone(&metrics);

        async move {
            if let Err(err) = metrics::serve(metrics_bind, metrics).await {
                tracing::error!("failed to serve the metrics endpoint: {:?}", err);
            }
        }
    });

    if let Some(docker) = docker {
        tokio::spawn(docker_events(Arc::clone(&node), docker));
    }

    while let Some(event) = events_rx.recv().await {
        match event {
            SyncEvent::LinkUp => {
                node.reset_epoch_watermark();
                node.note_link_up();
            }
            SyncEvent::Snapshot(snapshot) => node.apply_snapshot(snapshot).await,
        }
    }

    Ok(())
}

fn exec_target(config: &NodeConfig) -> Option<std::path::PathBuf> {
    if let Some(path) = &config.restart.binary_path {
        return Some(path.clone());
    }

    let argv0 = std::env::args_os().next()?;
    let cwd = std::env::current_dir().ok()?;

    let resolved =
        node::restart::exec::resolve_binary(&argv0, &cwd, std::env::var_os("PATH").as_deref());
    if resolved.is_none() {
        tracing::warn!(
            "failed to resolve this binary's path, set restart.binary_path to enable in-place restarts"
        );
    }

    resolved
}

async fn bootstrap(config: &NodeConfig, remote: &RemoteClient) -> Result<Identity, anyhow::Error> {
    let mut backoff = BOOTSTRAP_RETRY;
    loop {
        match Identity::bootstrap(&config.data_dir, remote).await {
            Ok(identity) => return Ok(identity),
            Err(err) if is_fatal(&err) => return Err(err).context("failed to bootstrap this node"),
            Err(err) => {
                tracing::warn!(
                    retry_secs = backoff.as_secs(),
                    "failed to bootstrap this node, retrying: {:?}",
                    err
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BOOTSTRAP_RETRY_MAX);
            }
        }
    }
}

fn is_fatal(err: &anyhow::Error) -> bool {
    err.chain().any(|c| {
        let text = c.to_string();
        text.contains("401") || text.contains("400") || text.contains("403")
    })
}

async fn docker_events(node: Arc<Node>, docker: DockerAdapter) {
    let mut reconnected = false;
    loop {
        let mut events = docker.events();
        if reconnected {
            node.reconcile_local().await;
        }

        while let Some(event) = events.next().await {
            match event {
                ContainerEvent::Started { id, name } => {
                    node::frontend::on_container_event(&node, &id, name.as_deref(), true).await;
                }
                ContainerEvent::Died { id, name } => {
                    node::frontend::on_container_event(&node, &id, name.as_deref(), false).await;
                }
            }
        }

        tracing::warn!("docker event stream ended, reopening");
        reconnected = true;
        tokio::time::sleep(DOCKER_EVENTS_RETRY).await;
    }
}

fn raise_file_limit() {
    let Ok((soft, hard)) = getrlimit(Resource::RLIMIT_NOFILE) else {
        return;
    };

    let wanted = WANTED_NOFILE.min(hard);
    if soft >= wanted {
        return;
    }

    match setrlimit(Resource::RLIMIT_NOFILE, wanted, hard) {
        Ok(()) => tracing::info!(soft = wanted, hard, "raised the file descriptor limit"),
        Err(err) => tracing::warn!(
            soft,
            hard,
            "failed to raise the file descriptor limit: {:?}",
            err
        ),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn malloc_conf_is_applied() {
        use tikv_jemalloc_ctl::raw;

        // SAFETY: opt.narenas is a read-only unsigned int option.
        let narenas: std::ffi::c_uint =
            unsafe { raw::read(b"opt.narenas\0") }.expect("read opt.narenas");
        assert_eq!(narenas, 4, "narenas from MALLOC_CONF was not applied");

        // SAFETY: opt.background_thread is a read-only bool option.
        let background: bool =
            unsafe { raw::read(b"opt.background_thread\0") }.expect("read opt.background_thread");
        assert!(
            background,
            "background_thread from MALLOC_CONF was not applied"
        );

        // SAFETY: opt.dirty_decay_ms is a read-only ssize_t option.
        let dirty_decay: isize =
            unsafe { raw::read(b"opt.dirty_decay_ms\0") }.expect("read opt.dirty_decay_ms");
        assert_eq!(dirty_decay, 1000, "dirty_decay_ms was not applied");
    }
}
