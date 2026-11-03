use crate::{config::NodeConfig, pinning::PinnedCert};
use anyhow::Context;
use futures::{SinkExt, StreamExt};
use rustls::crypto::CryptoProvider;
use serde::Deserialize;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{ClientRequestBuilder, Message},
};
use tundra_common::{
    hash::Hash32,
    state::Snapshot,
    sync::{NodeMsg, RemoteMsg},
};

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_secs(60);
const RECONNECT_MIN: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(30);

#[derive(Debug, Deserialize)]
pub struct RemoteIdentity {
    pub uuid: uuid::Uuid,
    pub cert_sha256: Option<Hash32>,
}

enum Transport {
    Tls(Box<rustls::ClientConfig>),
    Unix(PathBuf),
}

pub struct RemoteClient {
    http: reqwest::Client,
    transport: Transport,
    config: Arc<NodeConfig>,
    link_up: AtomicBool,
}

impl RemoteClient {
    pub fn new(
        config: Arc<NodeConfig>,
        provider: Arc<CryptoProvider>,
    ) -> Result<Self, anyhow::Error> {
        let (http, transport) = match config.remote.unix_path() {
            Some(path) => (
                reqwest::Client::builder()
                    .timeout(HTTP_TIMEOUT)
                    .unix_socket(path)
                    .tls_backend_preconfigured(
                        rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
                            .with_protocol_versions(&[&rustls::version::TLS13])?
                            .with_root_certificates(rustls::RootCertStore::empty())
                            .with_no_client_auth(),
                    ),
                Transport::Unix(path.to_path_buf()),
            ),
            None => {
                let tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
                    .with_protocol_versions(&[&rustls::version::TLS13])?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(PinnedCert::new(
                        config.remote.cert_sha256,
                        provider,
                    )))
                    .with_no_client_auth();

                (
                    reqwest::Client::builder()
                        .timeout(HTTP_TIMEOUT)
                        .tls_backend_preconfigured(tls.clone()),
                    Transport::Tls(Box::new(tls)),
                )
            }
        };

        Ok(Self {
            http: http
                .build()
                .context("failed to build the control-plane HTTP client")?,
            transport,
            config,
            link_up: AtomicBool::new(false),
        })
    }

    #[inline]
    pub fn link_up(&self) -> bool {
        self.link_up.load(Ordering::Relaxed)
    }

    fn set_link(&self, up: bool) {
        if self.link_up.swap(up, Ordering::Relaxed) != up {
            if up {
                tracing::info!("control link up");
            } else {
                tracing::warn!("control link down");
            }
        }
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, anyhow::Error> {
        let result = self
            .http
            .get(self.config.api(path))
            .bearer_auth(&self.config.remote.token)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status);

        match result {
            Ok(r) => {
                self.set_link(true);
                Ok(r.json().await?)
            }
            Err(err) => {
                if err.is_connect() || err.is_timeout() || err.is_request() {
                    self.set_link(false);
                }

                Err(err).context(format!("failed to GET {path}"))
            }
        }
    }

    pub async fn identity(&self) -> Result<RemoteIdentity, anyhow::Error> {
        self.get("/api/node/identity").await
    }

    pub async fn state(&self) -> Result<Snapshot, anyhow::Error> {
        self.get("/api/node/state").await
    }

    pub async fn submit_csr(&self, csr_pem: &str) -> Result<String, anyhow::Error> {
        let issued: Issued = self
            .http
            .post(self.config.api("/api/node/csr"))
            .bearer_auth(&self.config.remote.token)
            .json(&serde_json::json!({ "csr_pem": csr_pem }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        #[derive(Deserialize)]
        struct Issued {
            cert_pem: String,
        }

        Ok(issued.cert_pem)
    }

    pub async fn connect_token(&self, target: &uuid::Uuid) -> Result<String, anyhow::Error> {
        let token: Token = self
            .get(&format!("/api/node/connect-token?target={target}"))
            .await?;

        #[derive(Deserialize)]
        struct Token {
            jwt: String,
        }

        Ok(token.jwt)
    }
}

pub enum SyncEvent {
    LinkUp,
    Snapshot(Snapshot),
}

pub async fn sync_loop(
    remote: Arc<RemoteClient>,
    events: mpsc::Sender<SyncEvent>,
    metrics: Arc<crate::metrics::Metrics>,
    mut refresh: mpsc::Receiver<()>,
) {
    let mut backoff = RECONNECT_MIN;

    loop {
        match run_socket(&remote, &events, &metrics, &mut refresh).await {
            Ok(()) => {
                tracing::info!("control websocket closed cleanly");
                backoff = RECONNECT_MIN;
            }
            Err(err) => tracing::warn!("failed to run the control websocket: {:?}", err),
        }

        remote.set_link(false);
        metrics
            .remote_link
            .store(false, std::sync::atomic::Ordering::Relaxed);

        if let Ok(snapshot) = remote.state().await {
            let _ = events.send(SyncEvent::Snapshot(snapshot)).await;
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

async fn run_socket(
    remote: &RemoteClient,
    events: &mpsc::Sender<SyncEvent>,
    metrics: &crate::metrics::Metrics,
    refresh: &mut mpsc::Receiver<()>,
) -> Result<(), anyhow::Error> {
    let uri: tokio_tungstenite::tungstenite::http::Uri = remote
        .config
        .ws_url()
        .parse()
        .context("failed to build the control websocket URL")?;
    let host = uri.host().unwrap_or_default().to_owned();
    let port = uri.port_u16().unwrap_or(443);
    let request = ClientRequestBuilder::new(uri).with_header(
        "Authorization",
        format!("Bearer {}", remote.config.remote.token),
    );

    match &remote.transport {
        Transport::Unix(path) => {
            let socket = tokio::net::UnixStream::connect(path)
                .await
                .context("failed to connect the control socket")?;
            let (socket, _) = tokio_tungstenite::client_async(request, socket)
                .await
                .context("failed to connect the control websocket")?;

            pump(socket, remote, events, metrics, refresh).await
        }
        Transport::Tls(tls) => {
            let connector =
                tokio_tungstenite::Connector::Rustls(Arc::new(rustls::ClientConfig::clone(tls)));
            let addrs = crate::net::lookup_host(&host, port)
                .await
                .context(format!("failed to resolve {host}:{port}"))?;
            let socket = tokio::net::TcpStream::connect(addrs.as_slice())
                .await
                .context("failed to connect the control socket")?;
            let (socket, _) = tokio_tungstenite::client_async_tls_with_config(
                request,
                socket,
                None,
                Some(connector),
            )
            .await
            .context("failed to connect the control websocket")?;

            pump(socket, remote, events, metrics, refresh).await
        }
    }
}

async fn pump<S: AsyncRead + AsyncWrite + Unpin>(
    socket: WebSocketStream<S>,
    remote: &RemoteClient,
    events: &mpsc::Sender<SyncEvent>,
    metrics: &crate::metrics::Metrics,
    refresh: &mut mpsc::Receiver<()>,
) -> Result<(), anyhow::Error> {
    remote.set_link(true);
    metrics
        .remote_link
        .store(true, std::sync::atomic::Ordering::Relaxed);
    tracing::info!("control websocket connected");

    let (mut sink, mut stream) = socket.split();
    if events.send(SyncEvent::LinkUp).await.is_err() {
        return Ok(());
    }

    let mut poll = tokio::time::interval(POLL_INTERVAL);
    poll.tick().await;

    loop {
        tokio::select! {
            incoming = stream.next() => match incoming {
                Some(Ok(Message::Text(text))) => match serde_json::from_str(&text)? {
                    RemoteMsg::Snapshot { snapshot } => {
                        if events.send(SyncEvent::Snapshot(snapshot)).await.is_err() {
                            return Ok(());
                        }
                    }
                    RemoteMsg::MetricsRequest { req_id } => {
                        let reply = NodeMsg::Metrics { req_id, body: metrics.snapshot_json() };
                        sink.send(Message::text(serde_json::to_string(&reply)?)).await?;
                    }
                },
                Some(Ok(Message::Ping(p))) => sink.send(Message::Pong(p)).await?,
                Some(Ok(Message::Close(_))) | None => return Ok(()),
                Some(Ok(_)) => {}
                Some(Err(err)) => return Err(anyhow::anyhow!(err)),
            },
            Some(()) = refresh.recv() => {
                if let Ok(snapshot) = remote.state().await
                    && events.send(SyncEvent::Snapshot(snapshot)).await.is_err()
                {
                    return Ok(());
                }
            }
            _ = poll.tick() => {
                if let Ok(snapshot) = remote.state().await
                    && events.send(SyncEvent::Snapshot(snapshot)).await.is_err()
                {
                    return Ok(());
                }
            }
        }
    }
}
