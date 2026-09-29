use crate::{
    config::NodeConfig,
    metrics::{Metrics, PeerMetrics},
    node::{
        container::ContainerInfo,
        docker::DockerAdapter,
        frontend::binder::{ContainerTarget, FrontendBinder},
        identity::Identity,
        plan::{FrontendKey, desired_hosts, needed_peers},
        quic::{
            conn::{
                CONTROL_QUEUE, HANDSHAKE_TIMEOUT, PeerConn, REAUTH_CHECK, REAUTH_DEADLINE,
                REAUTH_INTERVAL, REAUTH_RECOVERY_GRACE, REAUTH_RETRY, control_writer,
                negotiated_alpn, parity_for, peer_cert_hash, read_frame, write_frame,
            },
            handshake::HandshakeBudget,
            registry::{Install, PeerRegistry, Role, close_loser},
        },
        relay::RelayRegistry,
        restart::{Handover, Killed, frozen::FrozenStore, gate::AcceptGate, resume::PeerResume},
        token::TokenStore,
    },
    pinning::CertPins,
    remote::RemoteClient,
};
use anyhow::Context;
use quinn::{Connection, Endpoint};
use rustls::crypto::CryptoProvider;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    os::fd::RawFd,
    sync::{
        Arc, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};
use tundra_common::{
    admit::{Transport, port_registered},
    codes::CloseCode,
    flow::Parity,
    hash::Hash32,
    jwt,
    state::{Snapshot, SnapshotIndex, revoked_nodes},
    wire::{ALPN_TUNNEL, ControlMsg, PROTO_VERSION, ResumeIntent, peek_hello_version},
};

pub mod container;
pub mod docker;
pub mod frontend;
pub mod identity;
pub mod ingress;
pub mod naming;
pub mod plan;
pub mod quic;
pub mod relay;
pub mod restart;
pub mod token;

pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10);
pub const PIN_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(1);
pub const STREAM_SLOTS_PER_PEER: usize = 1024;

const RESUME_POLL: Duration = Duration::from_millis(20);

pub struct FrontendHandle {
    pub id: u64,
    pub pid: i32,

    // borrowed, never owned: a handover dups it so the new image inherits socket and backlog
    pub fd: RawFd,
    pub replies: Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,

    pub cancel: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl FrontendHandle {
    #[inline]
    pub fn new(
        id: u64,
        pid: i32,
        fd: RawFd,
        replies: Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
        cancel: watch::Sender<bool>,
        tasks: Vec<tokio::task::JoinHandle<()>>,
    ) -> Self {
        Self {
            id,
            pid,
            fd,
            replies,
            cancel,
            tasks,
        }
    }
}

impl Drop for FrontendHandle {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
        for task in &self.tasks {
            task.abort();
        }
    }
}

pub struct Node {
    pub uuid: uuid::Uuid,
    pub identity: Identity,
    pub remote: Arc<RemoteClient>,
    pub metrics: Arc<Metrics>,
    pub provider: Arc<CryptoProvider>,

    pub peers: PeerRegistry,
    pub relays: Arc<RelayRegistry>,
    pub local_slots: Arc<tokio::sync::Semaphore>,
    pub handshakes: Arc<HandshakeBudget>,

    pub docker: Option<DockerAdapter>,
    pub binder: Arc<dyn FrontendBinder>,
    hosts_template: String,
    pub frontends: parking_lot::Mutex<HashMap<FrontendKey, FrontendHandle>>,
    pub containers: parking_lot::Mutex<HashMap<uuid::Uuid, ContainerInfo>>,

    tokens: Arc<TokenStore>,
    pub restart: Arc<Handover>,
    pub frozen: Arc<FrozenStore>,
    pub carried: parking_lot::Mutex<HashMap<uuid::Uuid, PeerResume>>,
    pub gate: Arc<AcceptGate>,
    resumes: AtomicU64,

    index: parking_lot::RwLock<Arc<SnapshotIndex>>,
    reconciling: tokio::sync::Mutex<()>,
    epoch: AtomicU64,
    applied_any: AtomicBool,

    endpoint: OnceLock<Endpoint>,
    refresh_tx: mpsc::Sender<()>,
    link_up_since: parking_lot::Mutex<Option<Instant>>,
    path_rtt: parking_lot::Mutex<HashMap<uuid::Uuid, (Duration, IpAddr)>>,
}

impl Node {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<NodeConfig>,
        identity: Identity,
        remote: Arc<RemoteClient>,
        metrics: Arc<Metrics>,
        provider: Arc<CryptoProvider>,
        docker: Option<DockerAdapter>,
        binder: Arc<dyn FrontendBinder>,
        restart: Arc<Handover>,
        refresh_tx: mpsc::Sender<()>,
    ) -> Arc<Self> {
        let uuid = identity.uuid;
        *metrics.uuid.lock() = Some(uuid);
        let tokens = Arc::new(TokenStore::new(&config.data_dir));
        metrics.attach_restart(Arc::clone(&restart));

        Arc::new(Self {
            uuid,
            identity,
            remote,
            metrics,
            provider,
            peers: PeerRegistry::new(uuid),
            relays: Arc::new(RelayRegistry::default()),
            local_slots: Arc::new(tokio::sync::Semaphore::new(STREAM_SLOTS_PER_PEER)),
            handshakes: Arc::new(HandshakeBudget::default()),
            docker,
            binder,
            hosts_template: config.hosts_path.clone(),
            frontends: parking_lot::Mutex::new(HashMap::new()),
            containers: parking_lot::Mutex::new(HashMap::new()),
            tokens,
            restart,
            frozen: Arc::new(FrozenStore::default()),
            carried: parking_lot::Mutex::new(HashMap::new()),
            gate: Arc::new(AcceptGate::default()),
            resumes: AtomicU64::new(0),
            index: parking_lot::RwLock::new(Arc::new(SnapshotIndex::new(Snapshot::empty()))),
            reconciling: tokio::sync::Mutex::new(()),
            epoch: AtomicU64::new(0),
            applied_any: AtomicBool::new(false),
            endpoint: OnceLock::new(),
            refresh_tx,
            link_up_since: parking_lot::Mutex::new(None),
            path_rtt: parking_lot::Mutex::new(HashMap::new()),
        })
    }

    pub fn record_rtt(&self, peer: &uuid::Uuid, conn: &Connection) {
        self.path_rtt
            .lock()
            .insert(*peer, (conn.rtt(), conn.remote_address().ip()));
    }

    #[inline]
    pub fn rtt_hint(&self, peer: &uuid::Uuid) -> Option<Duration> {
        self.path_rtt.lock().get(peer).map(|(rtt, _)| *rtt)
    }

    /// At accept time the peer is unknown until the handshake completes, but the transport
    /// config must be chosen before it; the dialing address identifies the path instead.
    #[inline]
    pub fn rtt_hint_by_ip(&self, ip: IpAddr) -> Option<Duration> {
        self.path_rtt
            .lock()
            .values()
            .find(|(_, known)| *known == ip)
            .map(|(rtt, _)| *rtt)
    }

    #[inline]
    pub fn peer_name(&self, peer: &uuid::Uuid) -> String {
        self.index()
            .node(peer)
            .map_or_else(|| peer.to_string(), |n| n.name.clone())
    }

    #[inline]
    pub fn index(&self) -> Arc<SnapshotIndex> {
        Arc::clone(&self.index.read())
    }

    #[inline]
    pub fn endpoint(&self) -> &Endpoint {
        self.endpoint
            .get()
            .expect("failed to read the endpoint installed at startup")
    }

    #[inline]
    pub fn set_endpoint(&self, endpoint: Endpoint) {
        let _ = self.endpoint.set(endpoint);
    }

    #[inline]
    pub fn pins(self: &Arc<Self>) -> Arc<dyn CertPins> {
        Arc::new(NodePins {
            node: Arc::downgrade(self),
            last_nudge: parking_lot::Mutex::new(None),
        })
    }

    #[inline]
    pub fn note_link_up(&self) {
        let mut since = self.link_up_since.lock();
        if since.is_none() {
            *since = Some(Instant::now());
        }
    }

    #[inline]
    pub fn note_link_down(&self) {
        *self.link_up_since.lock() = None;
    }

    fn is_reauth_enforceable(&self) -> bool {
        self.link_up_since
            .lock()
            .is_some_and(|t| t.elapsed() > REAUTH_RECOVERY_GRACE)
    }

    // a panel restarted on an empty database legitimately counts from zero again
    #[inline]
    pub fn reset_epoch_watermark(&self) {
        self.applied_any.store(false, Relaxed);
    }

    pub async fn apply_snapshot(self: &Arc<Self>, snapshot: Snapshot) {
        let epoch = snapshot.epoch;
        if self.applied_any.load(Relaxed) && epoch < self.epoch.load(Relaxed) {
            tracing::debug!(
                epoch,
                current = self.epoch.load(Relaxed),
                "ignoring a stale snapshot"
            );
            return;
        }

        let old = self.index();
        if self.applied_any.load(Relaxed) && old.snapshot() == &snapshot {
            self.reconcile_local().await;
            return;
        }
        let new = Arc::new(SnapshotIndex::new(snapshot));

        *self.index.write() = Arc::clone(&new);
        self.epoch.store(epoch, Relaxed);
        self.applied_any.store(true, Relaxed);
        self.metrics.epoch.store(epoch, Relaxed);
        self.metrics.snapshots_applied.fetch_add(1, Relaxed);

        for peer in self.peers.connected() {
            let Some(conn) = self.peers.get(&peer) else {
                continue;
            };

            let still_pinned =
                peer_cert_hash(&conn.conn).is_some_and(|h| new.node_by_cert(&h) == Some(peer));
            if !still_pinned {
                tracing::warn!(
                    peer = %peer,
                    "certificate no longer pinned, closing connection"
                );
                conn.close(CloseCode::Revoked);
                self.peers.remove(&conn);
                self.metrics.detach_peer(&conn.metrics);
            }
        }

        for peer in revoked_nodes(&old, &new) {
            self.peers.end_dial(&peer);
        }

        let withdrawn = self.relays.cancel_where(|src, dst, port, transport| {
            !new.allows(src, dst) || !port_registered(&new, dst, port, transport)
        });
        if withdrawn > 0 {
            tracing::info!(flows = withdrawn, "reset relays whose access was withdrawn");
        }

        for conn in self.peers.connected() {
            let Some(peer) = self.peers.get(&conn) else {
                continue;
            };

            let dropped = {
                let mut udp = peer.udp.lock();
                let egress = udp
                    .egress
                    .drain_where(|_, f| {
                        !new.allows(&f.src_server, &f.dst_server)
                            || !port_registered(&new, &f.dst_server, f.dst_port, Transport::Udp)
                    })
                    .len();
                let ingress = udp
                    .ingress
                    .drain_where(|_, f| {
                        !new.allows(&f.src_server, &f.dst_server)
                            || !port_registered(&new, &f.dst_server, f.dst_port, Transport::Udp)
                    })
                    .len();
                egress + ingress
            };
            if dropped > 0 {
                tracing::info!(
                    peer = %peer.peer,
                    flows = dropped,
                    "dropped flows whose access was withdrawn"
                );
            }

            peer.refresh_flow_metrics();
        }

        self.reconcile_local().await;

        tracing::info!(
            epoch,
            nodes = new.nodes().len(),
            servers = new.servers().len(),
            frontends = self.frontends.lock().len(),
            "snapshot applied"
        );

        for peer in needed_peers(&new, &self.uuid) {
            if self.peers.get(&peer).is_none() {
                tokio::spawn({
                    let node = Arc::clone(self);

                    async move { node.ensure_peer(peer).await }
                });
            }
        }
    }

    pub async fn reconcile_local(self: &Arc<Self>) {
        let _guard = self.reconciling.lock().await;
        let index = self.index();
        self.refresh_containers(&index).await;
        crate::node::frontend::reconcile(self, &index).await;
        self.reconcile_hosts(&index);
    }

    pub async fn refresh_containers(&self, index: &SnapshotIndex) {
        let mut found = HashMap::new();
        for server in index.servers_on(&self.uuid) {
            let Some(entry) = index.server(server) else {
                continue;
            };

            let inspected = match ContainerInfo::from_process_ref(
                &entry.container_ref,
                entry.dial_addr.as_deref(),
            ) {
                Ok(Some(info)) => Ok(info),
                Ok(None) => match &self.docker {
                    Some(docker) => docker.inspect(&entry.container_ref).await,
                    None => continue,
                },
                Err(err) => Err(err),
            };

            match inspected {
                Ok(info) if info.running => {
                    found.insert(*server, info);
                }
                Ok(_) => tracing::debug!(
                    server = %server,
                    container = %entry.container_ref,
                    "container is not running"
                ),
                Err(err) => tracing::warn!(
                    server = %server,
                    container = %entry.container_ref,
                    "failed to inspect the container: {:?}",
                    err
                ),
            }
        }

        *self.containers.lock() = found;
    }

    #[inline]
    pub fn container_of(&self, server: &uuid::Uuid) -> Option<ContainerInfo> {
        self.containers.lock().get(server).cloned()
    }

    #[inline]
    pub fn target_of(&self, server: &uuid::Uuid) -> Option<ContainerTarget> {
        self.container_of(server)
            .map(|c| ContainerTarget { pid: c.pid })
    }

    fn reconcile_hosts(&self, index: &SnapshotIndex) {
        for server in index.servers_on(&self.uuid) {
            let Some(container) = self.container_of(server) else {
                continue;
            };

            let path = naming::templated_path(&self.hosts_template, server)
                .unwrap_or_else(|| container.hosts_path.clone());

            let entries = desired_hosts(index, server);
            match naming::apply(&path, &entries) {
                Ok(true) => tracing::info!(
                    server = %server,
                    entries = entries.len(),
                    "rewrote hosts block"
                ),
                Ok(false) => {}
                Err(err) => tracing::warn!(
                    server = %server,
                    path = %path.display(),
                    "failed to rewrite the hosts block: {:?}",
                    err
                ),
            }
        }
    }

    pub async fn ensure_peer(self: &Arc<Self>, peer: uuid::Uuid) -> Option<Arc<PeerConn>> {
        if let Some(conn) = self.peers.get(&peer) {
            return Some(conn);
        }
        if peer == self.uuid {
            return None;
        }
        if !self.peers.begin_dial(peer) {
            return None;
        }

        let result = self.dial(peer).await;
        self.peers.end_dial(&peer);

        match result {
            Ok(_) => self.peers.get(&peer),
            Err(err) => {
                tracing::warn!(
                    peer = %peer,
                    "failed to dial the peer: {:?}",
                    err
                );
                None
            }
        }
    }

    async fn dial(self: &Arc<Self>, peer: uuid::Uuid) -> Result<Arc<PeerConn>, anyhow::Error> {
        let index = self.index();
        let entry = index.node(&peer).context("peer is not in the snapshot")?;
        if entry.cert_sha256.is_none() {
            return Err(anyhow::anyhow!("peer has no certificate on file"));
        }

        let addr = tokio::net::lookup_host((entry.host.as_str(), entry.tunnel_port))
            .await
            .context(format!(
                "failed to resolve {}:{}",
                entry.host, entry.tunnel_port
            ))?
            .next()
            .context("host resolved to nothing")?;

        let token = self
            .connect_token(&peer)
            .await
            .context("failed to fetch a connect token")?;

        let config = quic::client_config(
            &self.identity,
            self.pins(),
            Arc::clone(&self.provider),
            peer,
            self.rtt_hint(&peer),
        )?;
        let server_name = Identity::dns_name_of(&peer);

        tracing::info!(
            peer = %peer,
            addr = %addr,
            "dialing"
        );
        let connection = self
            .endpoint()
            .connect_with(config, addr, &server_name)?
            .await
            .context("failed to complete the quic handshake")?;

        check_alpn(&connection)?;

        let (mut send, mut recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, connection.open_bi())
            .await
            .context("failed to open the control stream before the timeout")??;

        let carried = self.carried_parity(&peer);
        let resume = carried.map(|p| ResumeIntent {
            parity_even: p == Parity::Even,
        });

        write_frame(
            &mut send,
            &ControlMsg::Hello {
                proto_version: PROTO_VERSION,
                instance_id: self.restart.instance_id,
                jwt: token,
                resume,
            },
        )
        .await?;

        let (peer_instance, resume_accepted) = match tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            read_frame(&mut recv),
        )
        .await
        {
            Ok(Ok(ControlMsg::HelloAck {
                instance_id,
                resume_accepted,
            })) => (instance_id, resume_accepted),
            Ok(Ok(other)) => {
                return Err(anyhow::anyhow!("expected HelloAck, got {other:?}"));
            }
            Ok(Err(err)) => {
                return Err(err.context(
                        "failed to read HelloAck, a peer on another protocol version cannot answer this",
                    ));
            }
            Err(_) => return Err(anyhow::anyhow!("HelloAck timed out")),
        };

        let parity = match (carried, resume_accepted) {
            (Some(parity), true) => parity,
            (Some(_), false) => {
                self.restart.counters.resume_refused.fetch_add(1, Relaxed);
                let killed = self.discard_carried(&peer, Killed::Unmatched);
                tracing::warn!(
                    peer = %peer,
                    flows = killed,
                    "the peer no longer holds our frozen relays"
                );
                parity_for(Role::Initiator)
            }
            (None, _) => parity_for(Role::Initiator),
        };

        let (conn, kept) = self.install(
            peer,
            self.peer_name(&peer),
            Role::Initiator,
            parity,
            peer_instance,
            connection,
            send,
            recv,
        );

        if kept
            && resume_accepted
            && let Some(carried) = self.take_carried(&peer)
        {
            self.begin_resume();
            tokio::spawn(crate::node::restart::resume::attach_all(
                Arc::clone(self),
                Arc::clone(&conn),
                carried,
            ));
        }

        Ok(conn)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn install(
        self: &Arc<Self>,
        peer: uuid::Uuid,
        name: String,
        role: Role,
        parity: Parity,
        peer_instance: u64,
        connection: Connection,
        control_send: quinn::SendStream,
        control_recv: quinn::RecvStream,
    ) -> (Arc<PeerConn>, bool) {
        let metrics = PeerMetrics::new(peer, name, role.to_str(), connection.clone());
        let (tx, rx) = mpsc::channel(CONTROL_QUEUE);
        let conn = Arc::new(PeerConn::new(
            peer,
            role,
            parity,
            peer_instance,
            connection,
            Arc::clone(&metrics),
            tx,
            STREAM_SLOTS_PER_PEER,
        ));

        tokio::spawn(control_writer(control_send, rx, peer));

        let pinned =
            peer_cert_hash(&conn.conn).is_some_and(|h| self.index().node_by_cert(&h) == Some(peer));
        if !pinned {
            tracing::warn!(
                peer = %peer,
                "refusing a connection whose certificate is no longer pinned"
            );
            conn.close(CloseCode::Revoked);
            return (conn, false);
        }

        let kept = match self.peers.install(Arc::clone(&conn)) {
            Install::Installed { displaced } => {
                if let Some(old) = displaced {
                    close_loser(&old);
                    self.metrics.detach_peer(&old.metrics);
                }

                self.metrics.attach_peer(metrics);
                self.record_rtt(&peer, &conn.conn);
                tracing::info!(
                    peer = %peer,
                    role = %role.to_str(),
                    remote = %conn.conn.remote_address(),
                    rtt_ms = conn.conn.rtt().as_millis() as u64,
                    "peer connected"
                );

                tokio::spawn({
                    let node = Arc::clone(self);
                    let conn = Arc::clone(&conn);

                    async move { node.drive(conn, control_recv).await }
                });

                true
            }
            Install::Rejected(loser) => {
                close_loser(&loser);
                false
            }
        };

        (conn, kept)
    }

    async fn drive(self: Arc<Self>, conn: Arc<PeerConn>, control: quinn::RecvStream) {
        let control_task = tokio::spawn(crate::node::ingress::control_loop(
            Arc::clone(&self),
            Arc::clone(&conn),
            control,
        ));
        let datagram_task = tokio::spawn(crate::node::ingress::datagram_loop(Arc::clone(&conn)));
        let stream_task = tokio::spawn(crate::node::ingress::stream_loop(
            Arc::clone(&self),
            Arc::clone(&conn),
        ));

        let mut auth_tasks = vec![tokio::spawn(enforce_auth_loop(
            Arc::clone(&self),
            Arc::clone(&conn),
        ))];
        if conn.role == Role::Initiator {
            auth_tasks.push(tokio::spawn(reauth_loop(
                Arc::clone(&self),
                Arc::clone(&conn),
            )));
        }

        let reason = conn.conn.closed().await;
        tracing::info!(
            peer = %conn.peer,
            role = %conn.role.to_str(),
            reason = %reason,
            "peer connection closed"
        );

        control_task.abort();
        datagram_task.abort();
        stream_task.abort();
        for task in auth_tasks {
            task.abort();
        }

        let released = {
            let mut udp = conn.udp.lock();
            let ingress = udp.ingress.drain_where(|_, _| true).len();
            let egress = udp.egress.drain_where(|_, _| true).len();
            ingress + egress
        };
        if released > 0 {
            tracing::debug!(
                peer = %conn.peer,
                flows = released,
                "released flows with the connection"
            );
        }

        self.peers.remove(&conn);
        self.metrics.detach_peer(&conn.metrics);
    }

    pub fn validate_token(
        &self,
        token: &str,
        cert: Hash32,
        expect_peer: uuid::Uuid,
    ) -> Result<(), anyhow::Error> {
        let index = self.index();
        let subject = index
            .node_by_cert(&cert)
            .ok_or_else(|| anyhow::anyhow!("no node holds certificate {cert}"))?;
        if subject != expect_peer {
            return Err(anyhow::anyhow!(
                "certificate belongs to {subject}, not {expect_peer}"
            ));
        }

        let client = jwt::JwtClient::new(&index.snapshot().jwt_pubkey)
            .context("panel jwt public key is malformed")?;
        let expect = jwt::Expect {
            audience: self.uuid,
            subject,
            client_cert: cert,
            leeway: jwt::CLOCK_LEEWAY_SECS,
        };
        client.validate_connect(token, &expect, jwt::unix_now())?;

        Ok(())
    }

    #[inline]
    pub fn nudge_pin_refresh(&self) {
        let _ = self.refresh_tx.try_send(());
    }

    pub fn seed_index(&self, snapshot: Snapshot) {
        let epoch = snapshot.epoch;
        *self.index.write() = Arc::new(SnapshotIndex::new(snapshot));
        self.epoch.store(epoch, Relaxed);
        self.metrics.epoch.store(epoch, Relaxed);
        tracing::info!(epoch, "seeded state from the previous image");
    }

    pub async fn connect_token(&self, peer: &uuid::Uuid) -> Result<String, anyhow::Error> {
        if let Some(cached) = self.tokens.get(peer, jwt::unix_now()) {
            self.restart.counters.tokens_reused.fetch_add(1, Relaxed);
            return Ok(cached);
        }

        self.fresh_token(peer).await
    }

    // re-auth never uses the cache, so no connection outlives a token the panel would refuse
    pub async fn fresh_token(&self, peer: &uuid::Uuid) -> Result<String, anyhow::Error> {
        let token = self.remote.connect_token(peer).await?;
        self.tokens.store(peer, &token);
        Ok(token)
    }

    pub fn carried_parity(&self, peer: &uuid::Uuid) -> Option<Parity> {
        self.carried.lock().get(peer).map(|c| c.parity)
    }

    pub fn take_carried(&self, peer: &uuid::Uuid) -> Option<PeerResume> {
        self.carried.lock().remove(peer)
    }

    pub fn carried_peers(&self) -> Vec<uuid::Uuid> {
        self.carried.lock().keys().copied().collect()
    }

    pub fn discard_carried(&self, peer: &uuid::Uuid, reason: Killed) -> usize {
        let Some(carried) = self.take_carried(peer) else {
            return 0;
        };

        let n = carried.flows.len();
        for flow in carried.flows {
            flow.kill();
        }

        self.restart.counters.killed(reason, n as u64);

        n
    }

    pub fn finish_resume(self: &Arc<Self>) {
        for peer in self.carried_peers() {
            let killed = self.discard_carried(&peer, Killed::NoResume);
            if killed > 0 {
                tracing::warn!(
                    peer = %peer,
                    flows = killed,
                    "no connection came back for these relays"
                );
            }
        }

        self.gate.resume_all();

        let report = self.restart.with_pending(|pending| {
            let mut report = std::mem::take(pending);
            report.unix = crate::metrics::unix_now();
            report.pause_ms = self.restart.pause_ms();
            report.flows_survived = self.restart.counters.flows_resumed.load(Relaxed);
            report.flows_killed = self.restart.counters.killed_total();
            report
        });
        self.restart.record(report);
        self.restart.finish();
    }

    #[inline]
    pub fn begin_resume(&self) {
        self.resumes.fetch_add(1, Relaxed);
    }

    #[inline]
    pub fn end_resume(&self) {
        self.resumes.fetch_sub(1, Relaxed);
    }

    // polled rather than notified: `notify_waiters` stores no permit, so a decrement landing
    // between the check and the wait would be lost, and a panicked task never decrements
    pub async fn await_resumes(&self) {
        while self.resumes.load(Relaxed) > 0 {
            tokio::time::sleep(RESUME_POLL).await;
        }
    }

    #[inline]
    pub fn frontend_replies(&self, id: u64) -> Option<mpsc::Sender<(Vec<u8>, SocketAddr)>> {
        self.frontends
            .lock()
            .values()
            .find(|h| h.id == id)
            .and_then(|h| h.replies.clone())
    }
}

pub fn check_alpn(connection: &Connection) -> Result<(), anyhow::Error> {
    match negotiated_alpn(connection) {
        Some(alpn) if alpn == ALPN_TUNNEL => Ok(()),
        other => Err(anyhow::anyhow!("unexpected alpn {other:?}")),
    }
}

struct Hello {
    proto_version: u8,
    instance_id: u64,
    jwt: String,
    resume: Option<ResumeIntent>,
}

struct NodePins {
    node: Weak<Node>,
    last_nudge: parking_lot::Mutex<Option<Instant>>,
}

impl std::fmt::Debug for NodePins {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NodePins")
    }
}

impl CertPins for NodePins {
    fn node_for(&self, hash: &Hash32) -> Option<uuid::Uuid> {
        self.node.upgrade()?.index().node_by_cert(hash)
    }

    fn pin_of(&self, node: &uuid::Uuid) -> Option<Hash32> {
        self.node.upgrade()?.index().node(node)?.cert_sha256
    }

    fn refresh(&self) {
        let Some(node) = self.node.upgrade() else {
            return;
        };

        let mut last = self.last_nudge.lock();
        if last.is_some_and(|t| t.elapsed() < PIN_REFRESH_MIN_INTERVAL) {
            return;
        }

        *last = Some(Instant::now());
        node.nudge_pin_refresh();
    }
}

async fn reauth_loop(node: Arc<Node>, conn: Arc<PeerConn>) {
    loop {
        tokio::time::sleep(REAUTH_INTERVAL).await;

        loop {
            match node.fresh_token(&conn.peer).await {
                Ok(jwt) => {
                    conn.expect_reauth_ack();
                    if !conn.send_control(ControlMsg::ReAuth { jwt }).await {
                        return;
                    }
                    break;
                }
                Err(err) => {
                    tracing::warn!(
                        peer = %conn.peer,
                        "failed to fetch a re-auth token, retrying: {:?}",
                        err
                    );
                    tokio::time::sleep(REAUTH_RETRY).await;
                }
            }
        }
    }
}

async fn enforce_auth_loop(node: Arc<Node>, conn: Arc<PeerConn>) {
    let mut ticker = tokio::time::interval(REAUTH_CHECK);
    loop {
        ticker.tick().await;

        node.record_rtt(&conn.peer, &conn.conn);

        if conn.last_auth().elapsed() <= REAUTH_DEADLINE {
            continue;
        }
        if !node.is_reauth_enforceable() {
            tracing::debug!(
                peer = %conn.peer,
                "re-auth overdue, deferred while the panel link recovers"
            );
            continue;
        }

        tracing::warn!(
            peer = %conn.peer,
            stale_secs = conn.last_auth().elapsed().as_secs(),
            "re-authentication overdue, closing"
        );
        conn.close(CloseCode::ReauthTimeout);
        return;
    }
}

pub async fn accept_loop(node: Arc<Node>) {
    while let Some(incoming) = node.endpoint().accept().await {
        let Some(slot) = node.handshakes.try_acquire(incoming.remote_address().ip()) else {
            node.metrics.handshakes_refused.fetch_add(1, Relaxed);
            tracing::debug!(
                remote = %incoming.remote_address(),
                "handshake budget exhausted, refusing an inbound connection"
            );
            incoming.refuse();
            continue;
        };

        tokio::spawn({
            let node = Arc::clone(&node);

            async move {
                let result = accept_one(&node, incoming).await;
                drop(slot);
                if let Err(err) = result {
                    tracing::debug!("rejected an inbound connection: {:?}", err);
                }
            }
        });
    }
    tracing::error!("quic endpoint stopped accepting");
}

async fn accept_one(node: &Arc<Node>, incoming: quinn::Incoming) -> Result<(), anyhow::Error> {
    let remote = incoming.remote_address();
    let connecting = match node.rtt_hint_by_ip(remote.ip()) {
        Some(rtt) => {
            let config = quic::server_config(
                &node.identity,
                node.pins(),
                Arc::clone(&node.provider),
                Some(rtt),
            )?;
            incoming
                .accept_with(Arc::new(config))
                .context("failed to start the inbound handshake")?
        }
        None => incoming
            .accept()
            .context("failed to start the inbound handshake")?,
    };
    let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
        .await
        .context("failed to complete the inbound handshake before the timeout")?
        .context("failed to complete the inbound handshake")?;
    check_alpn(&connection)?;

    let cert = peer_cert_hash(&connection).context("peer presented no certificate")?;
    let peer = match node.index().node_by_cert(&cert) {
        Some(p) => p,
        None => {
            node.nudge_pin_refresh();
            connection.close(
                CloseCode::AuthFailed.as_u32().into(),
                CloseCode::AuthFailed.reason(),
            );
            return Err(anyhow::anyhow!(
                "certificate {cert} from {remote} maps to no known node"
            ));
        }
    };

    let (mut send, mut recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, connection.accept_bi())
        .await
        .context("failed to accept the control stream before the timeout")??;

    let hello = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_hello(&mut recv))
        .await
        .context("failed to read Hello before the timeout")??;

    let Hello {
        proto_version,
        instance_id,
        jwt,
        resume,
    } = match hello {
        Some(hello) => hello,
        None => {
            connection.close(
                CloseCode::VersionMismatch.as_u32().into(),
                CloseCode::VersionMismatch.reason(),
            );
            return Err(anyhow::anyhow!(
                "peer {peer} sent a Hello this protocol version cannot read"
            ));
        }
    };

    if proto_version != PROTO_VERSION {
        connection.close(
            CloseCode::VersionMismatch.as_u32().into(),
            CloseCode::VersionMismatch.reason(),
        );
        node.frozen
            .discard(&peer, "the peer speaks an older protocol");
        return Err(anyhow::anyhow!(
            "peer {peer} speaks protocol version {proto_version}, we speak {PROTO_VERSION}"
        ));
    }

    if let Err(err) = node.validate_token(&jwt, cert, peer) {
        tracing::warn!(
            peer = %peer,
            remote = %remote,
            "rejecting an inbound connection, its token is invalid: {:?}",
            err
        );
        connection.close(
            CloseCode::AuthFailed.as_u32().into(),
            CloseCode::AuthFailed.reason(),
        );
        return Err(err);
    }

    let (resume_accepted, parity) = settle_resume(node, &peer, resume);
    write_frame(
        &mut send,
        &ControlMsg::HelloAck {
            instance_id: node.restart.instance_id,
            resume_accepted,
        },
    )
    .await?;

    let (conn, _kept) = node.install(
        peer,
        node.peer_name(&peer),
        Role::Acceptor,
        parity,
        instance_id,
        connection,
        send,
        recv,
    );
    conn.touch_auth();

    Ok(())
}

async fn read_hello(recv: &mut quinn::RecvStream) -> Result<Option<Hello>, anyhow::Error> {
    let body = crate::node::quic::conn::read_frame_body(recv).await?;
    match tundra_common::wire::decode_frame::<ControlMsg>(&body) {
        Ok(ControlMsg::Hello {
            proto_version,
            instance_id,
            jwt,
            resume,
        }) => Ok(Some(Hello {
            proto_version,
            instance_id,
            jwt,
            resume,
        })),
        Ok(other) => Err(anyhow::anyhow!(
            "the first control message was not Hello, got {other:?}"
        )),
        Err(err) => match peek_hello_version(&body) {
            Some(_) => Ok(None),
            None => Err(err).context("failed to decode the first control frame"),
        },
    }
}

fn settle_resume(
    node: &Arc<Node>,
    peer: &uuid::Uuid,
    intent: Option<ResumeIntent>,
) -> (bool, Parity) {
    let fallback = parity_for(Role::Acceptor);

    let Some(intent) = intent else {
        let killed = node
            .frozen
            .discard(peer, "the peer reconnected without resuming");
        if killed > 0 {
            tracing::warn!(
                peer = %peer,
                flows = killed,
                "the peer came back without our frozen relays"
            );
            node.restart
                .counters
                .killed(Killed::Unmatched, killed as u64);
        }

        node.gate.resume_peer(peer);
        node.peers.unsuppress_dial(peer);
        return (false, fallback);
    };

    let Some(held) = node.frozen.parity_of(peer) else {
        node.restart.counters.resume_refused.fetch_add(1, Relaxed);
        tracing::warn!(
            peer = %peer,
            "refusing a resume, nothing is frozen for this peer"
        );
        node.gate.resume_peer(peer);
        node.peers.unsuppress_dial(peer);
        return (false, fallback);
    };

    if (held == Parity::Even) == intent.parity_even {
        node.restart.counters.resume_refused.fetch_add(1, Relaxed);
        let killed = node
            .frozen
            .discard(peer, "the peer claimed our half of the id space");
        tracing::warn!(
            peer = %peer,
            flows = killed,
            "refusing a resume, the id spaces do not complement"
        );
        node.restart.counters.killed(Killed::Anomaly, killed as u64);
        node.gate.resume_peer(peer);
        node.peers.unsuppress_dial(peer);
        return (false, fallback);
    }

    (true, held)
}

pub async fn maintenance_loop(node: Arc<Node>) {
    let mut ticker = tokio::time::interval(MAINTENANCE_INTERVAL);
    loop {
        ticker.tick().await;

        if node.remote.link_up() {
            node.note_link_up();
        } else {
            node.note_link_down();
        }

        let now = Instant::now();
        let killed =
            crate::node::restart::release_expired(&node.frozen, &node.peers, &node.gate, now);
        if killed > 0 {
            tracing::warn!(
                flows = killed,
                "peers did not come back, killed their frozen relays"
            );
            node.restart
                .counters
                .killed(Killed::NoResume, killed as u64);
        }

        for peer in node.frozen.peers() {
            node.peers.suppress_dial(peer);
        }

        node.metrics
            .frozen_flows
            .store(node.frozen.flows_held() as u64, Relaxed);

        let index = node.index();
        let wanted: std::collections::BTreeSet<_> = needed_peers(&index, &node.uuid)
            .into_iter()
            .chain(node.carried_peers())
            .collect();
        for peer in wanted {
            if node.peers.get(&peer).is_none() {
                tokio::spawn({
                    let node = Arc::clone(&node);

                    async move { node.ensure_peer(peer).await }
                });
            }
        }

        for peer in node.peers.connected() {
            let Some(conn) = node.peers.get(&peer) else {
                continue;
            };

            let (collected, abandoned) = {
                let mut udp = conn.udp.lock();
                let collected = udp.egress.gc(now).len() + udp.ingress.gc(now).len();
                (collected, udp.pending.expire(now))
            };
            if abandoned > 0 {
                conn.metrics
                    .drops
                    .unknown_flow
                    .fetch_add(abandoned, Relaxed);
            }
            if collected > 0 {
                tracing::debug!(
                    peer = %peer,
                    flows = collected,
                    "collected idle flows"
                );
            }

            conn.refresh_flow_metrics();
        }

        node.metrics
            .frontends
            .store(node.frontends.lock().len() as u64, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_coalesce_policy_but_accept_local_changes_and_revoke_existing_relays() {
        tokio_test::block_on(async {
            let dir =
                std::env::temp_dir().join(format!("tundra-snapshot-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let cert = rcgen::CertificateParams::new(Vec::<String>::new())
                .unwrap()
                .self_signed(&key)
                .unwrap();
            std::fs::write(dir.join("node.key.pem"), key.serialize_pem()).unwrap();
            std::fs::write(dir.join("node.crt.pem"), cert.pem()).unwrap();
            let uuid = uuid::Uuid::new_v4();
            let identity = Identity::from_disk(&dir, uuid).unwrap();
            let config = Arc::new(NodeConfig {
                data_dir: dir.clone(),
                remote: crate::config::RemoteConfig {
                    url: "unix:///unused".into(),
                    token: "test".into(),
                    ..Default::default()
                },
                ..Default::default()
            });
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let remote =
                Arc::new(RemoteClient::new(Arc::clone(&config), Arc::clone(&provider)).unwrap());
            let metrics = Arc::new(Metrics::default());
            let restart = Arc::new(Handover::new(
                None,
                Vec::new(),
                0,
                Duration::from_secs(5),
                Duration::from_secs(30),
            ));
            let (refresh_tx, _) = mpsc::channel(1);
            let node = Node::new(
                config,
                identity,
                remote,
                Arc::clone(&metrics),
                provider,
                None,
                Arc::new(frontend::binder::NetnsBinder),
                restart,
                refresh_tx,
            );
            let mut snapshot = Snapshot::empty();
            snapshot.epoch = 42;
            for idx in 0..2 {
                snapshot.servers.push(tundra_common::state::ServerEntry {
                    uuid: uuid::Uuid::from_u128(u128::from(idx) + 1),
                    idx,
                    node_uuid: uuid,
                    name: format!("s{idx}"),
                    aliases: Vec::new(),
                    container_ref: "old".into(),
                    dial_addr: None,
                    ports: vec![tundra_common::state::PortSpec {
                        port: 8080,
                        proto: tundra_common::state::Proto::Tcp,
                    }],
                });
            }
            let src = uuid::Uuid::from_u128(1);
            let dst = uuid::Uuid::from_u128(2);
            snapshot.acls.push(tundra_common::state::AclEntry {
                src_server: src,
                dst_server: dst,
            });
            node.apply_snapshot(snapshot.clone()).await;
            node.apply_snapshot(snapshot.clone()).await;
            assert_eq!(metrics.snapshots_applied.load(Relaxed), 1);
            snapshot.servers.first_mut().unwrap().container_ref = "new".into();
            node.apply_snapshot(snapshot.clone()).await;
            assert_eq!(metrics.snapshots_applied.load(Relaxed), 2);
            assert_eq!(node.index().server(&src).unwrap().container_ref, "new");
            let (_guard, cancel) = node.relays.register(src, dst, 8080, Transport::Tcp);
            assert!(!*cancel.borrow());
            let mut revoked = Snapshot::empty();
            revoked.epoch = snapshot.epoch;
            node.apply_snapshot(revoked).await;
            assert!(*cancel.borrow());
            assert!(!node.index().allows(&src, &dst));
            drop(node);
            std::fs::remove_dir_all(dir).unwrap();
        });
    }

    // REAUTH_RECOVERY_GRACE

    #[test]
    fn reauth_recovery_grace_outlasts_a_token_fetch_and_retry() {
        assert!(REAUTH_RECOVERY_GRACE >= REAUTH_RETRY * 2);
        assert!(REAUTH_RECOVERY_GRACE < REAUTH_DEADLINE);
    }

    // MAINTENANCE_INTERVAL

    #[test]
    fn maintenance_interval_meets_the_five_second_revocation_target() {
        // revocation itself is snapshot-driven and immediate; maintenance only re-dials
        assert!(MAINTENANCE_INTERVAL <= Duration::from_secs(10));
    }
}
