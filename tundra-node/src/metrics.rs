use axum::{Json, Router, routing::get};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const CAPABILITIES: &[&str] = &["process_container_refs"];

#[inline]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Debug, Default)]
pub struct Drops {
    pub send_buffer_full: AtomicU64,
    pub unknown_flow: AtomicU64,
    pub frag_timeout: AtomicU64,
    pub frag_limit: AtomicU64,
    pub oversize: AtomicU64,
    pub malformed: AtomicU64,
}

impl Drops {
    fn json(&self) -> Value {
        json!({
            "send_buffer_full": self.send_buffer_full.load(Relaxed),
            "unknown_flow": self.unknown_flow.load(Relaxed),
            "frag_timeout": self.frag_timeout.load(Relaxed),
            "frag_limit": self.frag_limit.load(Relaxed),
            "oversize": self.oversize.load(Relaxed),
            "malformed": self.malformed.load(Relaxed),
        })
    }

    fn pairs(&self) -> [(&'static str, u64); 6] {
        [
            ("send_buffer_full", self.send_buffer_full.load(Relaxed)),
            ("unknown_flow", self.unknown_flow.load(Relaxed)),
            ("frag_timeout", self.frag_timeout.load(Relaxed)),
            ("frag_limit", self.frag_limit.load(Relaxed)),
            ("oversize", self.oversize.load(Relaxed)),
            ("malformed", self.malformed.load(Relaxed)),
        ]
    }
}

#[derive(Debug)]
pub struct PeerMetrics {
    pub uuid: uuid::Uuid,
    pub name: String,
    pub role: &'static str,
    pub remote: SocketAddr,

    established_unix: u64,
    established: Instant,
    conn: quinn::Connection,

    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub datagram_bytes_in: AtomicU64,
    pub datagram_bytes_out: AtomicU64,
    pub datagrams_in: AtomicU64,
    pub datagrams_out: AtomicU64,

    pub streams_open: AtomicU64,
    pub streams_total: AtomicU64,

    pub flows_open: AtomicU64,
    pub flows_opened_total: AtomicU64,
    pub flows_gc_total: AtomicU64,
    pub flows_rejected_total: AtomicU64,
    pub tcp_flows_open: AtomicU64,
    pub tcp_flows_rejected_total: AtomicU64,

    pub drain_messages_lost: AtomicU64,
    pub reauth_total: AtomicU64,
    pub drops: Drops,
}

impl PeerMetrics {
    pub fn new(
        uuid: uuid::Uuid,
        name: String,
        role: &'static str,
        conn: quinn::Connection,
    ) -> Arc<Self> {
        Arc::new(Self {
            uuid,
            name,
            role,
            remote: conn.remote_address(),

            established_unix: unix_now(),
            established: Instant::now(),
            conn,

            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            datagram_bytes_in: AtomicU64::new(0),
            datagram_bytes_out: AtomicU64::new(0),
            datagrams_in: AtomicU64::new(0),
            datagrams_out: AtomicU64::new(0),

            streams_open: AtomicU64::new(0),
            streams_total: AtomicU64::new(0),

            flows_open: AtomicU64::new(0),
            flows_opened_total: AtomicU64::new(0),
            flows_gc_total: AtomicU64::new(0),
            flows_rejected_total: AtomicU64::new(0),
            tcp_flows_open: AtomicU64::new(0),
            tcp_flows_rejected_total: AtomicU64::new(0),

            drain_messages_lost: AtomicU64::new(0),
            reauth_total: AtomicU64::new(0),
            drops: Drops::default(),
        })
    }

    #[inline]
    pub fn age(&self) -> std::time::Duration {
        self.established.elapsed()
    }

    fn json(&self) -> Value {
        let stats = self.conn.stats();
        json!({
            "uuid": self.uuid,
            "name": self.name,
            "role": self.role,
            "remote_addr": self.remote.to_string(),
            "established_unix": self.established_unix,
            "established_secs": self.established.elapsed().as_secs(),
            "path": {
                "rtt_ms": stats.path.rtt.as_secs_f64() * 1000.0,
                "cwnd": stats.path.cwnd,
                "congestion_events": stats.path.congestion_events,
                "lost_packets": stats.path.lost_packets,
                "lost_bytes": stats.path.lost_bytes,
                "sent_packets": stats.path.sent_packets,
                "black_holes_detected": stats.path.black_holes_detected,
                "current_mtu": stats.path.current_mtu,
            },
            "udp_tx": { "datagrams": stats.udp_tx.datagrams, "bytes": stats.udp_tx.bytes, "ios": stats.udp_tx.ios },
            "udp_rx": { "datagrams": stats.udp_rx.datagrams, "bytes": stats.udp_rx.bytes, "ios": stats.udp_rx.ios },
            "relay": {
                "stream_bytes_in": self.bytes_in.load(Relaxed),
                "stream_bytes_out": self.bytes_out.load(Relaxed),
                "datagram_bytes_in": self.datagram_bytes_in.load(Relaxed),
                "datagram_bytes_out": self.datagram_bytes_out.load(Relaxed),
                "datagrams_in": self.datagrams_in.load(Relaxed),
                "datagrams_out": self.datagrams_out.load(Relaxed),
                "streams_open": self.streams_open.load(Relaxed),
                "streams_total": self.streams_total.load(Relaxed),
            },
            "flows": {
                "open": self.flows_open.load(Relaxed),
                "opened_total": self.flows_opened_total.load(Relaxed),
                "gc_total": self.flows_gc_total.load(Relaxed),
                "rejected_total": self.flows_rejected_total.load(Relaxed),
                "tcp_open": self.tcp_flows_open.load(Relaxed),
                "tcp_rejected_total": self.tcp_flows_rejected_total.load(Relaxed),
            },
            "drain_messages_lost": self.drain_messages_lost.load(Relaxed),
            "reauth_total": self.reauth_total.load(Relaxed),
            "drops": self.drops.json(),
        })
    }
}

#[derive(Debug, serde::Serialize)]
pub struct Applied {
    pub binary_sha256: tundra_common::hash::Hash32,
    pub config_sha256: tundra_common::hash::Hash32,
}

impl Applied {
    pub fn load(config_sha256: tundra_common::hash::Hash32) -> Result<Self, anyhow::Error> {
        use sha2::Digest;
        use std::io::Read;

        let mut executable = std::fs::File::open("/proc/self/exe")?;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0; 64 * 1024];
        loop {
            let read = executable.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            if let Some(bytes) = buffer.get(..read) {
                hasher.update(bytes);
            }
        }

        Ok(Self {
            binary_sha256: tundra_common::hash::Hash32(hasher.finalize().into()),
            config_sha256,
        })
    }
}

#[derive(Debug)]
pub struct Metrics {
    pub applied: Option<Applied>,
    pub uuid: parking_lot::Mutex<Option<uuid::Uuid>>,
    pub epoch: AtomicU64,
    pub remote_link: AtomicBool,

    pub frontends: AtomicU64,
    pub local_streams_total: AtomicU64,
    pub local_flows_open: AtomicU64,
    pub local_drops: AtomicU64,
    pub handshakes_refused: AtomicU64,

    pub snapshots_applied: AtomicU64,
    pub frozen_flows: AtomicU64,

    started: Instant,
    peers: parking_lot::Mutex<HashMap<uuid::Uuid, Arc<PeerMetrics>>>,
    restart: parking_lot::Mutex<Option<Arc<crate::node::restart::Handover>>>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            applied: None,
            uuid: parking_lot::Mutex::new(None),
            epoch: AtomicU64::new(0),
            remote_link: AtomicBool::new(false),

            frontends: AtomicU64::new(0),
            local_streams_total: AtomicU64::new(0),
            local_flows_open: AtomicU64::new(0),
            local_drops: AtomicU64::new(0),
            handshakes_refused: AtomicU64::new(0),

            snapshots_applied: AtomicU64::new(0),
            frozen_flows: AtomicU64::new(0),

            started: Instant::now(),
            peers: parking_lot::Mutex::new(HashMap::new()),
            restart: parking_lot::Mutex::new(None),
        }
    }
}

impl Metrics {
    pub fn new_with_applied(applied: Applied) -> Self {
        Self {
            applied: Some(applied),
            ..Default::default()
        }
    }

    pub fn attach_restart(&self, handover: Arc<crate::node::restart::Handover>) {
        *self.restart.lock() = Some(handover);
    }

    pub fn attach_peer(&self, peer: Arc<PeerMetrics>) {
        self.peers.lock().insert(peer.uuid, peer);
    }

    // so a glare loser cannot erase its winner
    pub fn detach_peer(&self, peer: &Arc<PeerMetrics>) {
        let mut peers = self.peers.lock();
        if peers.get(&peer.uuid).is_some_and(|p| Arc::ptr_eq(p, peer)) {
            peers.remove(&peer.uuid);
        }
    }

    pub fn snapshot_json(&self) -> Value {
        let peers = self.peers.lock();
        let mut list: Vec<_> = peers.values().cloned().collect();
        drop(peers);
        list.sort_by_key(|p| p.uuid);

        json!({
            "applied": self.applied,
            "capabilities": CAPABILITIES,
            "node": {
                "uuid": *self.uuid.lock(),
                "uptime_secs": self.started.elapsed().as_secs(),
                "epoch": self.epoch.load(Relaxed),
                "remote_link": if self.remote_link.load(Relaxed) { "up" } else { "down" },
                "frontends": self.frontends.load(Relaxed),
                "snapshots_applied": self.snapshots_applied.load(Relaxed),
                "local_streams_total": self.local_streams_total.load(Relaxed),
                "local_flows_open": self.local_flows_open.load(Relaxed),
                "local_drops": self.local_drops.load(Relaxed),
                "handshakes_refused": self.handshakes_refused.load(Relaxed),
                "frozen_flows": self.frozen_flows.load(Relaxed),
                "peers_connected": list.len(),
            },
            "peers": list.iter().map(|p| p.json()).collect::<Vec<_>>(),
            "restart": self
                .restart
                .lock()
                .as_ref()
                .map(|h| h.json()),
        })
    }

    pub fn prometheus(&self) -> String {
        let peers = self.peers.lock();
        let mut list: Vec<_> = peers.values().cloned().collect();
        drop(peers);
        list.sort_by_key(|p| p.uuid);

        let mut out = String::new();
        let mut gauge = |name: &str, help: &str, kind: &str, body: &dyn Fn(&mut String)| {
            out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
            body(&mut out);
        };

        gauge("tundra_up", "always 1", "gauge", &|o| {
            o.push_str("tundra_up 1\n")
        });
        gauge(
            "tundra_epoch",
            "last applied snapshot epoch",
            "gauge",
            &|o| o.push_str(&format!("tundra_epoch {}\n", self.epoch.load(Relaxed))),
        );
        gauge(
            "tundra_remote_link_up",
            "control link status",
            "gauge",
            &|o| {
                o.push_str(&format!(
                    "tundra_remote_link_up {}\n",
                    u8::from(self.remote_link.load(Relaxed))
                ))
            },
        );
        gauge(
            "tundra_frontends",
            "bound frontend sockets",
            "gauge",
            &|o| {
                o.push_str(&format!(
                    "tundra_frontends {}\n",
                    self.frontends.load(Relaxed)
                ))
            },
        );
        gauge(
            "tundra_local_drops_total",
            "same-node relay drops",
            "counter",
            &|o| {
                o.push_str(&format!(
                    "tundra_local_drops_total {}\n",
                    self.local_drops.load(Relaxed)
                ))
            },
        );
        gauge(
            "tundra_handshakes_refused_total",
            "inbound handshakes refused over the handshake budget",
            "counter",
            &|o| {
                o.push_str(&format!(
                    "tundra_handshakes_refused_total {}\n",
                    self.handshakes_refused.load(Relaxed)
                ))
            },
        );
        gauge(
            "tundra_peers_connected",
            "live peer connections",
            "gauge",
            &|o| o.push_str(&format!("tundra_peers_connected {}\n", list.len())),
        );
        gauge(
            "tundra_frozen_flows",
            "relays held for a restarting peer",
            "gauge",
            &|o| {
                o.push_str(&format!(
                    "tundra_frozen_flows {}\n",
                    self.frozen_flows.load(Relaxed)
                ))
            },
        );

        let label = |p: &PeerMetrics| format!("peer=\"{}\",peer_name=\"{}\"", p.uuid, p.name);

        let mut per_peer =
            |name: &str, help: &str, kind: &str, pick: &dyn Fn(&PeerMetrics) -> f64| {
                out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
                for p in &list {
                    out.push_str(&format!("{name}{{{}}} {}\n", label(p), pick(p)));
                }
            };

        per_peer(
            "tundra_peer_rtt_seconds",
            "smoothed path RTT",
            "gauge",
            &|p| p.conn.stats().path.rtt.as_secs_f64(),
        );
        per_peer(
            "tundra_peer_cwnd_bytes",
            "congestion window",
            "gauge",
            &|p| p.conn.stats().path.cwnd as f64,
        );
        per_peer(
            "tundra_peer_mtu_bytes",
            "discovered path MTU",
            "gauge",
            &|p| p.conn.stats().path.current_mtu as f64,
        );
        per_peer(
            "tundra_peer_congestion_events_total",
            "congestion events",
            "counter",
            &|p| p.conn.stats().path.congestion_events as f64,
        );
        per_peer(
            "tundra_peer_lost_packets_total",
            "lost packets",
            "counter",
            &|p| p.conn.stats().path.lost_packets as f64,
        );
        per_peer(
            "tundra_peer_lost_bytes_total",
            "lost bytes",
            "counter",
            &|p| p.conn.stats().path.lost_bytes as f64,
        );
        per_peer(
            "tundra_peer_udp_tx_bytes_total",
            "UDP bytes sent",
            "counter",
            &|p| p.conn.stats().udp_tx.bytes as f64,
        );
        per_peer(
            "tundra_peer_udp_rx_bytes_total",
            "UDP bytes received",
            "counter",
            &|p| p.conn.stats().udp_rx.bytes as f64,
        );
        per_peer(
            "tundra_peer_stream_bytes_in_total",
            "relayed stream bytes in",
            "counter",
            &|p| p.bytes_in.load(Relaxed) as f64,
        );
        per_peer(
            "tundra_peer_stream_bytes_out_total",
            "relayed stream bytes out",
            "counter",
            &|p| p.bytes_out.load(Relaxed) as f64,
        );
        per_peer(
            "tundra_peer_datagrams_in_total",
            "tunnel datagrams received",
            "counter",
            &|p| p.datagrams_in.load(Relaxed) as f64,
        );
        per_peer(
            "tundra_peer_datagrams_out_total",
            "tunnel datagrams sent",
            "counter",
            &|p| p.datagrams_out.load(Relaxed) as f64,
        );
        per_peer(
            "tundra_peer_streams_open",
            "open relay streams",
            "gauge",
            &|p| p.streams_open.load(Relaxed) as f64,
        );
        per_peer(
            "tundra_peer_streams_total",
            "relay streams opened",
            "counter",
            &|p| p.streams_total.load(Relaxed) as f64,
        );
        per_peer("tundra_peer_flows_open", "open UDP flows", "gauge", &|p| {
            p.flows_open.load(Relaxed) as f64
        });
        per_peer(
            "tundra_peer_flows_opened_total",
            "UDP flows opened",
            "counter",
            &|p| p.flows_opened_total.load(Relaxed) as f64,
        );
        per_peer(
            "tundra_peer_flows_gc_total",
            "UDP flows collected when idle",
            "counter",
            &|p| p.flows_gc_total.load(Relaxed) as f64,
        );
        per_peer(
            "tundra_peer_reauth_total",
            "accepted re-authentications",
            "counter",
            &|p| p.reauth_total.load(Relaxed) as f64,
        );
        per_peer(
            "tundra_peer_tcp_flows_open",
            "open TCP relay flows",
            "gauge",
            &|p| p.tcp_flows_open.load(Relaxed) as f64,
        );

        let handover = self.restart.lock().clone();
        if let Some(handover) = handover {
            let counters = &handover.counters;
            out.push_str("# HELP tundra_restart_generation in-place restarts of this pid\n");
            out.push_str("# TYPE tundra_restart_generation counter\n");
            out.push_str(&format!(
                "tundra_restart_generation {}\n",
                handover.generation
            ));

            out.push_str(
                "# HELP tundra_restart_flows_resumed_total relays that survived a restart\n",
            );
            out.push_str("# TYPE tundra_restart_flows_resumed_total counter\n");
            out.push_str(&format!(
                "tundra_restart_flows_resumed_total {}\n",
                counters.flows_resumed.load(Relaxed)
            ));

            out.push_str(
                "# HELP tundra_restart_flows_killed_total relays a restart could not carry\n",
            );
            out.push_str("# TYPE tundra_restart_flows_killed_total counter\n");
            for (reason, value) in counters.killed_pairs() {
                out.push_str(&format!(
                    "tundra_restart_flows_killed_total{{reason=\"{reason}\"}} {value}\n"
                ));
            }
        }

        out.push_str("# HELP tundra_peer_datagram_drops_total dropped datagrams by reason\n");
        out.push_str("# TYPE tundra_peer_datagram_drops_total counter\n");
        for p in &list {
            for (reason, value) in p.drops.pairs() {
                out.push_str(&format!(
                    "tundra_peer_datagram_drops_total{{{},reason=\"{reason}\"}} {value}\n",
                    label(p)
                ));
            }
        }

        out
    }
}

pub fn router(metrics: &Arc<Metrics>) -> Router {
    Router::new()
        .route("/metrics.json", get(json_handler))
        .route("/metrics", get(prom_handler))
        .with_state(metrics.clone())
}

async fn json_handler(
    axum::extract::State(metrics): axum::extract::State<Arc<Metrics>>,
) -> Json<Value> {
    Json(metrics.snapshot_json())
}

async fn prom_handler(
    axum::extract::State(metrics): axum::extract::State<Arc<Metrics>>,
) -> ([(axum::http::HeaderName, &'static str); 1], String) {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        metrics.prometheus(),
    )
}

pub async fn serve(bind: SocketAddr, metrics: Arc<Metrics>) -> Result<(), anyhow::Error> {
    let app = router(&metrics);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(
        bind = %bind,
        "metrics endpoint listening"
    );
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applied_metrics_identify_the_running_executable_and_loaded_config() {
        let config_sha256 = tundra_common::hash::sha256(b"loaded config");
        let applied = Applied::load(config_sha256).unwrap();
        let binary_sha256 = tundra_common::hash::sha256(&std::fs::read("/proc/self/exe").unwrap());
        assert_eq!(applied.binary_sha256, binary_sha256);
        let metrics = Metrics::new_with_applied(applied).snapshot_json();
        assert_eq!(
            metrics["applied"]["config_sha256"],
            serde_json::json!(config_sha256)
        );
        assert_eq!(
            metrics["applied"]["binary_sha256"],
            serde_json::json!(binary_sha256)
        );
    }

    // Metrics

    #[test]
    fn idle_metrics_render_a_well_formed_document() {
        let m = Metrics::default();
        *m.uuid.lock() = Some(uuid::Uuid::from_u128(1));
        m.epoch.store(9, Relaxed);
        m.frontends.store(4, Relaxed);

        let v = m.snapshot_json();
        assert_eq!(v["node"]["epoch"], 9);
        assert_eq!(v["node"]["frontends"], 4);
        assert_eq!(v["node"]["remote_link"], "down");
        assert_eq!(v["capabilities"], serde_json::json!(CAPABILITIES));
        assert_eq!(v["peers"].as_array().unwrap().len(), 0);

        let text = m.prometheus();
        assert!(text.contains("tundra_epoch 9"));
        assert!(text.contains("tundra_remote_link_up 0"));
        assert!(text.contains("tundra_frontends 4"));
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let value = line.rsplit(' ').next().unwrap();
            assert!(value.parse::<f64>().is_ok(), "{line}");
        }
    }

    // Drops

    #[test]
    fn drop_counters_start_at_zero_and_are_all_named() {
        let d = Drops::default();
        assert!(d.pairs().iter().all(|(_, v)| *v == 0));

        let names: Vec<_> = d.pairs().iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            [
                "send_buffer_full",
                "unknown_flow",
                "frag_timeout",
                "frag_limit",
                "oversize",
                "malformed"
            ]
        );
        assert_eq!(d.json().as_object().unwrap().len(), names.len());
    }
}
