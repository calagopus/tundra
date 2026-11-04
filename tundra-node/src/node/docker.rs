use anyhow::Context;
use bollard::{
    Docker,
    query_parameters::{EventsOptions, EventsOptionsBuilder},
};
use futures::{Stream, StreamExt};
use std::{collections::HashMap, net::Ipv4Addr, path::PathBuf, pin::Pin};

use super::container::ContainerInfo;

fn classify(msg: bollard::models::EventMessage) -> Option<ContainerEvent> {
    let actor = msg.actor?;
    let id = actor.id?;
    let name = actor
        .attributes
        .as_ref()
        .and_then(|a| a.get("name"))
        .cloned();

    match msg.action.as_deref() {
        Some("start") => Some(ContainerEvent::Started { id, name }),
        Some("die") => Some(ContainerEvent::Died { id, name }),
        _ => None,
    }
}

fn first_ipv4(networks: &HashMap<String, bollard::models::EndpointSettings>) -> Option<Ipv4Addr> {
    let mut names: Vec<_> = networks.keys().collect();
    names.sort();

    for name in names {
        let Some(address) = networks
            .get(name)
            .and_then(|n| n.ip_address.as_deref())
            .filter(|s| !s.is_empty())
        else {
            continue;
        };

        if let Ok(ip) = address.parse() {
            return Some(ip);
        }
    }

    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerEvent {
    Started { id: String, name: Option<String> },
    Died { id: String, name: Option<String> },
}

#[derive(Clone)]
pub struct DockerAdapter {
    docker: Docker,
}

impl DockerAdapter {
    pub fn new() -> Result<Self, anyhow::Error> {
        Ok(Self {
            docker: Docker::connect_with_local_defaults().context("failed to connect to docker")?,
        })
    }

    pub async fn inspect(&self, container_ref: &str) -> Result<ContainerInfo, anyhow::Error> {
        let resp = self
            .docker
            .inspect_container(
                container_ref,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await
            .context(format!("failed to inspect container {container_ref}"))?;

        let Some(id) = resp.id.clone() else {
            return Err(anyhow::anyhow!("container has no id"));
        };

        let state = resp.state.as_ref();
        let running = state.and_then(|s| s.running).unwrap_or(false);
        let pid = state.and_then(|s| s.pid).unwrap_or(0);

        if running && pid <= 0 {
            return Err(anyhow::anyhow!(
                "container {container_ref} is running but reported pid {pid}"
            ));
        }

        let ip = resp
            .network_settings
            .as_ref()
            .and_then(|ns| ns.networks.as_ref())
            .and_then(first_ipv4);

        let hosts_path = resp
            .hosts_path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("/var/lib/docker/containers/{id}/hosts")));

        Ok(ContainerInfo {
            id,
            pid: pid as i32,
            running,
            ip,
            hosts_path,
        })
    }

    // not filtered by container: a server can be adopted between subscribing and the event
    // arriving, so only the reconciler, which holds the snapshot, can decide what to ignore
    pub fn events(&self) -> Pin<Box<dyn Stream<Item = ContainerEvent> + Send>> {
        let mut filters = HashMap::new();
        filters.insert("type", vec!["container"]);
        filters.insert("event", vec!["start", "die"]);

        let options: EventsOptions = EventsOptionsBuilder::new().filters(&filters).build();

        Box::pin(
            self.docker
                .events(Some(options))
                .filter_map(|event| async move { event.ok().and_then(classify) }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::{EndpointSettings, EventActor, EventMessage};

    fn endpoint(ip: &str) -> EndpointSettings {
        EndpointSettings {
            ip_address: Some(ip.to_owned()),
            ..Default::default()
        }
    }

    // first_ipv4

    #[test]
    fn first_ipv4_takes_the_lowest_network_name_and_skips_blanks() {
        let mut nets = HashMap::new();
        nets.insert("zulu".to_owned(), endpoint("172.20.0.9"));
        nets.insert("bridge".to_owned(), endpoint("172.17.0.2"));
        assert_eq!(first_ipv4(&nets), Some(Ipv4Addr::new(172, 17, 0, 2)));

        let mut nets = HashMap::new();
        nets.insert("bridge".to_owned(), endpoint(""));
        nets.insert("overlay".to_owned(), endpoint("10.1.2.3"));
        assert_eq!(first_ipv4(&nets), Some(Ipv4Addr::new(10, 1, 2, 3)));

        assert_eq!(first_ipv4(&HashMap::new()), None);
    }

    // classify

    #[test]
    fn classify_surfaces_only_start_and_die_events() {
        let event = |action: &str| EventMessage {
            action: Some(action.to_owned()),
            actor: Some(EventActor {
                id: Some("abc123".to_owned()),
                attributes: Some(HashMap::from([("name".to_owned(), "srv".to_owned())])),
            }),
            ..Default::default()
        };

        assert_eq!(
            classify(event("start")),
            Some(ContainerEvent::Started {
                id: "abc123".into(),
                name: Some("srv".into())
            })
        );
        assert_eq!(
            classify(event("die")),
            Some(ContainerEvent::Died {
                id: "abc123".into(),
                name: Some("srv".into())
            })
        );
        assert_eq!(classify(event("health_status: healthy")), None);
        assert_eq!(classify(event("destroy")), None);
        assert_eq!(classify(EventMessage::default()), None);
    }
}
