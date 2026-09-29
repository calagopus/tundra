use anyhow::Context;
use std::{net::Ipv4Addr, path::PathBuf};

pub const PROCESS_REF_PREFIX: &str = "pid:";

#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub pid: i32,
    pub running: bool,
    pub ip: Option<Ipv4Addr>,
    pub hosts_path: PathBuf,
}

impl ContainerInfo {
    /// Resolves a runtime-neutral process reference without requiring a
    /// container engine. Wings uses these references for native LXC runtimes.
    pub fn from_process_ref(
        container_ref: &str,
        dial_addr: Option<&str>,
    ) -> Result<Option<Self>, anyhow::Error> {
        let Some(raw_pid) = container_ref.strip_prefix(PROCESS_REF_PREFIX) else {
            return Ok(None);
        };
        let pid: i32 = raw_pid
            .parse()
            .with_context(|| format!("invalid process container reference {container_ref}"))?;
        if pid <= 0 {
            return Err(anyhow::anyhow!(
                "process container reference {container_ref} has an invalid PID"
            ));
        }

        let running = PathBuf::from(format!("/proc/{pid}/ns/net")).exists();
        let ip = dial_addr.and_then(|dial| {
            dial.parse::<std::net::SocketAddr>()
                .map(|address| address.ip())
                .or_else(|_| dial.parse::<std::net::IpAddr>())
                .ok()
                .and_then(|address| match address {
                    std::net::IpAddr::V4(address) => Some(address),
                    std::net::IpAddr::V6(_) => None,
                })
        });

        Ok(Some(Self {
            id: container_ref.to_owned(),
            pid,
            running,
            ip,
            // Process-backed runtimes provide the managed hosts template.
            hosts_path: PathBuf::new(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_references_resolve_without_a_container_engine() {
        let reference = format!("pid:{}", std::process::id());
        let info = ContainerInfo::from_process_ref(&reference, Some("10.70.0.58:25565"))
            .unwrap()
            .unwrap();
        assert!(info.running);
        assert_eq!(info.pid, std::process::id() as i32);
        assert_eq!(info.ip, Some(Ipv4Addr::new(10, 70, 0, 58)));
        assert!(
            ContainerInfo::from_process_ref("docker-id", None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn process_references_reject_invalid_pids() {
        assert!(ContainerInfo::from_process_ref("pid:0", None).is_err());
        assert!(ContainerInfo::from_process_ref("pid:not-a-pid", None).is_err());
    }
}
