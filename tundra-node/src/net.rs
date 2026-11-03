use hickory_resolver::{TokioResolver, config::LookupIpStrategy};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::OnceLock,
};

pub fn host_to_ip(host: &str) -> Option<IpAddr> {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    IpAddr::from_str(host).ok()
}

fn build_resolver() -> TokioResolver {
    let mut builder =
        TokioResolver::builder_tokio().expect("failed to create TokioResolver builder");
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;

    builder.build().expect("failed to build TokioResolver")
}

pub async fn lookup_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, anyhow::Error> {
    if let Some(ip) = host_to_ip(host) {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    static RESOLVER: OnceLock<TokioResolver> = OnceLock::new();

    let lookup = RESOLVER.get_or_init(build_resolver).lookup_ip(host).await?;

    Ok(lookup.iter().map(|ip| SocketAddr::new(ip, port)).collect())
}
