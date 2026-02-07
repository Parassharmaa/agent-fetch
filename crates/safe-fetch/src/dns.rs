use std::net::{IpAddr, SocketAddr};

use hickory_resolver::TokioResolver;

use crate::error::FetchError;
use crate::ip_check::is_private_ip;

/// DNS resolver that validates all resolved IPs against SSRF rules.
pub struct SafeDnsResolver {
    resolver: TokioResolver,
    deny_private_ips: bool,
}

impl SafeDnsResolver {
    pub fn new(deny_private_ips: bool) -> Self {
        let resolver = TokioResolver::builder_tokio()
            .expect("failed to read system DNS config")
            .build();

        Self {
            resolver,
            deny_private_ips,
        }
    }

    /// Resolve a hostname and validate all returned IPs.
    /// Returns the set of validated socket addresses.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, FetchError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if self.deny_private_ips && is_private_ip(ip) {
                return Err(FetchError::PrivateIpBlocked {
                    host: host.to_string(),
                    resolved_ip: ip,
                });
            }
            return Ok(vec![SocketAddr::new(ip, port)]);
        }

        let response =
            self.resolver
                .lookup_ip(host)
                .await
                .map_err(|e: hickory_resolver::ResolveError| {
                    FetchError::DnsResolutionFailed(e.to_string())
                })?;

        let ips: Vec<IpAddr> = response.iter().collect();

        if ips.is_empty() {
            return Err(FetchError::DnsResolutionFailed(format!(
                "no addresses found for {host}"
            )));
        }

        if self.deny_private_ips {
            for &ip in &ips {
                if is_private_ip(ip) {
                    return Err(FetchError::PrivateIpBlocked {
                        host: host.to_string(),
                        resolved_ip: ip,
                    });
                }
            }
        }

        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }
}
