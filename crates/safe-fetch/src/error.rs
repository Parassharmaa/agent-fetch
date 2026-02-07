use std::net::IpAddr;

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("private IP blocked: host {host} resolved to {resolved_ip}")]
    PrivateIpBlocked { host: String, resolved_ip: IpAddr },

    #[error("domain not in allowlist: {0}")]
    DomainNotAllowed(String),

    #[error("domain is blocked: {0}")]
    DomainBlocked(String),

    #[error("scheme not allowed: {0}")]
    SchemeNotAllowed(String),

    #[error("method not allowed: {0}")]
    MethodNotAllowed(String),

    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),

    #[error("request body too large: {size} bytes exceeds limit of {limit} bytes")]
    RequestBodyTooLarge { size: usize, limit: usize },

    #[error("response body too large: {size} bytes exceeds limit of {limit} bytes")]
    ResponseBodyTooLarge { size: usize, limit: usize },

    #[error("too many redirects (limit: {limit})")]
    TooManyRedirects { limit: u8 },

    #[error("rate limit exceeded")]
    RateLimitExceeded,

    #[error("connection timeout")]
    ConnectionTimeout,

    #[error("request timeout")]
    RequestTimeout,

    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("HTTP error: {0}")]
    HttpError(String),

    #[error("redirect to private IP: {url} resolved to {resolved_ip}")]
    RedirectToPrivateIp { url: String, resolved_ip: IpAddr },
}
