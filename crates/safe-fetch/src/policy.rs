use serde::Deserialize;

/// Pattern for matching domains — either exact or wildcard (e.g. `*.example.com`).
#[derive(Debug, Clone, Deserialize)]
pub struct DomainPattern(pub String);

impl DomainPattern {
    pub fn matches(&self, domain: &str) -> bool {
        let pattern = self.0.to_lowercase();
        let domain = domain.to_lowercase();

        if let Some(suffix) = pattern.strip_prefix("*.") {
            domain.ends_with(&format!(".{suffix}"))
        } else {
            domain == pattern
        }
    }
}

/// Controls every aspect of what the safe HTTP client is allowed to do.
#[derive(Debug, Clone, Deserialize)]
pub struct FetchPolicy {
    /// If `Some`, only these domains may be fetched. If `None`, all public domains are allowed.
    pub allowed_domains: Option<Vec<DomainPattern>>,
    /// Domains that are always rejected (checked before `allowed_domains`).
    pub blocked_domains: Vec<DomainPattern>,
    /// Block requests that resolve to private/internal IPs (default: true).
    pub deny_private_ips: bool,
    /// Allowed HTTP methods (default: common methods).
    pub allowed_methods: Vec<String>,
    /// Allowed URL schemes (default: ["https", "http"]).
    pub allowed_schemes: Vec<String>,
    /// Max request body size in bytes (default: 10 MB).
    pub max_request_body_bytes: usize,
    /// Max response body size in bytes (default: 50 MB).
    pub max_response_body_bytes: usize,
    /// TCP connect timeout in milliseconds (default: 10 000).
    pub connect_timeout_ms: u64,
    /// Overall request timeout in milliseconds (default: 30 000).
    pub request_timeout_ms: u64,
    /// Maximum number of redirects to follow (default: 10).
    pub max_redirects: u8,
    /// Maximum number of concurrent in-flight requests (default: 50).
    pub max_concurrent_requests: usize,
    /// Maximum requests per minute globally (default: 500).
    pub max_requests_per_minute: u32,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        Self {
            allowed_domains: None,
            blocked_domains: Vec::new(),
            deny_private_ips: true,
            allowed_methods: vec![
                "GET".into(),
                "POST".into(),
                "PUT".into(),
                "PATCH".into(),
                "DELETE".into(),
                "HEAD".into(),
                "OPTIONS".into(),
            ],
            allowed_schemes: vec!["https".into(), "http".into()],
            max_request_body_bytes: 10 * 1024 * 1024,
            max_response_body_bytes: 50 * 1024 * 1024,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 30_000,
            max_redirects: 10,
            max_concurrent_requests: 50,
            max_requests_per_minute: 500,
        }
    }
}

impl FetchPolicy {
    /// Check domain against blocked list, then allowed list.
    pub fn check_domain(&self, domain: &str) -> Result<(), crate::error::FetchError> {
        for pat in &self.blocked_domains {
            if pat.matches(domain) {
                return Err(crate::error::FetchError::DomainBlocked(domain.to_string()));
            }
        }
        if let Some(ref allowed) = self.allowed_domains {
            if !allowed.iter().any(|pat| pat.matches(domain)) {
                return Err(crate::error::FetchError::DomainNotAllowed(
                    domain.to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn check_scheme(&self, scheme: &str) -> Result<(), crate::error::FetchError> {
        if !self
            .allowed_schemes
            .iter()
            .any(|s| s.eq_ignore_ascii_case(scheme))
        {
            return Err(crate::error::FetchError::SchemeNotAllowed(
                scheme.to_string(),
            ));
        }
        Ok(())
    }

    pub fn check_method(&self, method: &str) -> Result<(), crate::error::FetchError> {
        if !self
            .allowed_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
        {
            return Err(crate::error::FetchError::MethodNotAllowed(
                method.to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_domain_match() {
        let pat = DomainPattern("api.example.com".into());
        assert!(pat.matches("api.example.com"));
        assert!(pat.matches("API.EXAMPLE.COM"));
        assert!(!pat.matches("other.example.com"));
        assert!(!pat.matches("example.com"));
    }

    #[test]
    fn wildcard_domain_match() {
        let pat = DomainPattern("*.example.com".into());
        assert!(pat.matches("api.example.com"));
        assert!(pat.matches("deep.sub.example.com"));
        assert!(!pat.matches("example.com")); // base domain does NOT match wildcard
        assert!(!pat.matches("example.org"));
        assert!(!pat.matches("notexample.com"));
    }

    #[test]
    fn blocked_takes_precedence() {
        let policy = FetchPolicy {
            allowed_domains: Some(vec![DomainPattern("*.example.com".into())]),
            blocked_domains: vec![DomainPattern("evil.example.com".into())],
            ..Default::default()
        };

        assert!(policy.check_domain("api.example.com").is_ok());
        assert!(policy.check_domain("evil.example.com").is_err());
    }

    #[test]
    fn allowlist_rejects_unlisted() {
        let policy = FetchPolicy {
            allowed_domains: Some(vec![DomainPattern("api.example.com".into())]),
            ..Default::default()
        };

        assert!(policy.check_domain("api.example.com").is_ok());
        assert!(policy.check_domain("other.example.com").is_err());
    }

    #[test]
    fn no_allowlist_allows_all() {
        let policy = FetchPolicy::default();
        assert!(policy.check_domain("anything.example.com").is_ok());
    }

    #[test]
    fn scheme_validation() {
        let policy = FetchPolicy::default();
        assert!(policy.check_scheme("https").is_ok());
        assert!(policy.check_scheme("http").is_ok());
        assert!(policy.check_scheme("ftp").is_err());
    }

    #[test]
    fn method_validation() {
        let policy = FetchPolicy::default();
        assert!(policy.check_method("GET").is_ok());
        assert!(policy.check_method("get").is_ok());
        assert!(policy.check_method("TRACE").is_err());
    }
}
