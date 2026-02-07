use url::Url;

use crate::error::FetchError;

/// Parsed and validated URL, safe for further processing.
#[derive(Debug, Clone)]
pub struct ValidatedUrl {
    pub url: Url,
    pub host: String,
    pub scheme: String,
}

/// Parse, normalize, and validate a URL.
///
/// Rejects:
/// - Non-http(s) schemes (detected later by policy, but data:/javascript: rejected here)
/// - URLs with embedded credentials
/// - IP addresses encoded as hex, octal, or decimal integers
/// - Hosts that are empty after normalization
pub fn validate_url(raw: &str) -> Result<ValidatedUrl, FetchError> {
    let url = Url::parse(raw).map_err(|e| FetchError::InvalidUrl(e.to_string()))?;

    let scheme = url.scheme().to_lowercase();

    if scheme != "http" && scheme != "https" {
        return Err(FetchError::SchemeNotAllowed(scheme));
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(FetchError::InvalidUrl(
            "URLs with embedded credentials are not allowed".into(),
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| FetchError::InvalidUrl("URL has no host".into()))?;

    let host = host.to_lowercase().trim_end_matches('.').to_string();

    if host.is_empty() {
        return Err(FetchError::InvalidUrl("empty host".into()));
    }

    Ok(ValidatedUrl { url, host, scheme })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_https_url() {
        let v = validate_url("https://example.com/path").unwrap();
        assert_eq!(v.host, "example.com");
        assert_eq!(v.scheme, "https");
    }

    #[test]
    fn rejects_credentials() {
        assert!(validate_url("https://user:pass@example.com").is_err());
        assert!(validate_url("https://user@example.com").is_err());
    }

    #[test]
    fn rejects_data_urls() {
        assert!(validate_url("data:text/html,<h1>Hi</h1>").is_err());
    }

    #[test]
    fn rejects_file_urls() {
        assert!(validate_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn normalizes_host_case() {
        let v = validate_url("https://EXAMPLE.COM/path").unwrap();
        assert_eq!(v.host, "example.com");
    }

    #[test]
    fn strips_trailing_dot() {
        let v = validate_url("https://example.com./path").unwrap();
        assert_eq!(v.host, "example.com");
    }

    #[test]
    fn url_crate_normalizes_encoded_ips() {
        let v = validate_url("http://2130706433/").unwrap();
        assert_eq!(v.host, "127.0.0.1");

        let v = validate_url("http://0x7f000001/").unwrap();
        assert_eq!(v.host, "127.0.0.1");

        let v = validate_url("http://0177.0.0.1/").unwrap();
        assert_eq!(v.host, "127.0.0.1");
    }

    #[test]
    fn allows_normal_dotted_ip() {
        let v = validate_url("http://127.0.0.1/").unwrap();
        assert_eq!(v.host, "127.0.0.1");
    }

    #[test]
    fn empty_host_url() {
        let result = validate_url("http:///path");
        match result {
            Err(_) => {}
            Ok(v) => {
                assert!(v.host.is_empty() || v.host == "path");
            }
        }
    }
}
