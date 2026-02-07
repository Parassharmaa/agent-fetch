use std::collections::HashMap;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use safe_fetch::{DomainPattern, FetchPolicy, FetchRequest, SafeClient};

#[napi(object)]
pub struct SafeHttpClientOptions {
    pub allowed_domains: Option<Vec<String>>,
    pub blocked_domains: Option<Vec<String>>,
    pub deny_private_ips: Option<bool>,
    pub allowed_methods: Option<Vec<String>>,
    pub allowed_schemes: Option<Vec<String>>,
    pub max_request_body_bytes: Option<f64>,
    pub max_response_body_bytes: Option<f64>,
    pub connect_timeout_ms: Option<f64>,
    pub request_timeout_ms: Option<f64>,
    pub max_redirects: Option<u32>,
    pub max_concurrent_requests: Option<f64>,
    pub max_requests_per_minute: Option<u32>,
}

#[napi(object)]
pub struct FetchOptions {
    pub method: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<Buffer>,
}

#[napi(object)]
pub struct FetchResult {
    pub status: u32,
    pub headers: HashMap<String, String>,
    pub body: Buffer,
}

#[napi]
pub struct SafeHttpClient {
    client: SafeClient,
}

#[napi]
impl SafeHttpClient {
    #[napi(constructor)]
    pub fn new(options: Option<SafeHttpClientOptions>) -> Self {
        let mut policy = FetchPolicy::default();

        if let Some(opts) = options {
            if let Some(domains) = opts.allowed_domains {
                policy.allowed_domains = Some(domains.into_iter().map(DomainPattern).collect());
            }
            if let Some(domains) = opts.blocked_domains {
                policy.blocked_domains = domains.into_iter().map(DomainPattern).collect();
            }
            if let Some(v) = opts.deny_private_ips {
                policy.deny_private_ips = v;
            }
            if let Some(v) = opts.allowed_methods {
                policy.allowed_methods = v;
            }
            if let Some(v) = opts.allowed_schemes {
                policy.allowed_schemes = v;
            }
            if let Some(v) = opts.max_request_body_bytes {
                policy.max_request_body_bytes = v as usize;
            }
            if let Some(v) = opts.max_response_body_bytes {
                policy.max_response_body_bytes = v as usize;
            }
            if let Some(v) = opts.connect_timeout_ms {
                policy.connect_timeout_ms = v as u64;
            }
            if let Some(v) = opts.request_timeout_ms {
                policy.request_timeout_ms = v as u64;
            }
            if let Some(v) = opts.max_redirects {
                policy.max_redirects = v as u8;
            }
            if let Some(v) = opts.max_concurrent_requests {
                policy.max_concurrent_requests = v as usize;
            }
            if let Some(v) = opts.max_requests_per_minute {
                policy.max_requests_per_minute = v;
            }
        }

        Self {
            client: SafeClient::new(policy),
        }
    }

    #[napi]
    pub async fn fetch(&self, url: String, options: Option<FetchOptions>) -> Result<FetchResult> {
        let (method, headers, body) = match options {
            Some(opts) => (
                opts.method.unwrap_or_else(|| "GET".into()),
                opts.headers.unwrap_or_default(),
                opts.body.map(|b| b.to_vec()),
            ),
            None => ("GET".into(), HashMap::new(), None),
        };

        let request = FetchRequest {
            url,
            method,
            headers,
            body,
        };

        let response = self
            .client
            .fetch(request)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(FetchResult {
            status: response.status as u32,
            headers: response.headers,
            body: Buffer::from(response.body),
        })
    }
}
