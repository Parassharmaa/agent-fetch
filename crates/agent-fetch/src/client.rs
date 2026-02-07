use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::dns::SafeDnsResolver;
use crate::error::FetchError;
use crate::policy::FetchPolicy;
use crate::rate_limit::RateLimiter;
use crate::url_check::{validate_url, ValidatedUrl};

/// A request to be executed by the safe client.
#[derive(Debug, Clone)]
pub struct FetchRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

/// The response returned by the safe client.
#[derive(Debug, Clone)]
pub struct FetchResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Custom DNS resolver that pins connections to pre-validated IP addresses.
/// This defeats DNS rebinding attacks by resolving once through our safe resolver
/// and then feeding those addresses to reqwest.
struct PinnedResolver {
    addrs: Vec<SocketAddr>,
}

impl Resolve for PinnedResolver {
    fn resolve(&self, _name: Name) -> Resolving {
        let addrs: Vec<SocketAddr> = self.addrs.clone();
        Box::pin(async move {
            let iter: Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

/// The safe HTTP client that enforces all policies.
pub struct SafeClient {
    policy: FetchPolicy,
    dns_resolver: SafeDnsResolver,
    rate_limiter: RateLimiter,
}

impl SafeClient {
    pub fn new(policy: FetchPolicy) -> Self {
        let dns_resolver = SafeDnsResolver::new(policy.deny_private_ips);
        let rate_limiter = RateLimiter::new(
            policy.max_requests_per_minute,
            policy.max_concurrent_requests,
        );

        Self {
            policy,
            dns_resolver,
            rate_limiter,
        }
    }

    /// Execute a fetch request through the full validation pipeline.
    pub async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        let validated = validate_url(&request.url)?;
        self.policy.check_scheme(&validated.scheme)?;
        self.policy.check_domain(&validated.host)?;
        self.policy.check_method(&request.method)?;

        if let Some(ref body) = request.body {
            if body.len() > self.policy.max_request_body_bytes {
                return Err(FetchError::RequestBodyTooLarge {
                    size: body.len(),
                    limit: self.policy.max_request_body_bytes,
                });
            }
        }

        let _permit = self.rate_limiter.acquire(&validated.host).await?;

        let port = validated.url.port_or_known_default().unwrap_or(443);
        let addrs = self.dns_resolver.resolve(&validated.host, port).await?;

        self.execute_request(&request, &validated, addrs).await
    }

    fn build_client(&self, addrs: Vec<SocketAddr>) -> Result<reqwest::Client, FetchError> {
        reqwest::Client::builder()
            .dns_resolver(Arc::new(PinnedResolver { addrs }))
            .connect_timeout(Duration::from_millis(self.policy.connect_timeout_ms))
            .timeout(Duration::from_millis(self.policy.request_timeout_ms))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e: reqwest::Error| FetchError::HttpError(e.to_string()))
    }

    async fn execute_request(
        &self,
        request: &FetchRequest,
        validated: &ValidatedUrl,
        addrs: Vec<SocketAddr>,
    ) -> Result<FetchResponse, FetchError> {
        let client = self.build_client(addrs)?;

        let method: http::Method = request
            .method
            .parse()
            .map_err(|_| FetchError::MethodNotAllowed(request.method.clone()))?;

        let mut req_builder = client.request(method, validated.url.as_str());

        for (key, value) in &request.headers {
            req_builder = req_builder.header(key.as_str(), value.as_str());
        }

        if let Some(ref body) = request.body {
            req_builder = req_builder.body(Bytes::from(body.clone()));
        }

        let mut current_url = validated.url.clone();
        let mut redirects_followed: u8 = 0;
        let mut response: reqwest::Response =
            req_builder.send().await.map_err(classify_reqwest_error)?;

        while response.status().is_redirection() {
            redirects_followed += 1;
            if redirects_followed > self.policy.max_redirects {
                return Err(FetchError::TooManyRedirects {
                    limit: self.policy.max_redirects,
                });
            }

            let location = response
                .headers()
                .get(http::header::LOCATION)
                .and_then(|v: &http::HeaderValue| v.to_str().ok())
                .ok_or_else(|| FetchError::HttpError("redirect without Location header".into()))?
                .to_string();

            let redirect_url = current_url
                .join(&location)
                .map_err(|e| FetchError::InvalidUrl(e.to_string()))?;

            let redirect_validated = validate_url(redirect_url.as_str())?;
            self.policy.check_scheme(&redirect_validated.scheme)?;
            self.policy.check_domain(&redirect_validated.host)?;

            let redirect_port = redirect_validated
                .url
                .port_or_known_default()
                .unwrap_or(443);
            let redirect_addrs = self
                .dns_resolver
                .resolve(&redirect_validated.host, redirect_port)
                .await
                .map_err(|e| match e {
                    FetchError::PrivateIpBlocked { resolved_ip, .. } => {
                        FetchError::RedirectToPrivateIp {
                            url: redirect_url.to_string(),
                            resolved_ip,
                        }
                    }
                    other => other,
                })?;

            let redirect_client = self.build_client(redirect_addrs)?;

            current_url = redirect_validated.url.clone();
            response = redirect_client
                .get(redirect_validated.url.as_str())
                .send()
                .await
                .map_err(classify_reqwest_error)?;
        }

        self.read_body_limited(response).await
    }

    async fn read_body_limited(
        &self,
        response: reqwest::Response,
    ) -> Result<FetchResponse, FetchError> {
        let status = response.status().as_u16();

        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        if let Some(cl) = response.content_length() {
            if cl as usize > self.policy.max_response_body_bytes {
                return Err(FetchError::ResponseBodyTooLarge {
                    size: cl as usize,
                    limit: self.policy.max_response_body_bytes,
                });
            }
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| FetchError::HttpError(e.to_string()))?;

        if body.len() > self.policy.max_response_body_bytes {
            return Err(FetchError::ResponseBodyTooLarge {
                size: body.len(),
                limit: self.policy.max_response_body_bytes,
            });
        }

        Ok(FetchResponse {
            status,
            headers,
            body: body.to_vec(),
        })
    }
}

fn classify_reqwest_error(e: reqwest::Error) -> FetchError {
    if e.is_connect() {
        FetchError::ConnectionTimeout
    } else if e.is_timeout() {
        FetchError::RequestTimeout
    } else {
        FetchError::HttpError(e.to_string())
    }
}
