use agent_fetch::{FetchPolicy, FetchRequest, SafeClient};

#[tokio::test]
async fn rejects_private_ip_direct() {
    let client = SafeClient::new(FetchPolicy::default());
    let req = FetchRequest {
        url: "http://127.0.0.1/".into(),
        method: "GET".into(),
        headers: Default::default(),
        body: None,
    };
    let err = client.fetch(req).await.unwrap_err();
    assert!(
        err.to_string().contains("private IP blocked"),
        "expected private IP error, got: {err}"
    );
}

#[tokio::test]
async fn rejects_metadata_ip() {
    let client = SafeClient::new(FetchPolicy::default());
    let req = FetchRequest {
        url: "http://169.254.169.254/latest/meta-data/".into(),
        method: "GET".into(),
        headers: Default::default(),
        body: None,
    };
    let err = client.fetch(req).await.unwrap_err();
    assert!(
        err.to_string().contains("private IP blocked"),
        "expected private IP error, got: {err}"
    );
}

#[tokio::test]
async fn rejects_blocked_domain() {
    let policy = FetchPolicy {
        blocked_domains: vec![agent_fetch::DomainPattern("evil.com".into())],
        ..Default::default()
    };
    let client = SafeClient::new(policy);
    let req = FetchRequest {
        url: "https://evil.com/".into(),
        method: "GET".into(),
        headers: Default::default(),
        body: None,
    };
    let err = client.fetch(req).await.unwrap_err();
    assert!(err.to_string().contains("blocked"), "got: {err}");
}

#[tokio::test]
async fn rejects_domain_not_in_allowlist() {
    let policy = FetchPolicy {
        allowed_domains: Some(vec![agent_fetch::DomainPattern("good.com".into())]),
        ..Default::default()
    };
    let client = SafeClient::new(policy);
    let req = FetchRequest {
        url: "https://bad.com/".into(),
        method: "GET".into(),
        headers: Default::default(),
        body: None,
    };
    let err = client.fetch(req).await.unwrap_err();
    assert!(err.to_string().contains("allowlist"), "got: {err}");
}

#[tokio::test]
async fn rejects_disallowed_method() {
    let client = SafeClient::new(FetchPolicy::default());
    let req = FetchRequest {
        url: "https://example.com/".into(),
        method: "TRACE".into(),
        headers: Default::default(),
        body: None,
    };
    let err = client.fetch(req).await.unwrap_err();
    assert!(err.to_string().contains("method"), "got: {err}");
}

#[tokio::test]
async fn rejects_ftp_scheme() {
    let client = SafeClient::new(FetchPolicy::default());
    let req = FetchRequest {
        url: "ftp://example.com/file".into(),
        method: "GET".into(),
        headers: Default::default(),
        body: None,
    };
    let err = client.fetch(req).await.unwrap_err();
    assert!(
        err.to_string().contains("scheme"),
        "expected scheme error, got: {err}"
    );
}

#[tokio::test]
async fn rejects_oversized_request_body() {
    let policy = FetchPolicy {
        max_request_body_bytes: 100,
        ..Default::default()
    };
    let client = SafeClient::new(policy);
    let req = FetchRequest {
        url: "https://example.com/".into(),
        method: "POST".into(),
        headers: Default::default(),
        body: Some(vec![0u8; 200]),
    };
    let err = client.fetch(req).await.unwrap_err();
    assert!(
        err.to_string().contains("request body too large"),
        "got: {err}"
    );
}
