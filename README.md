# safe-fetch

Sandboxed HTTP client in Rust with Node.js bindings. Prevents SSRF attacks by validating every request through a policy pipeline before any connection is made.

## What it blocks

- Private/internal IPs (loopback, RFC 1918, link-local, cloud metadata, multicast)
- DNS rebinding (resolves DNS upfront, pins connections to validated IPs)
- IP encoding tricks (hex, octal, decimal — normalized before validation)
- Redirect-based SSRF (re-validates every redirect target)
- Unauthorized domains (allowlist/blocklist support)
- Resource exhaustion (rate limiting, body size limits, timeouts)

## Rust usage

```rust
use safe_fetch::{SafeClient, FetchPolicy, FetchRequest};

let client = SafeClient::new(FetchPolicy::default());

let response = client.fetch(FetchRequest {
    url: "https://api.example.com/data".into(),
    method: "GET".into(),
    headers: Default::default(),
    body: None,
}).await?;

println!("Status: {}", response.status);
```

### With a restrictive policy

```rust
use safe_fetch::{SafeClient, FetchPolicy, DomainPattern};

let policy = FetchPolicy {
    allowed_domains: Some(vec![
        DomainPattern("*.example.com".into()),
    ]),
    blocked_domains: vec![
        DomainPattern("internal.example.com".into()),
    ],
    max_redirects: 3,
    request_timeout_ms: 5_000,
    ..Default::default()
};

let client = SafeClient::new(policy);
```

## Node.js usage

```js
const { SafeHttpClient } = require('safe-fetch');

const client = new SafeHttpClient({
  allowedDomains: ['*.example.com'],
  blockedDomains: ['internal.example.com'],
  maxRedirects: 3,
  requestTimeoutMs: 5000,
});

const response = await client.fetch('https://api.example.com/data', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: Buffer.from(JSON.stringify({ key: 'value' })),
});

console.log(response.status);
console.log(response.headers);
console.log(response.body.toString());
```

## Building

```sh
# Rust library
cargo build -p safe-fetch

# Node.js bindings
cd crates/safe-fetch-js
npm install
npm run build
```

## Testing

```sh
cargo test --workspace
```
