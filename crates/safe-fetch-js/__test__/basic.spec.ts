import test from 'ava';
import { SafeHttpClient } from '../index.js';

test('constructor creates client with defaults', (t) => {
  const client = new SafeHttpClient();
  t.truthy(client);
});

test('constructor accepts options', (t) => {
  const client = new SafeHttpClient({
    allowedDomains: ['example.com'],
    blockedDomains: ['evil.com'],
    denyPrivateIps: true,
    maxRedirects: 5,
    connectTimeoutMs: 5000,
    requestTimeoutMs: 15000,
  });
  t.truthy(client);
});

test('rejects private IPs', async (t) => {
  const client = new SafeHttpClient();
  await t.throwsAsync(() => client.fetch('http://127.0.0.1/'), {
    message: /private IP blocked/,
  });
});

test('rejects cloud metadata IP', async (t) => {
  const client = new SafeHttpClient();
  await t.throwsAsync(
    () => client.fetch('http://169.254.169.254/latest/meta-data/'),
    { message: /private IP blocked/ },
  );
});

test('rejects blocked domain', async (t) => {
  const client = new SafeHttpClient({
    blockedDomains: ['evil.com'],
  });
  await t.throwsAsync(() => client.fetch('https://evil.com/'), {
    message: /blocked/,
  });
});

test('rejects domain not in allowlist', async (t) => {
  const client = new SafeHttpClient({
    allowedDomains: ['good.com'],
  });
  await t.throwsAsync(() => client.fetch('https://bad.com/'), {
    message: /allowlist/,
  });
});

test('rejects disallowed scheme', async (t) => {
  const client = new SafeHttpClient();
  await t.throwsAsync(() => client.fetch('ftp://example.com/file'), {
    message: /scheme/,
  });
});

test('fetches a public URL', async (t) => {
  const client = new SafeHttpClient();
  const res = await client.fetch('https://httpbin.org/get');
  t.is(res.status, 200);
  t.truthy(res.headers['content-type']);
  t.true(res.body.length > 0);
});

test('POST with body and headers', async (t) => {
  const client = new SafeHttpClient();
  const body = JSON.stringify({ hello: 'world' });
  const res = await client.fetch('https://httpbin.org/post', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: Buffer.from(body),
  });
  t.is(res.status, 200);
  const json = JSON.parse(res.body.toString());
  t.is(json.json.hello, 'world');
});

test('respects allowlist for allowed domain', async (t) => {
  const client = new SafeHttpClient({
    allowedDomains: ['httpbin.org'],
  });
  const res = await client.fetch('https://httpbin.org/status/204');
  t.is(res.status, 204);
});

test('returns correct status codes', async (t) => {
  const client = new SafeHttpClient();
  const res = await client.fetch('https://httpbin.org/status/404');
  t.is(res.status, 404);
});

test('returns response headers', async (t) => {
  const client = new SafeHttpClient();
  const res = await client.fetch('https://httpbin.org/response-headers?X-Test=hello');
  t.is(res.status, 200);
  t.is(res.headers['x-test'], 'hello');
});
