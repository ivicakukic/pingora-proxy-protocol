# Pingora Proxy Protocol Demo

A demonstration of [HAProxy PROXY protocol](https://www.haproxy.org/download/2.8/doc/proxy-protocol.txt) (receiver side) functionality with [Pingora](https://github.com/cloudflare/pingora).

This project shows how to implement PROXY protocol v1 and v2 support in Pingora-based applications. The example uses the [`proxy-header`](https://crates.io/crates/proxy-header) crate for parsing (chosen for completeness and superb performance), but any other implementation can be used as well.

## Overview

The PROXY protocol allows proxies and load balancers to preserve the original client connection information (IP address, port) when forwarding traffic to backend servers.

This demo includes:

`src/proxy.rs`
- **PROXY protocol**: Custom implementation of the `Receiver` component
- **Proxy service**: HTTP proxy server w/ PROXY protocol, forwards client information via HTTP headers
- **Echo service**: Simple HTTP service that displays received headers

`src/client.rs`
- **Test client**: Test client that can send requests with or without PROXY protocol headers

`tests/docker-compose.yml`
- **Dockerized demo**: HAProxy running in TCP mode -> Pingora HTTP proxy


## Features

- PROXY protocol v1 and v2
- PROXY protocol v2 TLVs (Type-Length-Value)
- TLS/HTTPS with both HTTP/1 and HTTP/2

## Requirements

- Rust (2024 edition)
- TLS backend (OpenSSL, BoringSSL, Rustls, or s2n)

## Building

Build the project with your preferred TLS backend:

```bash
# Using OpenSSL
cargo build --features openssl

# Using BoringSSL
cargo build --features boringssl

# Using Rustls
cargo build --features rustls

# Using s2n
cargo build --features s2n
```

## Services

The proxy starts several services on different ports:

| Service | Port | Protocol | PROXY Protocol |
|---------|------|----------|----------------|
| ProxyApp w/o PP | 8080 | HTTP | No |
| ProxyApp w/o PP | 8443 | HTTPS | No |
| ProxyApp w/ PP v1 | 8081 | HTTP | v1 |
| ProxyApp w/ PP v1 | 8444 | HTTPS | v1 |
| ProxyApp w/ PP v2 | 8082 | HTTP | v2 |
| ProxyApp w/ PP v2 | 8445 | HTTPS | v2 |
| EchoApp | 9001 | HTTP | No |

## Testing

### Method 1: Docker with HAProxy

This method uses Docker Compose to start both Pingora and HAProxy. HAProxy acts as a TCP proxy in front of Pingora and handles the PROXY protocol headers, allowing you to test all endpoints using simple curl commands.

**Setup:**

```bash
# Build the release binary
cargo build -r --features openssl

# Start the services
docker-compose -f tests/docker-compose.yml up
```

**Testing:**

```bash
# HTTP endpoints
curl http://localhost:8080/
curl http://localhost:8081/
curl http://localhost:8082/

# HTTPS endpoints
curl -k https://localhost:8443/
curl -k https://localhost:8444/
curl -k https://localhost:8445/
```

HAProxy will automatically add the appropriate PROXY protocol headers (none, v1, or v2) based on the port.

### Method 2: Running Proxy and Custom Test Client Directly

Run the proxy directly without Docker:

```bash
RUST_LOG=INFO cargo run --features openssl -- -c tests/pingora_conf.yml
```

The test client supports various modes for testing PROXY protocol:

```bash
# Simple HTTP request (no PROXY protocol)
RUST_LOG=INFO cargo run --bin client --features openssl

# PROXY protocol v1 over HTTP
RUST_LOG=INFO cargo run --bin client --features openssl -- --proxy v1

# PROXY protocol v2 over HTTP
RUST_LOG=INFO cargo run --bin client --features openssl -- --proxy v2

# PROXY protocol v2 over HTTPS
RUST_LOG=INFO cargo run --bin client --features openssl -- --proxy v2 --tls

# Custom source IP
RUST_LOG=INFO cargo run --bin client --features openssl -- --proxy v2 --source 127.0.0.10
```

**Client Options:**

- `--proxy <none|v1|v2>`: PROXY protocol version (default: none)
- `--tls`: Use TLS connection
- `--source <IP>`: Source IP address for PROXY protocol (default: 127.0.0.4)
- `--destination <IP>`: Destination IP address (default: 127.0.0.1)

## Notes

- The Pingora dependency requires the `proxy_protocol` feature enabled in `pingora-core`
- TLS certificates are loaded from `tests/keys/` directory
- The client binary requires the `openssl` feature
- This is a demonstration/testing tool - adjust security settings for production use
