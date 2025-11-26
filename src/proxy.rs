use std::{borrow::Cow, ops::Deref, sync::atomic::{ AtomicU32, Ordering::Relaxed }};
use async_trait::async_trait;
use bytes::Bytes;
use http::{header, Response, StatusCode};
use tokio::io::AsyncReadExt;

use pingora_core::{
    upstreams::peer::HttpPeer,
    protocols::{
        l4::stream::Stream,
        http::ServerSession,
        proxy_protocol::{ProxyProtocolHeader, ProxyProtocolReceiver, HeaderV1, HeaderV2, Command, Addresses, Transport::Tcp4, Transport::Tcp6, Transport::Unknown},
    },
    server::{Server, configuration::Opt},
    services::listening::Service,
    apps::http_app::ServeHttp,
    listeners::tls::TlsSettings
};
use pingora_error::{Result, Error, ErrorType, OrErr};
use pingora_http::RequestHeader;
use pingora_proxy::{ProxyHttp, Session, http_proxy_service_with_name};


#[derive(Default)]
struct EchoService { counter: AtomicU32 }
struct ProxyService;
struct ProxyServiceCtx;

#[derive(Clone)]
struct ProxyProtocol { is_v1: bool }


#[async_trait]
impl ServeHttp for EchoService {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        let get_header = |name: &str| {
            session.req_header().headers.get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
        };

        let xff = get_header("X-Forwarded-For");
        let x_uid = get_header("X-Proxy-Unique-ID");
        let counter = self.counter.fetch_add(1, Relaxed);

        let body = Bytes::from(format!("Hello from EchoApp!\n\nX-Forwarded-For: {}\nX-Proxy-Unique-ID: {}\nCounter: {}\n", xff, x_uid, counter));

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::CONTENT_LENGTH, body.len().to_string())
            .body(body.to_vec())
            .unwrap()
    }
}



#[async_trait]
impl ProxyHttp for ProxyService {
    type CTX = ProxyServiceCtx;

    fn new_ctx(&self) -> Self::CTX {
        ProxyServiceCtx
    }

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(("127.0.0.1", 9001), false, "".to_string())))
    }

    async fn upstream_request_filter(&self, session: &mut Session, upstream_request: &mut RequestHeader, _ctx: &mut Self::CTX) -> Result<()>
    where Self::CTX: Send + Sync
    {
        // With "proxy_protocol" feature enabled in pingora-core, we can access the parsed Proxy Protocol header
        // from the session's socket digest.

        if let Some(digest) = session.digest().and_then(|d| d.socket_digest.as_ref()) {
            if let Some(ep) = digest.proxy_protocol() {
                if let Some(addr) = match ep {
                    ProxyProtocolHeader::V1(hdr) => &hdr.addresses,
                    ProxyProtocolHeader::V2(hdr) => &hdr.addresses,
                } {
                    let _ = upstream_request.insert_header("X-Forwarded-For", addr.source.ip().to_string());
                }

                // If required, we can use the `proxy-header` crate to parse the TLVs as well
                // (https://crates.io/crates/proxy-header)
                if let ProxyProtocolHeader::V2(hdr) = ep {
                    if let Some(tlvs) = &hdr.tlvs {
                        let header = proxy_header::ProxyHeader::from((None, Cow::Borrowed(tlvs.deref())));
                        if let Some(unique_id) = header.unique_id() {
                            let _ = upstream_request.insert_header("X-Proxy-Unique-ID", std::str::from_utf8(unique_id).unwrap_or_default());
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ProxyProtocolReceiver for ProxyProtocol {
    /// This example uses the `proxy-header` crate to parse the Proxy Protocol headers.
    /// https://crates.io/crates/proxy-header
    async fn accept(&self, stream: &mut Stream) ->  Result<(ProxyProtocolHeader, Vec<u8>)> {
        use proxy_header::{ParseConfig, ProxyHeader, Error::BufferTooShort};

        let parse_config = ParseConfig {
            allow_v1: self.is_v1,
            allow_v2: !self.is_v1,
            include_tlvs: !self.is_v1
        };
        let mut bytes = Vec::with_capacity( if self.is_v1 { 107 } else { 256 } ); // limit the v2 to 256 bytes for simplicity

        loop {
            let bytes_read = stream.read_buf(&mut bytes).await.or_err(ErrorType::ReadError, "Failed to read from stream")?;
            if bytes_read == 0 {
                return Error::e_explain(ErrorType::ReadError, "EOF unexpected");
            }

            match ProxyHeader::parse(&bytes, parse_config) {
                Ok((header, consumed)) => {
                    let header = header.into_owned();
                    bytes.drain(..consumed);

                    let (addr, tlvs) = header.into();

                    let (command, addresses, transport) = match addr {
                        None => { (Command::Local, None, Unknown)  },
                        Some(addr) => {(
                            Command::Proxy,
                            Some(Addresses {
                                source: addr.source,
                                destination: addr.destination,
                            }),
                            if addr.source.is_ipv4() { Tcp4 } else { Tcp6 },
                        )}
                    };

                    let header = match self.is_v1 {
                        true => ProxyProtocolHeader::V1(HeaderV1 { transport, addresses, }),
                        false => ProxyProtocolHeader::V2(HeaderV2 { transport, addresses, command, tlvs: Some(tlvs) }),
                    };
                    return Ok((header, bytes));
                }
                Err(BufferTooShort) => continue,
                Err(_) => {
                    return Error::e_explain(ErrorType::UnknownError, "Invalid proxy header");
                }
            }
        }
    }
}

fn tls() -> TlsSettings {
    let cert_path = "./tests/keys/server.crt";
    let key_path = "./tests/keys/key.pem";

    let mut tls = TlsSettings::intermediate(&cert_path, &key_path).unwrap();
    tls.enable_h2();
    tls
}

// RUST_LOG=DEBUG cargo run --features <openssl|boringssl|rustls|s2n> -- -c tests/pingora_conf.yml
fn main() {
    env_logger::builder().init();

    let ppv1 = ProxyProtocol { is_v1: true };
    let ppv2 = ProxyProtocol { is_v1: false };

    let mut server = Server::new(Some(Opt::parse_args())).unwrap();
    server.bootstrap();

    let mut proxy = http_proxy_service_with_name(&server.configuration, ProxyService, "ProxyApp w/o PP");
    proxy.add_tcp("0.0.0.0:8080");
    proxy.add_tls_with_settings("0.0.0.0:8443", None, tls());
    server.add_service(proxy);

    let mut proxy_v1 = http_proxy_service_with_name(&server.configuration, ProxyService, "ProxyApp w/ PP v1");
    proxy_v1.add_proxy_protocol_endpoint("0.0.0.0:8081", None, None, ppv1.clone());
    proxy_v1.add_proxy_protocol_endpoint("0.0.0.0:8444", None, Some(tls()), ppv1);
    server.add_service(proxy_v1);

    let mut proxy_v2 = http_proxy_service_with_name(&server.configuration, ProxyService, "ProxyApp w/ PP v2");
    proxy_v2.add_proxy_protocol_endpoint("0.0.0.0:8082", None, None, ppv2.clone());
    proxy_v2.add_proxy_protocol_endpoint("0.0.0.0:8445", None, Some(tls()), ppv2);
    server.add_service(proxy_v2);


    let mut echo = Service::new("EchoApp".to_string(), EchoService::default());
    echo.add_tcp("0.0.0.0:9001");
    server.add_service(echo);

    server.run_forever();
}
