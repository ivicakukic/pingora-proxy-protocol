use std::borrow::Cow;

use clap::{Parser, ValueEnum};
use tokio::io::AsyncWriteExt;
use tokio::{self, io::AsyncReadExt};

use pingora_core::{
    protocols::{
        IO,
        l4::{socket::SocketAddr, stream::Stream},
        tls::{SslStream, client::handshake},
    },
    tls::{
        ext::{clear_error_stack, ssl_set_renegotiate_mode_freely},
        ssl::{SslConnector, SslMethod, SslVerifyMode},
    },
    upstreams::peer::{BasicPeer, Peer},
};

use pingora_error::{
    ErrorType::{ConnectTimedout, InternalError},
    OrErr, Result,
};

use proxy_header::{ProxiedAddress, ProxyHeader, Tlv};

#[derive(ValueEnum, Clone, Debug)]
enum ProxyMode {
    None,
    V1,
    V2,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, value_enum, default_value = "none", help = "Use Proxy Protocol")]
    proxy: ProxyMode,

    #[arg(short, long, help = "Use TLS connection")]
    tls: bool,

    #[arg(short, long, default_value = "127.0.0.4", help = "Source IP address for Proxy Protocol")]
    source: String,

    #[arg(short, long, default_value = "127.0.0.1", help = "Destination IP address")]
    destination: String,
}

async fn connect_l4(addr: &SocketAddr) -> Result<Stream> {
    let addr = addr.as_inet().expect("impossible");
    let stream = tokio::net::TcpStream::connect((addr.ip(), addr.port()))
        .await
        .map(|s| s.into())
        .or_fail()
        .unwrap();
    Ok(stream)
}

async fn connect_tls<T, P>(stream: T, peer: &P, tls_ctx: &SslConnector) -> Result<SslStream<T>>
where
    T: IO,
    P: Peer + Send + Sync,
{
    let mut ssl_conf = tls_ctx.configure().unwrap();
    ssl_set_renegotiate_mode_freely(&mut ssl_conf);
    ssl_conf.set_verify(SslVerifyMode::NONE);
    ssl_conf.set_verify_hostname(false);
    clear_error_stack();
    handshake(ssl_conf, peer.sni(), stream)
        .await
        .or_err(ConnectTimedout, "TLS handshake failed")
}

async fn connect<P: Peer + Send + Sync>(
    peer: &P,
    haproxy: Option<&[u8]>,
    tls_ctx: Option<&SslConnector>,
) -> Result<Box<dyn IO>> {
    let mut stream: Stream = connect_l4(peer.address()).await.unwrap();

    if let Some(bytes) = haproxy {
        stream
            .write_all(bytes)
            .await
            .or_err(InternalError, "failed to write proxy protocol header")?;
    }

    if let Some(tls_ctx) = tls_ctx {
        let tls_stream = connect_tls(stream, peer, tls_ctx).await?;
        Ok(Box::new(tls_stream))
    } else {
        Ok(Box::new(stream))
    }
}

// RUST_LOG=INFO cargo run --bin client --features openssl -- --proxy v2 --tls --source 127.0.0.10
fn main() {
    env_logger::init();

    let args = Args::parse();
    let port = match args.tls {
        false => 8080,
        true => 8443,
    };
    let port = match args.proxy {
        ProxyMode::None => port,    // 8080 or 8443
        ProxyMode::V1 => port + 1,  // 8081 or 8444
        ProxyMode::V2 => port + 2,  // 8082 or 8445
    };

    let peer_addr = format!("{}:{}", args.destination, port);

    let proxied_addr = ProxiedAddress::stream(
        format!("{}:50576", args.source).parse().unwrap(),
        peer_addr.parse().unwrap(),
    );

    let mut proxy_header = Vec::<u8>::new();
    let proxy_header = match args.proxy {
        ProxyMode::V1 => {
            ProxyHeader::with_address(proxied_addr)
                .encode_v1(&mut proxy_header)
                .unwrap();
            Some(proxy_header)
        }
        ProxyMode::V2 => {
            ProxyHeader::with_tlvs(
                Some(proxied_addr),
                vec![Tlv::UniqueId(Cow::Owned(b"123223".to_vec()))],
            )
            .encode_v2(&mut proxy_header)
            .unwrap();
            Some(proxy_header)
        }
        ProxyMode::None => None,
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut peer = BasicPeer::new(peer_addr.as_str());
        peer.sni = "any".to_string();
        let tls_ctx = match args.tls {
            true => Some(
                SslConnector::builder(SslMethod::tls_client())
                    .unwrap()
                    .build(),
            ),
            false => None,
        };

        // Connect
        let mut stream = connect(&peer, proxy_header.as_ref().map(|v| &**v), tls_ctx.as_ref())
            .await
            .unwrap();

        // Send HTTP request
        let request_body =
            b"GET / HTTP/1.0\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(request_body).await.unwrap();

        // Read the response
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        println!("Response:\n{}", String::from_utf8_lossy(&response));
    });
}
