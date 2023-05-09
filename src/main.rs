mod dhcp;
mod handler;

use dhcp::DhcpCodec;
use futures::StreamExt;
use handler::Handler;
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;
use tracing_subscriber::prelude::*;

// Just some hacking :)
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("netboot")
        .enable_io()
        .build()?;
    rt.block_on(async { init().await })
}

async fn init() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    let sock = UdpSocket::bind("0.0.0.0:67").await?;
    sock.set_broadcast(true)?;

    let (sink, stream) = UdpFramed::new(sock, DhcpCodec::new()).split();
    let mut handler = Handler::new(stream, sink);
    handler.handle().await
}
