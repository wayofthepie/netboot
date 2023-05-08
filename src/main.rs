mod dhcp;

use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::str::FromStr;

use dhcp::{
    DhcpCodec, DhcpMessage, DhcpOption, DhcpOptionValue, DhcpOptions, MessageType, Operation,
};
use futures::stream::SplitSink;
use futures::SinkExt;
use futures::StreamExt;
use futures::TryStreamExt;
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

    let (mut sink, mut stream) = UdpFramed::new(sock, DhcpCodec::new()).split();
    while let Some((msg, _)) = stream.try_next().await? {
        tracing::debug!("{:#?}", msg);
        match msg.operation {
            dhcp::Operation::Discover => handle_discover(msg, &mut sink).await,
            dhcp::Operation::Offer => todo!(),
            dhcp::Operation::Request => todo!(),
            dhcp::Operation::Acknowledgement => todo!(),
        }
    }
    Ok(())
}

async fn handle_discover(
    mut dhcp: DhcpMessage,
    sink: &mut SplitSink<UdpFramed<DhcpCodec>, (DhcpMessage, SocketAddr)>,
) {
    dhcp.operation = Operation::Offer;
    dhcp.your_address = Ipv4Addr::from_str("192.168.122.204").unwrap();
    dhcp.server_address = Ipv4Addr::from_str("192.168.122.1").unwrap();
    let mut options = DhcpOptions::new();
    options.insert(
        DhcpOption::MessageType,
        DhcpOptionValue::MessageType(MessageType::Offer),
    );
    options.insert(
        DhcpOption::SubnetMask,
        DhcpOptionValue::SubnetMask(Ipv4Addr::from_str("255.255.255.0").unwrap()),
    );
    options.insert(
        DhcpOption::Router,
        DhcpOptionValue::Router(Ipv4Addr::from_str("192.168.122.1").unwrap()),
    );

    dhcp.options = options;
    sink.send((dhcp, SocketAddr::from_str("255.255.255.255:68").unwrap()))
        .await
        .unwrap();
}
