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
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    let sock = UdpSocket::bind("0.0.0.0:67").await?;
    sock.set_broadcast(true)?;

    let (mut sink, mut stream) = UdpFramed::new(sock, DhcpCodec::new()).split();
    while let Some((msg, _)) = stream.try_next().await? {
        println!("{msg:?}");

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
