mod dhcp;

use std::{io, net::Ipv4Addr, str::FromStr};
use tokio::net::UdpSocket;
use tracing_subscriber::prelude::*;

use crate::dhcp::{
    models::{DhcpOption, DhcpOptionValue, DhcpOptions, MessageType, Operation},
    parser::parse_dhcp,
};

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();
    let sock = UdpSocket::bind("0.0.0.0:67").await?;
    let mut buf = [0; 1024];
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        println!("{:?} bytes received from {:?}", len, addr);

        let mut dhcp = parse_dhcp(&buf).unwrap();
        println!("{:#?}", dhcp);

        dhcp.operation = Operation::Offer;
        dhcp.your_address = Ipv4Addr::from_str("192.168.122.204").unwrap();
        dhcp.server_address = Ipv4Addr::from_str("192.168.122.1").unwrap();
        let options = dhcp.options;
        let mut offer_options = DhcpOptions::new();
        offer_options.insert(
            DhcpOption::MessageType,
            DhcpOptionValue::MessageType(MessageType::Offer),
        );
        offer_options.insert(
            DhcpOption::SubnetMask,
            DhcpOptionValue::SubnetMask(Ipv4Addr::from_str("255.255.255.255").unwrap()),
        );
        offer_options.insert(
            DhcpOption::Router,
            DhcpOptionValue::Router(Ipv4Addr::from_str("192.168.122.1").unwrap()),
        );

        dhcp.options = offer_options;
        println!("offer {:#?}", dhcp);
        sock.set_broadcast(true)?;

        let len = sock.send_to(&buf[..len], addr).await?;
        println!("{:?} bytes sent", len);
    }
}
