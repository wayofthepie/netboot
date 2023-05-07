mod dhcp;

use std::{collections::HashMap, net::Ipv4Addr, str::FromStr};

use dhcp::DhcpMessage;
use mac_address::MacAddress;
use tokio::net::UdpSocket;
use tracing_subscriber::prelude::*;

use crate::dhcp::{DhcpOption, DhcpOptionValue, DhcpOptions, MessageType, Operation};

// Just some hacking :)
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    let mut addresses = HashMap::<MacAddress, Ipv4Addr>::new();
    let sock = UdpSocket::bind("0.0.0.0:67").await?;
    sock.set_broadcast(true)?;
    let mut buf = [0; 1500];

    loop {
        sock.recv(&mut buf).await?;
        let mut dhcp = DhcpMessage::deserialize(&buf).unwrap();
        let mac_bytes: [u8; 6] = dhcp.client_hardware_address.try_into().unwrap();
        let mac = MacAddress::new(mac_bytes);
        let ip = Ipv4Addr::from_str("192.168.122.151").unwrap();
        addresses.insert(mac, ip);
        dhcp.operation = Operation::Offer;
        dhcp.your_address = ip;
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
        let bytes = dhcp.serialize().unwrap();
        sock.send_to(&bytes, "255.255.255.255:68").await.unwrap();
        println!("{:?}", addresses);
    }
}
