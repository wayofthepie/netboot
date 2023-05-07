mod dhcp;

use dhcp::models::{DhcpMessage, Flags};
use std::{env::args, io, net::Ipv4Addr, str::FromStr};
use tokio::net::UdpSocket;
use tracing_subscriber::prelude::*;

use crate::dhcp::{
    models::{DhcpOption, DhcpOptionValue, DhcpOptions, MessageType, Operation},
    parser::parse_dhcp,
};

// Just some hacking :)
#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    if args().len() > 1 {
        let sock = UdpSocket::bind("0.0.0.0:68").await?;
        sock.set_broadcast(true)?;
        let hwaddr = vec![];
        let mut options = DhcpOptions::new();
        options.insert(
            DhcpOption::MessageType,
            DhcpOptionValue::MessageType(MessageType::Discover),
        );
        options.insert(
            DhcpOption::SubnetMask,
            DhcpOptionValue::SubnetMask(Ipv4Addr::from_str("255.255.255.0").unwrap()),
        );

        let dhcp_discover = DhcpMessage {
            operation: Operation::Discover,
            hardware_type: dhcp::models::HardwareType::Ethernet,
            hardware_len: 6,
            hops: 0,
            xid: 0,
            seconds: 0,
            flags: Flags { broadcast: true },
            client_address: Ipv4Addr::from_str("0.0.0.0").unwrap(),
            your_address: Ipv4Addr::from_str("0.0.0.0").unwrap(),
            server_address: Ipv4Addr::from_str("0.0.0.0").unwrap(),
            gateway_address: Ipv4Addr::from_str("0.0.0.0").unwrap(),
            client_hardware_address: &hwaddr,
            options,
        };

        let len = sock
            .send_to(&dhcp_discover.as_byte_vec().unwrap(), "255.255.255.255:67")
            .await
            .unwrap();
        println!("sent {:#?}", len);
        let mut buf = vec![];

        loop {
            let rec = sock.recv(&mut buf).await?;
            println!("received {}", rec);
        }
    }
    let mut buf = [0; 1024];
    let sock = UdpSocket::bind("0.0.0.0:67").await?;
    sock.set_broadcast(true)?;
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        println!("{:?} bytes received from {:?}", len, addr);

        let mut dhcp = parse_dhcp(&buf).unwrap();
        if dhcp.operation == Operation::Discover {
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
                DhcpOptionValue::SubnetMask(Ipv4Addr::from_str("255.255.255.0").unwrap()),
            );
            offer_options.insert(
                DhcpOption::Router,
                DhcpOptionValue::Router(Ipv4Addr::from_str("192.168.122.1").unwrap()),
            );

            dhcp.options = offer_options;
            println!("offer {:#?}", dhcp);

            let len = sock
                .send_to(&dhcp.as_byte_vec().unwrap(), "192.168.122.255:68")
                .await?;
            println!("{:?} bytes sent", len);
        }
    }
}
