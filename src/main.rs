mod dhcp;

use std::io;
use tokio::net::UdpSocket;
use tracing_subscriber::prelude::*;

use crate::dhcp::parser::parse_dhcp;

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

        let (rem, dhcp) = parse_dhcp(&buf).unwrap();
        println!("{:02X?} rem", rem);
        println!("{:02X?}", dhcp.client_hardware_address);
        println!("{:#?}", dhcp.is_broadcast());
        println!("First 0x{:b}", dhcp.flags.to_be_bytes()[0]);
        println!("Second 0x{:b}", dhcp.flags.to_be_bytes()[1]);

        let len = sock.send_to(&buf[..len], addr).await?;
        println!("{:?} bytes sent", len);
    }
}
