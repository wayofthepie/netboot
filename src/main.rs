mod dhcp;

use std::io;
use tokio::net::UdpSocket;

use crate::dhcp::parse_dhcp;

#[tokio::main]
async fn main() -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:67").await?;
    let mut buf = [0; 1024];
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        println!("{:?} bytes received from {:?}", len, addr);

        let (rem, dhcp) = parse_dhcp(&buf).unwrap();
        println!("{:02X?} discover mac", dhcp.client_hardware_address);
        println!("{:02X?} rem", rem);
        println!("{:#?}", dhcp.options);

        let len = sock.send_to(&buf[..len], addr).await?;
        println!("{:?} bytes sent", len);
    }
}
