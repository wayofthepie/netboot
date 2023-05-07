mod dhcp;

use dhcp::DhcpMessage;
use tokio::net::UdpSocket;
use tracing_subscriber::prelude::*;

// Just some hacking :)
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    let sock = UdpSocket::bind("0.0.0.0:67").await?;
    let mut buf = [0; 1500];
    loop {
        sock.recv(&mut buf).await?;
        let dhcp = DhcpMessage::deserialize(&buf).unwrap();
        println!("{:?}", dhcp);
    }
}
