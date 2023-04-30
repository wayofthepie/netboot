use std::io;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:67").await?;
    let mut buf = [0; 1024];
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        println!("{:?} bytes received from {:?}", len, addr);

        let len = sock.send_to(&buf[..len], addr).await?;
        println!("{:?} bytes sent", len);
    }
}

mod dhcp_parser {
    use nom::{bytes::complete::take, IResult};

    pub struct DHCPDiscover {
        op: u8,
        hardware_type: u8,
        hardware_len: u8,
        hops: u8, // number of relays
    }

    pub fn parse_dhcp_discover(bytes: &[u8]) -> IResult<&[u8], DHCPDiscover> {
        let (rem, op) = take_byte(bytes)?;
        let (rem, hardware_type) = take_byte(rem)?;
        let (rem, hardware_len) = take_byte(rem)?;
        let discover = DHCPDiscover {
            op: op[0],
            hardware_type: hardware_type[0],
            hardware_len: hardware_len[0],
            hops: 0x00,
        };
        Ok((rem, discover))
    }

    fn take_byte(bytes: &[u8]) -> IResult<&[u8], &[u8]> {
        take(1usize)(bytes)
    }

    #[test]
    fn should_parse_dhcp_discover() {
        let op = 0x01;
        let hardware_type = 0x02;
        let hardware_len = 0x03;
        let hops = 0x04;
        let expected = DHCPDiscover {
            op,
            hardware_type,
            hardware_len,
            hops,
        };
        let bytes: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04];
        let (_, result) = parse_dhcp_discover(&bytes).unwrap();
        assert_eq!(result.op, expected.op);
        assert_eq!(result.hardware_type, expected.hardware_type);
        assert_eq!(result.hardware_len, expected.hardware_len)
    }
}
