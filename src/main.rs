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
    use nom::error::ParseError;
    use nom::{bytes::complete::take, error::ErrorKind, IResult};

    #[derive(Debug)]
    pub enum DHCPDiscoverError<I> {
        NomError(nom::error::Error<I>),
    }

    impl<'a> From<nom::error::Error<&'a [u8]>> for DHCPDiscoverError<&'a [u8]> {
        fn from(e: nom::error::Error<&'a [u8]>) -> Self {
            DHCPDiscoverError::NomError(e)
        }
    }

    impl<I> ParseError<I> for DHCPDiscoverError<I> {
        fn from_error_kind(input: I, kind: ErrorKind) -> Self {
            DHCPDiscoverError::NomError(nom::error::Error::new(input, kind))
        }

        fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
            other
        }
    }

    pub struct DHCPDiscover {
        op: u8,
        hardware_type: u8,
        hardware_len: u8,
        hops: u8, // number of relays
        xid: [u8; 4],
    }

    pub fn parse_dhcp_discover(
        bytes: &[u8],
    ) -> IResult<&[u8], DHCPDiscover, DHCPDiscoverError<&[u8]>> {
        let (rem, op) = take_byte(bytes)?;
        let (rem, hardware_type) = take_byte(rem)?;
        let (rem, hardware_len) = take_byte(rem)?;
        let (rem, hops) = take_byte(rem)?;
        let (rem, xid) = take(4usize)(rem)?;
        let xid: [u8; 4] = xid.try_into().unwrap();
        let discover = DHCPDiscover {
            op,
            hardware_type,
            hardware_len,
            hops,
            xid,
        };
        Ok((rem, discover))
    }

    fn take_byte(bytes: &[u8]) -> IResult<&[u8], u8, DHCPDiscoverError<&[u8]>> {
        take(1usize)(bytes).map(|(rem, slice)| (rem, slice[0]))
    }

    #[test]
    fn should_parse_dhcp_discover() {
        let op = 0x01;
        let hardware_type = 0x02;
        let hardware_len = 0x03;
        let hops = 0x04;
        let xid = [0x05, 0x06, 0x07, 0x08];
        let expected = DHCPDiscover {
            op,
            hardware_type,
            hardware_len,
            hops,
            xid,
        };
        let bytes: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let (_, result) = parse_dhcp_discover(&bytes).unwrap();
        assert_eq!(result.op, expected.op);
        assert_eq!(result.hardware_type, expected.hardware_type);
        assert_eq!(result.hardware_len, expected.hardware_len);
        assert_eq!(result.hops, expected.hops);
        assert_eq!(result.xid, expected.xid);
    }
}
