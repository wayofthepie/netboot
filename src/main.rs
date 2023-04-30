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
    use nom::combinator::map;
    use nom::error::ParseError;
    use nom::sequence::tuple;
    use nom::{bytes::complete::take, error::ErrorKind, IResult};

    #[derive(Debug)]
    pub enum DHCPDiscoverError<I> {
        InvalidDataError,
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
        seconds: [u8; 2],
        flags: [u8; 2],
        client_address: [u8; 4],
        your_address: [u8; 4],
        server_address: [u8; 4],
    }

    pub fn parse_dhcp_discover(
        bytes: &[u8],
    ) -> IResult<&[u8], DHCPDiscover, DHCPDiscoverError<&[u8]>> {
        match bytes {
            &[op, hardware_type, hardware_len, hops, ref rem @ ..] => {
                type ParsedRemainder<'a> = (
                    &'a [u8],
                    ([u8; 4], [u8; 2], [u8; 2], [u8; 4], [u8; 4], [u8; 4]),
                );
                let (rem, (xid, seconds, flags, client_address, your_address, server_address)): ParsedRemainder =
                    tuple((
                        takeN_bytes::<4>,
                        takeN_bytes::<2>,
                        takeN_bytes::<2>,
                        takeN_bytes::<4>,
                        takeN_bytes::<4>,
                        takeN_bytes::<4>,
                    ))(rem)?;
                let discover = DHCPDiscover {
                    op,
                    hardware_type,
                    hardware_len,
                    hops,
                    xid,
                    seconds,
                    flags,
                    client_address,
                    your_address,
                    server_address,
                };
                Ok((rem, discover))
            }
            _ => Err(nom::Err::Error(DHCPDiscoverError::InvalidDataError)),
        }
    }

    fn takeN_bytes<const N: usize>(
        bytes: &[u8],
    ) -> IResult<&[u8], [u8; N], DHCPDiscoverError<&[u8]>> {
        map(take(N), |client_address: &[u8]| {
            client_address.try_into().unwrap()
        })(bytes)
    }

    #[test]
    fn should_parse_dhcp_discover() {
        let op = 0x01;
        let hardware_type = 0x02;
        let hardware_len = 0x03;
        let hops = 0x04;
        let xid = [0x05, 0x06, 0x07, 0x08];
        let seconds = [0x09, 0x10];
        let flags = [0x11, 0x12];
        let client_address = [0x13, 0x14, 0x15, 0x16];
        let your_address = [0x17, 0x18, 0x19, 0x20];
        let server_address = [0x21, 0x22, 0x23, 0x24];
        let expected = DHCPDiscover {
            op,
            hardware_type,
            hardware_len,
            hops,
            xid,
            seconds,
            flags,
            client_address,
            your_address,
            server_address,
        };
        let bytes: Vec<u8> = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24,
        ];
        let (rem, result) = parse_dhcp_discover(&bytes).unwrap();
        assert_eq!(result.op, expected.op);
        assert_eq!(result.hardware_type, expected.hardware_type);
        assert_eq!(result.hardware_len, expected.hardware_len);
        assert_eq!(result.hops, expected.hops);
        assert_eq!(result.xid, expected.xid);
        assert_eq!(result.seconds, expected.seconds);
        assert_eq!(result.flags, expected.flags);
        assert_eq!(result.client_address, expected.client_address);
        assert_eq!(result.your_address, expected.your_address);
        assert_eq!(result.server_address, expected.server_address);
        assert!(rem.is_empty());
    }
}
