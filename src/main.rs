use std::io;
use tokio::net::UdpSocket;

use crate::dhcp_parser::parse_dhcp;

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

mod dhcp_parser {
    use nom::combinator::map;
    use nom::error::ParseError;
    use nom::sequence::tuple;
    use nom::{bytes::complete::take, error::ErrorKind, IResult};

    #[derive(Debug)]
    pub enum DHCPMessageError<I> {
        InvalidDataError,
        NomError(nom::error::Error<I>),
    }

    impl<'a> From<nom::error::Error<&'a [u8]>> for DHCPMessageError<&'a [u8]> {
        fn from(e: nom::error::Error<&'a [u8]>) -> Self {
            DHCPMessageError::NomError(e)
        }
    }

    impl<I> ParseError<I> for DHCPMessageError<I> {
        fn from_error_kind(input: I, kind: ErrorKind) -> Self {
            DHCPMessageError::NomError(nom::error::Error::new(input, kind))
        }

        fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
            other
        }
    }

    #[derive(Debug)]
    pub struct DHCPMessage {
        pub op: u8,
        pub hardware_type: u8,
        pub hardware_len: u8,
        pub hops: u8, // number of relays
        pub xid: [u8; 4],
        pub seconds: [u8; 2],
        pub flags: [u8; 2],
        pub client_address: [u8; 4],
        pub your_address: [u8; 4],
        pub server_address: [u8; 4],
        pub gateway_address: [u8; 4],
        // This can be more than just a mac address, hence why it's 16 bytes. For example
        // it could be a GUID up to 128 bits in length.
        pub client_hardware_address: [u8; 16],
        pub magic_cookie: [u8; 4],
        pub options: Vec<DHCPOption>,
    }

    #[derive(Debug, PartialEq)]
    pub enum DHCPOption {
        ArpCacheTimeout(u32),
        NotYetImplemented,
    }

    pub fn parse_dhcp(bytes: &[u8]) -> IResult<&[u8], DHCPMessage, DHCPMessageError<&[u8]>> {
        match bytes {
            &[op, hardware_type, hardware_len, hops, ref rem @ ..] => {
                type ParsedRemainder<'a> = (
                    &'a [u8],
                    (
                        [u8; 4],
                        [u8; 2],
                        [u8; 2],
                        [u8; 4],
                        [u8; 4],
                        [u8; 4],
                        [u8; 4],
                        [u8; 16],
                        [u8; 192],
                        [u8; 4],
                    ),
                );
                let (
                    rem,
                    (
                        xid,
                        seconds,
                        flags,
                        client_address,
                        your_address,
                        server_address,
                        gateway_address,
                        client_hardware_address,
                        _,
                        magic_cookie,
                    ),
                ): ParsedRemainder = tuple((
                    take_n_bytes::<4>,
                    take_n_bytes::<2>,
                    take_n_bytes::<2>,
                    take_n_bytes::<4>,
                    take_n_bytes::<4>,
                    take_n_bytes::<4>,
                    take_n_bytes::<4>,
                    take_n_bytes::<16>,
                    take_n_bytes::<192>,
                    take_n_bytes::<4>,
                ))(rem)?;
                let (rem, options) = parse_dhcp_option(rem)?;
                let discover = DHCPMessage {
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
                    gateway_address,
                    client_hardware_address,
                    magic_cookie,
                    options: vec![options],
                };
                Ok((rem, discover))
            }
            _ => Err(nom::Err::Error(DHCPMessageError::InvalidDataError)),
        }
    }

    // For reference see <https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml>.
    fn parse_dhcp_option(bytes: &[u8]) -> IResult<&[u8], DHCPOption, DHCPMessageError<&[u8]>> {
        match bytes {
            &[0x35, _, ref rem @ ..] => {
                let (rem, data) = take_n_bytes::<4>(rem)?;
                let timeout: u32 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Ok((rem, DHCPOption::ArpCacheTimeout(timeout / 100)))
            }
            _ => Ok((bytes, DHCPOption::NotYetImplemented)),
        }
    }

    fn take_n_bytes<const N: usize>(
        bytes: &[u8],
    ) -> IResult<&[u8], [u8; N], DHCPMessageError<&[u8]>> {
        map(take(N), |client_address: &[u8]| {
            client_address.try_into().unwrap()
        })(bytes)
    }

    const TEST_MESSAGE_NO_OPTION: &[u8] = &[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0x44, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x45, 0x46, 0x47, 0x48,
    ];

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
        let gateway_address = [0x25, 0x26, 0x27, 0x28];
        let client_hardware_address = [
            0x29, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42,
            0x43, 0x44,
        ];
        let magic_cookie = [0x45, 0x46, 0x47, 0x48];
        let expected = DHCPMessage {
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
            gateway_address,
            client_hardware_address,
            magic_cookie,
            options: vec![],
        };
        let (rem, result) = parse_dhcp(TEST_MESSAGE_NO_OPTION).unwrap();
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
        assert_eq!(result.gateway_address, expected.gateway_address);
        assert_eq!(
            result.client_hardware_address,
            expected.client_hardware_address
        );
        assert_eq!(result.magic_cookie, expected.magic_cookie);
        assert!(rem.is_empty());
    }

    #[test]
    fn should_parse_arp_cache_timeout_option() {
        let timeout = 60000_u32;
        let timeout_bytes: [u8; 4] = timeout.to_be_bytes();
        let dhcp_options: [u8; 2] = [0x35, 0x04];
        let bytes = [
            TEST_MESSAGE_NO_OPTION,
            dhcp_options.as_slice(),
            timeout_bytes.as_slice(),
        ]
        .concat();
        let (_, result) = parse_dhcp(&bytes).unwrap();
        let expected_timeout = timeout / 100;
        assert_eq!(
            result.options,
            vec![DHCPOption::ArpCacheTimeout(expected_timeout)]
        )
    }
}
