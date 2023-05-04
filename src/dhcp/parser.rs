use std::net::Ipv4Addr;

use nom::bytes::complete::take;
use nom::combinator::map;
use nom::multi::many0;
use nom::sequence::tuple;
use nom::IResult;

use super::error::DHCPMessageError;

const DHCP_OPTION_MESSAGE_TYPE: u8 = 53;
const DHCP_OPTION_ARP_CACHE_TIMEOUT: u8 = 35;
const DHCP_OPTION_SUBNET_MASK: u8 = 1;
const DHCP_OPTION_LOG_SERVER: u8 = 7;
const DHCP_OPTION_RESOURCE_LOCATION_SERVER: u8 = 11;
const DHCP_OPTION_PATH_MTU_PLATEAU_TABLE: u8 = 25;

#[derive(Debug, PartialEq)]
pub struct DHCPMessage<'a> {
    pub operation: Operation,
    pub hardware_type: HardwareType,
    pub hardware_len: u8,
    pub hops: u8,
    pub xid: u32,
    pub seconds: u16,
    flags: u16,
    pub client_address: Ipv4Addr,
    pub your_address: Ipv4Addr,
    pub server_address: Ipv4Addr,
    pub gateway_address: Ipv4Addr,
    pub client_hardware_address: &'a [u8],
    pub options: Vec<Option>,
}

#[derive(Debug, PartialEq)]
pub enum Operation {
    Discover,
    Offer,
    Acknowledgement,
}

#[derive(Debug, PartialEq)]
pub enum MessageType {
    Discover,
}

// The hardware types are defined in https://www.rfc-editor.org/rfc/rfc1700.
#[derive(Debug, PartialEq)]
pub enum HardwareType {
    Ethernet,
    Ieee802_11Wireless,
}

#[derive(Debug, PartialEq)]
pub enum Option {
    MessageType(MessageType),
    ArpCacheTimeout(u32),
    SubnetMask(Ipv4Addr),
    LogServer(Vec<Ipv4Addr>),
    ResourceLocationProtocolServer(Vec<Ipv4Addr>),
    PathMTUPlateauTable(Vec<u16>),
}

#[derive(Debug)]
struct RawDHCPMessage<'a> {
    operation: u8,
    hardware_type: u8,
    hardware_len: u8,
    hops: u8, // number of relays
    xid: &'a [u8; 4],
    seconds: &'a [u8; 2],
    flags: &'a [u8; 2],
    client_address: &'a [u8; 4],
    your_address: &'a [u8; 4],
    server_address: &'a [u8; 4],
    gateway_address: &'a [u8; 4],
    client_hardware_address: &'a [u8; 16],
    options: &'a [u8],
}

pub fn parse_dhcp(bytes: &[u8]) -> IResult<&[u8], DHCPMessage, DHCPMessageError<&[u8]>> {
    // TODO make sure rest is empty
    let (_, raw) = parse_raw_dhcp(bytes)?;
    let operation = op_from_byte(raw.operation)?;
    let hardware_len = raw.hardware_len;
    let hardware_type = hardware_type_from_byte(raw.hardware_type)?;
    let (rest, options) = many0(parse_dhcp_option)(raw.options)?;
    let xid = u32::from_be_bytes(raw.xid.to_owned());
    let seconds = u16::from_be_bytes(raw.seconds.to_owned());
    let flags = u16::from_be_bytes(raw.flags.to_owned());
    let client_address = Ipv4Addr::from(*raw.client_address);
    let your_address = Ipv4Addr::from(*raw.your_address);
    let server_address = Ipv4Addr::from(*raw.server_address);
    let gateway_address = Ipv4Addr::from(*raw.gateway_address);
    let (_, client_hardware_address) = take(hardware_len)(raw.client_hardware_address.as_slice())?;
    tracing::debug!("{:#?}", raw);
    let dhcp = DHCPMessage {
        operation,
        hardware_type,
        hardware_len,
        hops: raw.hops,
        xid,
        seconds,
        flags,
        client_address,
        your_address,
        server_address,
        gateway_address,
        client_hardware_address,
        options,
    };
    Ok((rest, dhcp))
}

fn parse_raw_dhcp(bytes: &[u8]) -> IResult<&[u8], RawDHCPMessage, DHCPMessageError<&[u8]>> {
    match bytes {
        &[operation, hardware_type, hardware_len, hops, ref rest @ ..] => {
            let (
                rest,
                (
                    xid,
                    seconds,
                    flags,
                    client_address,
                    your_address,
                    server_address,
                    gateway_address,
                    client_hardware_address,
                    _bootp,
                    _magic_cookie,
                    options,
                ),
            ) = tuple((
                take_n_bytes::<4>,
                take_n_bytes::<2>,
                take_n_bytes::<2>,
                take_n_bytes::<4>,
                take_n_bytes::<4>,
                take_n_bytes::<4>,
                take_n_bytes::<4>,
                take_n_bytes::<16usize>,
                take_n_bytes::<192>,
                take_n_bytes::<4>,
                nom::combinator::rest,
            ))(rest)?;
            let raw = RawDHCPMessage {
                operation,
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
                options,
            };
            Ok((rest, raw))
        }
        _ => Err(nom::Err::Error(DHCPMessageError::InvalidData)),
    }
}

// For reference see <https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml>.
fn parse_dhcp_option(bytes: &[u8]) -> IResult<&[u8], Option, DHCPMessageError<&[u8]>> {
    match bytes {
        [DHCP_OPTION_MESSAGE_TYPE, _, ref rest @ ..] => match rest {
            [1, ..] => Ok((&rest[0..], Option::MessageType(MessageType::Discover))),
            _ => Err(nom::Err::Error(
                DHCPMessageError::InvalidValueForOptionMessageType(rest[0]),
            )),
        },
        [DHCP_OPTION_ARP_CACHE_TIMEOUT, _, ref rest @ ..] => {
            let (rest, data) = take_n_bytes::<4>(rest)?;
            let timeout: u32 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            Ok((rest, Option::ArpCacheTimeout(timeout)))
        }
        [DHCP_OPTION_SUBNET_MASK, _, ref rest @ ..] => {
            let (rest, data) = take_n_bytes::<4>(rest)?;
            let subnet_mask = Ipv4Addr::from(*data);
            Ok((rest, Option::SubnetMask(subnet_mask)))
        }
        [DHCP_OPTION_LOG_SERVER, len, ref rest @ ..] => {
            let (rest, data) = take(*len as usize)(rest)?;
            // TODO: Make sure there are no bytes leftover here.
            let (_, addresses) = parse_ip_addresses(data)?;
            Ok((rest, Option::LogServer(addresses)))
        }
        [DHCP_OPTION_RESOURCE_LOCATION_SERVER, len, ref rest @ ..] => {
            let (rest, data) = take(*len as usize)(rest)?;
            // TODO: Make sure there are no bytes leftover here.
            let (_, addresses) = parse_ip_addresses(data)?;
            Ok((rest, Option::ResourceLocationProtocolServer(addresses)))
        }
        [DHCP_OPTION_PATH_MTU_PLATEAU_TABLE, len, ref rest @ ..] => {
            let (rest, data) = take(*len as usize)(rest)?;
            // TODO: Make sure there are no bytes leftover here.
            let (_, sizes) =
                many0(map(take_n_bytes::<2>, |&bytes| u16::from_be_bytes(bytes)))(data)?;
            tracing::debug!("MTU PLATEAU [ len: {len}, sizes: {sizes:#?}]");
            Ok((rest, Option::PathMTUPlateauTable(sizes)))
        }
        _ => Err(nom::Err::Error(DHCPMessageError::NotYetImplemented)),
    }
}

fn take_n_bytes<const N: usize>(bytes: &[u8]) -> IResult<&[u8], &[u8; N], DHCPMessageError<&[u8]>> {
    map(take(N), |client_address: &[u8]| {
        client_address.try_into().unwrap()
    })(bytes)
}

fn parse_ip_addresses(bytes: &[u8]) -> IResult<&[u8], Vec<Ipv4Addr>, DHCPMessageError<&[u8]>> {
    many0(map(take_n_bytes::<4>, |&bytes| Ipv4Addr::from(bytes)))(bytes)
}

fn op_from_byte<'a>(byte: u8) -> Result<Operation, nom::Err<DHCPMessageError<&'a [u8]>>> {
    match byte {
        1 => Ok(Operation::Discover),
        2 => Ok(Operation::Offer),
        4 => Ok(Operation::Acknowledgement),
        _ => Err(nom::Err::Error(DHCPMessageError::InvalidOperation)),
    }
}

fn hardware_type_from_byte<'a>(
    byte: u8,
) -> Result<HardwareType, nom::Err<DHCPMessageError<&'a [u8]>>> {
    match byte {
        1 => Ok(HardwareType::Ethernet),
        40 => Ok(HardwareType::Ieee802_11Wireless),
        _ => Err(nom::Err::Error(DHCPMessageError::InvalidHardwareType(byte))),
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use crate::dhcp::parser::{
        parse_dhcp, HardwareType, Operation, Option, DHCP_OPTION_ARP_CACHE_TIMEOUT,
    };

    const OPERATION: u8 = 1;
    const HARDWARE_TYPE: u8 = 1;
    const HARDWARE_LEN: u8 = 6;
    const HOPS: u8 = 4;
    const XID: &[u8; 4] = &[5, 6, 7, 8];
    const SECONDS: &[u8; 2] = &[0, 1];
    const FLAGS: &[u8; 2] = &[11, 12];
    const CLIENT_ADDRESS: &[u8; 4] = &[0, 0, 0, 0];
    const YOUR_ADDRESS: &[u8; 4] = &[1, 1, 1, 1];
    const SERVER_ADDRESS: &[u8; 4] = &[2, 2, 2, 2];
    const GATEWAY_ADDRESS: &[u8; 4] = &[3, 3, 3, 3];
    const CLIENT_HARDWARE_ADDRESS: &[u8; 16] = &[3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3];

    #[rustfmt::skip]
    fn test_message_no_option() -> Vec<u8> {
        let single_bytes = vec![OPERATION, HARDWARE_TYPE, HARDWARE_LEN, HOPS];
        let xid = XID.to_vec();
        let seconds = SECONDS.to_vec();
        let flags = FLAGS.to_vec();
        let client_address = CLIENT_ADDRESS.to_vec();
        let your_address = YOUR_ADDRESS.to_vec();
        let server_address = SERVER_ADDRESS.to_vec();
        let gateway_address = GATEWAY_ADDRESS.to_vec();
        let client_hardware_address = CLIENT_HARDWARE_ADDRESS.to_vec();
        let rest = vec![0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 45, 46, 47, 48
        ];
        [
            single_bytes, xid, seconds, flags,
            client_address, your_address, server_address,
            gateway_address, client_hardware_address ,rest
        ].concat()
    }

    #[test]
    fn should_parse_dhcp_message() {
        let timeout_ms = 600_u32;
        let timeout_bytes = &timeout_ms.to_be_bytes();
        let bytes = [
            test_message_no_option().as_slice(),
            &[DHCP_OPTION_ARP_CACHE_TIMEOUT, 4],
            timeout_bytes,
        ]
        .concat();
        let (rest, dhcp) = parse_dhcp(&bytes).unwrap();
        assert!(rest.is_empty());
        assert_eq!(dhcp.operation, Operation::Discover);
        assert_eq!(dhcp.hardware_type, HardwareType::Ethernet);
        assert_eq!(dhcp.hardware_len, HARDWARE_LEN);
        assert_eq!(dhcp.hops, HOPS);
        assert_eq!(dhcp.xid, u32::from_be_bytes(*XID));
        assert_eq!(dhcp.seconds, u16::from_be_bytes(*SECONDS));
        assert_eq!(dhcp.flags, u16::from_be_bytes(*FLAGS));
        assert_eq!(
            dhcp.client_address,
            Ipv4Addr::from(u32::from_be_bytes(*CLIENT_ADDRESS))
        );
        assert_eq!(
            dhcp.your_address,
            Ipv4Addr::from(u32::from_be_bytes(*YOUR_ADDRESS))
        );
        assert_eq!(
            dhcp.server_address,
            Ipv4Addr::from(u32::from_be_bytes(*SERVER_ADDRESS))
        );
        assert_eq!(
            dhcp.gateway_address,
            Ipv4Addr::from(u32::from_be_bytes(*GATEWAY_ADDRESS))
        );
        assert_eq!(
            dhcp.client_hardware_address,
            &CLIENT_HARDWARE_ADDRESS[..HARDWARE_LEN as usize]
        );
        assert_eq!(dhcp.options, vec![Option::ArpCacheTimeout(timeout_ms)]);
    }

    mod dhcp_hardware_types {
        use crate::dhcp::parser::{parse_dhcp, test::test_message_no_option, HardwareType};

        #[test]
        fn ethernet() {
            let mut bytes = test_message_no_option();
            bytes[1] = 1;
            let (rest, result) = parse_dhcp(&bytes).unwrap();
            assert!(rest.is_empty());
            assert_eq!(result.hardware_type, HardwareType::Ethernet);
        }

        #[test]
        fn ieee_802_11_wireless() {
            let mut bytes = test_message_no_option();
            bytes[1] = 40;
            let (rest, result) = parse_dhcp(&bytes).unwrap();
            assert!(rest.is_empty());
            assert_eq!(result.hardware_type, HardwareType::Ieee802_11Wireless);
        }
    }

    mod dhcp_operations {
        use crate::dhcp::parser::{parse_dhcp, test::test_message_no_option, Operation};

        #[test]
        fn dhcp_offer() {
            let mut bytes = test_message_no_option();
            bytes[0] = 2;
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(result.operation, Operation::Offer);
        }

        #[test]
        fn dhcp_acknowledgement() {
            let mut bytes = test_message_no_option();
            bytes[0] = 4;
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(result.operation, Operation::Acknowledgement);
        }
    }

    mod dhcp_options {
        use std::net::Ipv4Addr;

        use crate::dhcp::parser::{
            parse_dhcp, test::test_message_no_option, MessageType, Option,
            DHCP_OPTION_ARP_CACHE_TIMEOUT, DHCP_OPTION_LOG_SERVER,
            DHCP_OPTION_PATH_MTU_PLATEAU_TABLE, DHCP_OPTION_RESOURCE_LOCATION_SERVER,
            DHCP_OPTION_SUBNET_MASK,
        };

        #[test]
        fn dhcp_message_type_discover() {
            let dhcp_options = [53, 1, 1];
            let bytes = [&test_message_no_option(), dhcp_options.as_slice()].concat();
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(
                result.options,
                vec![Option::MessageType(MessageType::Discover)]
            );
        }

        #[test]
        fn arp_cache_timeout_option() {
            let timeout = 600_u32;
            let timeout_bytes: [u8; 4] = timeout.to_be_bytes();
            let dhcp_options: [u8; 2] = [DHCP_OPTION_ARP_CACHE_TIMEOUT, 4];
            let bytes = [
                &test_message_no_option(),
                dhcp_options.as_slice(),
                timeout_bytes.as_slice(),
            ]
            .concat();
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(result.options, vec![Option::ArpCacheTimeout(timeout)])
        }

        #[test]
        fn subnet_mask_option() {
            let subnet_mask = Ipv4Addr::new(255, 255, 255, 0);
            let subnet_mask_bytes: u32 = subnet_mask.into();
            let subnet_mask_bytes: [u8; 4] = subnet_mask_bytes.to_be_bytes();
            let dhcp_option: [u8; 2] = [DHCP_OPTION_SUBNET_MASK, 4];
            let bytes = [
                &test_message_no_option(),
                dhcp_option.as_slice(),
                subnet_mask_bytes.as_slice(),
            ]
            .concat();
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(result.options, vec![Option::SubnetMask(subnet_mask)])
        }

        #[test]
        fn log_server_option() {
            let log_servers = vec![Ipv4Addr::new(255, 255, 255, 0), Ipv4Addr::new(1, 1, 1, 1)];
            let log_servers_bytes: Vec<u8> = log_servers
                .iter()
                .flat_map(|&ip| u32::from(ip).to_be_bytes())
                .collect();
            let dhcp_option: [u8; 2] = [DHCP_OPTION_LOG_SERVER, 8];
            let bytes = [
                &test_message_no_option(),
                dhcp_option.as_slice(),
                log_servers_bytes.as_slice(),
            ]
            .concat();
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(result.options, vec![Option::LogServer(log_servers)])
        }

        #[test]
        fn location_server_option() {
            let rlp_servers = vec![Ipv4Addr::new(255, 255, 255, 0), Ipv4Addr::new(1, 1, 1, 1)];
            let rlp_servers_bytes: Vec<u8> = rlp_servers
                .iter()
                .flat_map(|&ip| u32::from(ip).to_be_bytes())
                .collect();
            let dhcp_option: [u8; 2] = [DHCP_OPTION_RESOURCE_LOCATION_SERVER, 8];
            let bytes = [
                &test_message_no_option(),
                dhcp_option.as_slice(),
                rlp_servers_bytes.as_slice(),
            ]
            .concat();
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(
                result.options,
                vec![Option::ResourceLocationProtocolServer(rlp_servers)]
            )
        }

        #[test]
        fn mtu_plateau_table() {
            let sizes = vec![10u16, 20];
            let sizes_bytes: Vec<u8> = sizes.iter().copied().flat_map(u16::to_be_bytes).collect();
            let dhcp_option: [u8; 2] = [DHCP_OPTION_PATH_MTU_PLATEAU_TABLE, 4];
            let bytes = [
                &test_message_no_option(),
                dhcp_option.as_slice(),
                sizes_bytes.as_slice(),
            ]
            .concat();
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(result.options, vec![Option::PathMTUPlateauTable(sizes)])
        }
    }
}
