use std::net::Ipv4Addr;

use nom::bytes::complete::take;
use nom::combinator::map;
use nom::multi::many0;
use nom::sequence::tuple;
use nom::IResult;

use super::error::DHCPMessageError;
use super::models::{
    DhcpMessage, DhcpOption, Flags, HardwareType, MessageType, Operation, RawDhcpMessage,
    ACKNOWLEDGEMENT_OPERATION, DISCOVER_OPERATION, ETHERNET_HARDWARE_TYPE,
    IEE801_11WIRELESS_HARDWARE_TYPE, OFFER_OPERATION, OPTION_ARP_CACHE_TIMEOUT, OPTION_LOG_SERVER,
    OPTION_MESSAGE_TYPE, OPTION_MESSAGE_TYPE_ACKNOWLEDGEMENT, OPTION_MESSAGE_TYPE_DISCOVER,
    OPTION_MESSAGE_TYPE_OFFER, OPTION_MESSAGE_TYPE_RELEASE, OPTION_MESSAGE_TYPE_REQUEST,
    OPTION_PATH_MTU_PLATEAU_TABLE, OPTION_RESOURCE_LOCATION_SERVER, OPTION_SUBNET_MASK,
};

pub fn parse_dhcp(bytes: &[u8]) -> IResult<&[u8], DhcpMessage, DHCPMessageError<&[u8]>> {
    // TODO make sure rest is empty
    let (_, raw) = parse_raw_dhcp(bytes)?;
    let operation = op_from_byte(raw.operation)?;
    let hardware_len = raw.hardware_len;
    let hardware_type = hardware_type_from_byte(raw.hardware_type)?;
    let (rest, options) = many0(parse_dhcp_option)(raw.options)?;
    let xid = u32::from_be_bytes(raw.xid.to_owned());
    let seconds = u16::from_be_bytes(raw.seconds.to_owned());
    let flags = parse_flags(raw.flags)?;
    let client_address = Ipv4Addr::from(*raw.client_address);
    let your_address = Ipv4Addr::from(*raw.your_address);
    let server_address = Ipv4Addr::from(*raw.server_address);
    let gateway_address = Ipv4Addr::from(*raw.gateway_address);
    let (_, client_hardware_address) = take(hardware_len)(raw.client_hardware_address.as_slice())?;
    let dhcp = DhcpMessage {
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

fn parse_raw_dhcp(bytes: &[u8]) -> IResult<&[u8], RawDhcpMessage, DHCPMessageError<&[u8]>> {
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
            let raw = RawDhcpMessage {
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
fn parse_dhcp_option(bytes: &[u8]) -> IResult<&[u8], DhcpOption, DHCPMessageError<&[u8]>> {
    match bytes {
        [OPTION_MESSAGE_TYPE, _, ref rest @ ..] => match rest {
            [OPTION_MESSAGE_TYPE_DISCOVER, ..] => {
                Ok((&rest[0..], DhcpOption::MessageType(MessageType::Discover)))
            }
            [OPTION_MESSAGE_TYPE_OFFER, ..] => {
                Ok((&rest[0..], DhcpOption::MessageType(MessageType::Offer)))
            }
            [OPTION_MESSAGE_TYPE_REQUEST, ..] => {
                Ok((&rest[0..], DhcpOption::MessageType(MessageType::Request)))
            }
            [OPTION_MESSAGE_TYPE_ACKNOWLEDGEMENT, ..] => Ok((
                &rest[0..],
                DhcpOption::MessageType(MessageType::Acknowledgement),
            )),
            [OPTION_MESSAGE_TYPE_RELEASE, ..] => {
                Ok((&rest[0..], DhcpOption::MessageType(MessageType::Release)))
            }
            _ => Err(nom::Err::Error(
                DHCPMessageError::InvalidValueForOptionMessageType(rest[0]),
            )),
        },
        [OPTION_ARP_CACHE_TIMEOUT, _, ref rest @ ..] => {
            let (rest, data) = take_n_bytes::<4>(rest)?;
            let timeout: u32 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            Ok((rest, DhcpOption::ArpCacheTimeout(timeout)))
        }
        [OPTION_SUBNET_MASK, _, ref rest @ ..] => {
            let (rest, data) = take_n_bytes::<4>(rest)?;
            let subnet_mask = Ipv4Addr::from(*data);
            Ok((rest, DhcpOption::SubnetMask(subnet_mask)))
        }
        [OPTION_LOG_SERVER, len, ref rest @ ..] => {
            let (rest, data) = take(*len as usize)(rest)?;
            // TODO: Make sure there are no bytes leftover here.
            let (_, addresses) = parse_ip_addresses(data)?;
            Ok((rest, DhcpOption::LogServer(addresses)))
        }
        [OPTION_RESOURCE_LOCATION_SERVER, len, ref rest @ ..] => {
            let (rest, data) = take(*len as usize)(rest)?;
            // TODO: Make sure there are no bytes leftover here.
            let (_, addresses) = parse_ip_addresses(data)?;
            Ok((rest, DhcpOption::ResourceLocationProtocolServer(addresses)))
        }
        [OPTION_PATH_MTU_PLATEAU_TABLE, len, ref rest @ ..] => {
            let (rest, data) = take(*len as usize)(rest)?;
            // TODO: Make sure there are no bytes leftover here.
            let (_, sizes) =
                many0(map(take_n_bytes::<2>, |&bytes| u16::from_be_bytes(bytes)))(data)?;
            Ok((rest, DhcpOption::PathMTUPlateauTable(sizes)))
        }
        _ => Err(nom::Err::Error(DHCPMessageError::NotYetImplemented)),
    }
}

const BROADCAST_BIT: usize = 15;
fn parse_flags(flags: &[u8; 2]) -> Result<Flags, nom::Err<DHCPMessageError<&[u8]>>> {
    let flags = u16::from_be_bytes(*flags);
    Ok(Flags {
        broadcast: is_bit_set(BROADCAST_BIT, flags),
    })
}

fn is_bit_set(index: usize, num: u16) -> bool {
    num & (1 << index) != 0
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
        DISCOVER_OPERATION => Ok(Operation::Discover),
        OFFER_OPERATION => Ok(Operation::Offer),
        ACKNOWLEDGEMENT_OPERATION => Ok(Operation::Acknowledgement),
        _ => Err(nom::Err::Error(DHCPMessageError::InvalidOperation)),
    }
}

fn hardware_type_from_byte<'a>(
    byte: u8,
) -> Result<HardwareType, nom::Err<DHCPMessageError<&'a [u8]>>> {
    match byte {
        ETHERNET_HARDWARE_TYPE => Ok(HardwareType::Ethernet),
        IEE801_11WIRELESS_HARDWARE_TYPE => Ok(HardwareType::Ieee802_11Wireless),
        _ => Err(nom::Err::Error(DHCPMessageError::InvalidHardwareType(byte))),
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use crate::dhcp::{
        models::{MAGIC_COOKIE, OPTION_ARP_CACHE_TIMEOUT},
        parser::{parse_dhcp, DhcpOption, Flags, HardwareType, Operation},
    };

    const OPERATION: u8 = 1;
    const HARDWARE_TYPE: u8 = 1;
    const HARDWARE_LEN: u8 = 6;
    const HOPS: u8 = 4;
    const XID: &[u8; 4] = &[5, 6, 7, 8];
    const SECONDS: &[u8; 2] = &[0, 1];
    const FLAGS: &[u8; 2] = &[0b10000000, 0b00];
    const CLIENT_ADDRESS: &[u8; 4] = &[0, 0, 0, 0];
    const YOUR_ADDRESS: &[u8; 4] = &[1, 1, 1, 1];
    const SERVER_ADDRESS: &[u8; 4] = &[2, 2, 2, 2];
    const GATEWAY_ADDRESS: &[u8; 4] = &[3, 3, 3, 3];
    const CLIENT_HARDWARE_ADDRESS: &[u8; 16] = &[3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

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
        [
            single_bytes, xid, seconds, flags,
            client_address, your_address, server_address,
            gateway_address, client_hardware_address ,[0; 192].to_vec(),
            MAGIC_COOKIE.to_be_bytes().to_vec()
        ].concat()
    }

    #[test]
    fn should_parse_dhcp_message() {
        let timeout_ms = 600_u32;
        let timeout_bytes = &timeout_ms.to_be_bytes();
        let bytes = [
            test_message_no_option().as_slice(),
            &[OPTION_ARP_CACHE_TIMEOUT, 4],
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
        assert_eq!(dhcp.flags, Flags { broadcast: true });
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
        assert_eq!(dhcp.options, vec![DhcpOption::ArpCacheTimeout(timeout_ms)]);
    }

    #[test]
    fn parsing_then_serializing_back_to_bytes_should_be_isomorphic() {
        let dhcp_options = [53, 1, 2];
        let bytes = [&test_message_no_option(), dhcp_options.as_slice()].concat();
        let (_, result) = parse_dhcp(&bytes).unwrap();
        assert_eq!(result.as_byte_vec(), bytes);
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
        fn discover() {
            let mut bytes = test_message_no_option();
            bytes[0] = 1;
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(result.operation, Operation::Discover);
        }

        #[test]
        fn offer() {
            let mut bytes = test_message_no_option();
            bytes[0] = 2;
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(result.operation, Operation::Offer);
        }

        #[test]
        fn acknowledgement() {
            let mut bytes = test_message_no_option();
            bytes[0] = 4;
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(result.operation, Operation::Acknowledgement);
        }
    }

    mod dhcp_flags {
        use crate::dhcp::parser::{parse_dhcp, test::test_message_no_option};

        #[test]
        fn acknowledgement() {
            let mut bytes = test_message_no_option();
            bytes[10] = 0b10000000;
            bytes[11] = 0x00;
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert!(result.flags.broadcast)
        }
    }

    mod dhcp_options {
        use std::net::Ipv4Addr;

        use crate::dhcp::{
            models::{
                OPTION_ARP_CACHE_TIMEOUT, OPTION_LOG_SERVER, OPTION_PATH_MTU_PLATEAU_TABLE,
                OPTION_RESOURCE_LOCATION_SERVER, OPTION_SUBNET_MASK,
            },
            parser::{parse_dhcp, test::test_message_no_option, DhcpOption, MessageType},
        };

        #[test]
        fn dhcp_message_type_discover() {
            let dhcp_options = [53, 1, 1];
            let bytes = [&test_message_no_option(), dhcp_options.as_slice()].concat();
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(
                result.options,
                vec![DhcpOption::MessageType(MessageType::Discover)]
            );
        }

        #[test]
        fn dhcp_message_type_offer() {
            let dhcp_options = [53, 1, 2];
            let bytes = [&test_message_no_option(), dhcp_options.as_slice()].concat();
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(
                result.options,
                vec![DhcpOption::MessageType(MessageType::Offer)]
            );
        }

        #[test]
        fn dhcp_message_type_request() {
            let dhcp_options = [53, 1, 3];
            let bytes = [&test_message_no_option(), dhcp_options.as_slice()].concat();
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(
                result.options,
                vec![DhcpOption::MessageType(MessageType::Request)]
            );
        }

        #[test]
        fn dhcp_message_type_acknowledgement() {
            let dhcp_options = [53, 1, 5];
            let bytes = [&test_message_no_option(), dhcp_options.as_slice()].concat();
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(
                result.options,
                vec![DhcpOption::MessageType(MessageType::Acknowledgement)]
            );
        }

        #[test]
        fn dhcp_message_type_release() {
            let dhcp_options = [53, 1, 7];
            let bytes = [&test_message_no_option(), dhcp_options.as_slice()].concat();
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(
                result.options,
                vec![DhcpOption::MessageType(MessageType::Release)]
            );
        }

        #[test]
        fn arp_cache_timeout_option() {
            let timeout = 600_u32;
            let timeout_bytes: [u8; 4] = timeout.to_be_bytes();
            let dhcp_options: [u8; 2] = [OPTION_ARP_CACHE_TIMEOUT, 4];
            let bytes = [
                &test_message_no_option(),
                dhcp_options.as_slice(),
                timeout_bytes.as_slice(),
            ]
            .concat();
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(result.options, vec![DhcpOption::ArpCacheTimeout(timeout)])
        }

        #[test]
        fn subnet_mask_option() {
            let subnet_mask = Ipv4Addr::new(255, 255, 255, 0);
            let subnet_mask_bytes: u32 = subnet_mask.into();
            let subnet_mask_bytes: [u8; 4] = subnet_mask_bytes.to_be_bytes();
            let dhcp_option: [u8; 2] = [OPTION_SUBNET_MASK, 4];
            let bytes = [
                &test_message_no_option(),
                dhcp_option.as_slice(),
                subnet_mask_bytes.as_slice(),
            ]
            .concat();
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(result.options, vec![DhcpOption::SubnetMask(subnet_mask)])
        }

        #[test]
        fn log_server_option() {
            let log_servers = vec![Ipv4Addr::new(255, 255, 255, 0), Ipv4Addr::new(1, 1, 1, 1)];
            let log_servers_bytes: Vec<u8> = log_servers
                .iter()
                .flat_map(|&ip| u32::from(ip).to_be_bytes())
                .collect();
            let dhcp_option: [u8; 2] = [OPTION_LOG_SERVER, 8];
            let bytes = [
                &test_message_no_option(),
                dhcp_option.as_slice(),
                log_servers_bytes.as_slice(),
            ]
            .concat();
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(result.options, vec![DhcpOption::LogServer(log_servers)])
        }

        #[test]
        fn location_server_option() {
            let rlp_servers = vec![Ipv4Addr::new(255, 255, 255, 0), Ipv4Addr::new(1, 1, 1, 1)];
            let rlp_servers_bytes: Vec<u8> = rlp_servers
                .iter()
                .flat_map(|&ip| u32::from(ip).to_be_bytes())
                .collect();
            let dhcp_option: [u8; 2] = [OPTION_RESOURCE_LOCATION_SERVER, 8];
            let bytes = [
                &test_message_no_option(),
                dhcp_option.as_slice(),
                rlp_servers_bytes.as_slice(),
            ]
            .concat();
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(
                result.options,
                vec![DhcpOption::ResourceLocationProtocolServer(rlp_servers)]
            )
        }

        #[test]
        fn mtu_plateau_table() {
            let sizes = vec![10u16, 20];
            let sizes_bytes: Vec<u8> = sizes.iter().copied().flat_map(u16::to_be_bytes).collect();
            let dhcp_option: [u8; 2] = [OPTION_PATH_MTU_PLATEAU_TABLE, 4];
            let bytes = [
                &test_message_no_option(),
                dhcp_option.as_slice(),
                sizes_bytes.as_slice(),
            ]
            .concat();
            let (_, result) = parse_dhcp(&bytes).unwrap();
            assert_eq!(result.options, vec![DhcpOption::PathMTUPlateauTable(sizes)])
        }
    }
}
