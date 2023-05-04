use std::net::Ipv4Addr;

use nom::bytes::complete::take;
use nom::combinator::map;
use nom::multi::many0;
use nom::sequence::tuple;
use nom::IResult;

use super::error::DHCPMessageError;

const DHCP_OPTION_ARP_CACHE_TIMEOUT: u8 = 0x035;
const DHCP_OPTION_SUBNET_MASK: u8 = 0x01;
const DHCP_OPTION_LOG_SERVER: u8 = 0x07;
const DHCP_OPTION_RESOURCE_LOCATION_SERVER: u8 = 0x11;
const DHCP_OPTION_PATH_MTU_PLATEAU_TABLE: u8 = 0x25;

#[derive(Debug, PartialEq)]
pub struct DHCPMessage {
    pub operation: DHCPOperation,
    pub options: Vec<DHCPOption>,
}

#[derive(Debug, Default, PartialEq)]
pub enum DHCPOperation {
    #[default]
    Discover,
}

#[derive(Debug, PartialEq)]
pub enum DHCPOption {
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
    // This can be more than just a mac address, hence why it's 16 bytes. For example
    // it could be a GUID up to 128 bits in length. The length that needs to be
    // parsed is defined in hardware_len.
    client_hardware_address: &'a [u8; 16],
    options: &'a [u8],
}

pub fn parse_dhcp(bytes: &[u8]) -> IResult<&[u8], DHCPMessage, DHCPMessageError<&[u8]>> {
    // TODO make sure remainder is empty
    let (_, raw) = parse_raw_dhcp(bytes)?;
    let (_, operation) = op_from_byte(raw.operation)?;
    let (rem, options) = many0(parse_dhcp_option)(raw.options)?;
    let dhcp = DHCPMessage { operation, options };
    Ok((rem, dhcp))
}

fn parse_raw_dhcp(bytes: &[u8]) -> IResult<&[u8], RawDHCPMessage, DHCPMessageError<&[u8]>> {
    match bytes {
        &[op, hardware_type, hardware_len, hops, ref rem @ ..] => {
            type ParsedRemainder<'a> = (
                &'a [u8],
                (
                    &'a [u8; 4],   // xid
                    &'a [u8; 2],   // seconds
                    &'a [u8; 2],   // flags
                    &'a [u8; 4],   // client addr
                    &'a [u8; 4],   // your addr
                    &'a [u8; 4],   // server address
                    &'a [u8; 4],   // gateway address
                    &'a [u8; 16],  // client hardware address
                    &'a [u8; 192], // bootp
                    &'a [u8; 4],   // magic cookie
                    &'a [u8],
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
                    _, // bootp
                    _, // magic cookie
                    options,
                ),
            ): ParsedRemainder = tuple((
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
            ))(rem)?;
            let discover = RawDHCPMessage {
                operation: op,
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
            Ok((rem, discover))
        }
        _ => Err(nom::Err::Error(DHCPMessageError::InvalidData)),
    }
}

// For reference see <https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml>.
fn parse_dhcp_option(bytes: &[u8]) -> IResult<&[u8], DHCPOption, DHCPMessageError<&[u8]>> {
    match bytes {
        [DHCP_OPTION_ARP_CACHE_TIMEOUT, _, ref rem @ ..] => {
            let (rem, data) = take_n_bytes::<4>(rem)?;
            let timeout: u32 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            Ok((rem, DHCPOption::ArpCacheTimeout(timeout)))
        }
        [DHCP_OPTION_SUBNET_MASK, _, ref rem @ ..] => {
            let (rem, data) = take_n_bytes::<4>(rem)?;
            let subnet_mask = Ipv4Addr::from(*data);
            Ok((rem, DHCPOption::SubnetMask(subnet_mask)))
        }
        [DHCP_OPTION_LOG_SERVER, len, ref rem @ ..] => {
            let (rem, data) = take(*len as usize)(rem)?;
            // TODO: Make sure there are no bytes leftover here.
            let (_, addresses) = parse_ip_addresses(data)?;
            Ok((rem, DHCPOption::LogServer(addresses)))
        }
        [DHCP_OPTION_RESOURCE_LOCATION_SERVER, len, ref rem @ ..] => {
            let (rem, data) = take(*len as usize)(rem)?;
            // TODO: Make sure there are no bytes leftover here.
            let (_, addresses) = parse_ip_addresses(data)?;
            Ok((rem, DHCPOption::ResourceLocationProtocolServer(addresses)))
        }
        [DHCP_OPTION_PATH_MTU_PLATEAU_TABLE, len, ref rem @ ..] => {
            let (rem, data) = take(*len as usize)(rem)?;
            // TODO: Make sure there are no bytes leftover here.
            let (_, sizes) =
                many0(map(take_n_bytes::<2>, |&bytes| u16::from_be_bytes(bytes)))(data)?;
            tracing::debug!("MTU PLATEAU [ len: {len}, sizes: {sizes:#?}]");
            Ok((rem, DHCPOption::PathMTUPlateauTable(sizes)))
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

fn op_from_byte<'a>(byte: u8) -> IResult<(), DHCPOperation, DHCPMessageError<&'a [u8]>> {
    match byte {
        0x01 => Ok(((), DHCPOperation::Discover)),
        _ => Err(nom::Err::Error(DHCPMessageError::InvalidOperation)),
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use crate::dhcp::parser::{
        parse_dhcp, parse_raw_dhcp, DHCPOperation, DHCPOption, RawDHCPMessage,
        DHCP_OPTION_ARP_CACHE_TIMEOUT, DHCP_OPTION_LOG_SERVER, DHCP_OPTION_PATH_MTU_PLATEAU_TABLE,
        DHCP_OPTION_RESOURCE_LOCATION_SERVER, DHCP_OPTION_SUBNET_MASK,
    };

    const TEST_MESSAGE_NO_OPTION: &[u8] = &[
        0x01, 0x01, 0x06, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
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

    // TODO temporary, until fully refactored
    #[test]
    fn should_parse_dhcp_message_to_raw() {
        let op = 0x01;
        let hardware_type = 0x01;
        let hardware_len = 0x06;
        let hops = 0x04;
        let xid = &[0x05, 0x06, 0x07, 0x08];
        let seconds = &[0x09, 0x10];
        let flags = &[0x11, 0x12];
        let client_address = &[0x13, 0x14, 0x15, 0x16];
        let your_address = &[0x17, 0x18, 0x19, 0x20];
        let server_address = &[0x21, 0x22, 0x23, 0x24];
        let gateway_address = &[0x25, 0x26, 0x27, 0x28];
        let client_hardware_address = &[
            0x29, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42,
            0x43, 0x44,
        ];
        let expected = RawDHCPMessage {
            operation: op,
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
            options: &[],
        };
        let (rem, result) = parse_raw_dhcp(TEST_MESSAGE_NO_OPTION).unwrap();
        assert_eq!(result.operation, expected.operation);
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
        assert!(rem.is_empty());
    }

    #[test]
    fn should_parse_dhcp_message() {
        let timeout_ms = 600_u32;
        let timeout_bytes = &timeout_ms.to_be_bytes();
        let bytes = [
            TEST_MESSAGE_NO_OPTION,
            &[DHCP_OPTION_ARP_CACHE_TIMEOUT, 0x04],
            timeout_bytes,
        ]
        .concat();
        let (remainder, result) = parse_dhcp(&bytes).unwrap();
        assert!(remainder.is_empty());
        assert_eq!(result.operation, DHCPOperation::Discover);
        assert_eq!(
            result.options,
            vec![DHCPOption::ArpCacheTimeout(timeout_ms)]
        );
    }

    #[test]
    fn should_parse_arp_cache_timeout_option() {
        let timeout = 600_u32;
        let timeout_bytes: [u8; 4] = timeout.to_be_bytes();
        let dhcp_options: [u8; 2] = [DHCP_OPTION_ARP_CACHE_TIMEOUT, 0x04];
        let bytes = [
            TEST_MESSAGE_NO_OPTION,
            dhcp_options.as_slice(),
            timeout_bytes.as_slice(),
        ]
        .concat();
        let (_, result) = parse_dhcp(&bytes).unwrap();
        assert_eq!(result.options, vec![DHCPOption::ArpCacheTimeout(timeout)])
    }

    #[test]
    fn should_parse_subnet_mask_option() {
        let subnet_mask = Ipv4Addr::new(255, 255, 255, 0);
        let subnet_mask_bytes: u32 = subnet_mask.into();
        let subnet_mask_bytes: [u8; 4] = subnet_mask_bytes.to_be_bytes();
        let dhcp_option: [u8; 2] = [DHCP_OPTION_SUBNET_MASK, 0x04];
        let bytes = [
            TEST_MESSAGE_NO_OPTION,
            dhcp_option.as_slice(),
            subnet_mask_bytes.as_slice(),
        ]
        .concat();
        let (_, result) = parse_dhcp(&bytes).unwrap();
        assert_eq!(result.options, vec![DHCPOption::SubnetMask(subnet_mask)])
    }

    #[test]
    fn should_parse_log_server_option() {
        let log_servers = vec![Ipv4Addr::new(255, 255, 255, 0), Ipv4Addr::new(1, 1, 1, 1)];
        let log_servers_bytes: Vec<u8> = log_servers
            .iter()
            .flat_map(|&ip| u32::from(ip).to_be_bytes())
            .collect();
        let dhcp_option: [u8; 2] = [DHCP_OPTION_LOG_SERVER, 0x08];
        let bytes = [
            TEST_MESSAGE_NO_OPTION,
            dhcp_option.as_slice(),
            log_servers_bytes.as_slice(),
        ]
        .concat();
        let (_, result) = parse_dhcp(&bytes).unwrap();
        assert_eq!(result.options, vec![DHCPOption::LogServer(log_servers)])
    }

    #[test]
    fn should_parse_resource_location_server_option() {
        let rlp_servers = vec![Ipv4Addr::new(255, 255, 255, 0), Ipv4Addr::new(1, 1, 1, 1)];
        let rlp_servers_bytes: Vec<u8> = rlp_servers
            .iter()
            .flat_map(|&ip| u32::from(ip).to_be_bytes())
            .collect();
        let dhcp_option: [u8; 2] = [DHCP_OPTION_RESOURCE_LOCATION_SERVER, 0x08];
        let bytes = [
            TEST_MESSAGE_NO_OPTION,
            dhcp_option.as_slice(),
            rlp_servers_bytes.as_slice(),
        ]
        .concat();
        let (_, result) = parse_dhcp(&bytes).unwrap();
        assert_eq!(
            result.options,
            vec![DHCPOption::ResourceLocationProtocolServer(rlp_servers)]
        )
    }

    #[test]
    fn should_parse_path_mtu_plateau_table() {
        let sizes = vec![10u16, 20];
        let sizes_bytes: Vec<u8> = sizes.iter().copied().flat_map(u16::to_be_bytes).collect();
        let dhcp_option: [u8; 2] = [DHCP_OPTION_PATH_MTU_PLATEAU_TABLE, 0x04];
        let bytes = [
            TEST_MESSAGE_NO_OPTION,
            dhcp_option.as_slice(),
            sizes_bytes.as_slice(),
        ]
        .concat();
        let (_, result) = parse_dhcp(&bytes).unwrap();
        assert_eq!(result.options, vec![DHCPOption::PathMTUPlateauTable(sizes)])
    }
}
