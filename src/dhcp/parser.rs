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
    pub hardware_type: HardwareType,
    pub hardware_len: u8,
    pub hops: u8,
    pub xid: u32,
    pub seconds: u16,
    flags: u16,
    pub options: Vec<DHCPOption>,
}

#[derive(Debug, PartialEq)]
pub enum DHCPOperation {
    Discover,
}

// The hardware types are defined in https://www.rfc-editor.org/rfc/rfc1700.
#[derive(Debug, PartialEq)]
pub enum HardwareType {
    Ethernet,
    Ieee802_11Wireless,
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
    let operation = op_from_byte(raw.operation)?;
    let hardware_type = hardware_type_from_byte(raw.hardware_type)?;
    let (rem, options) = many0(parse_dhcp_option)(raw.options)?;
    let dhcp = DHCPMessage {
        operation,
        hardware_type,
        hardware_len: raw.hardware_len,
        hops: raw.hops,
        xid: u32::from_be_bytes(raw.xid.to_owned()),
        seconds: u16::from_be_bytes(raw.seconds.to_owned()),
        flags: u16::from_be_bytes(raw.flags.to_owned()),
        options,
    };
    Ok((rem, dhcp))
}

fn parse_raw_dhcp(bytes: &[u8]) -> IResult<&[u8], RawDHCPMessage, DHCPMessageError<&[u8]>> {
    match bytes {
        &[operation, hardware_type, hardware_len, hops, ref rem @ ..] => {
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
                    _bootp,
                    _magic_cookie,
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
            Ok((rem, raw))
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

fn op_from_byte<'a>(byte: u8) -> Result<DHCPOperation, nom::Err<DHCPMessageError<&'a [u8]>>> {
    match byte {
        0x01 => Ok(DHCPOperation::Discover),
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
        parse_dhcp, DHCPOperation, DHCPOption, HardwareType, DHCP_OPTION_ARP_CACHE_TIMEOUT,
        DHCP_OPTION_LOG_SERVER, DHCP_OPTION_PATH_MTU_PLATEAU_TABLE,
        DHCP_OPTION_RESOURCE_LOCATION_SERVER, DHCP_OPTION_SUBNET_MASK,
    };

    const OPERATION: u8 = 0x01;
    const HARDWARE_TYPE: u8 = 0x01;
    const HARDWARE_LEN: u8 = 0x06;
    const HOPS: u8 = 0x04;
    const XID: &[u8; 4] = &[0x05, 0x06, 0x07, 0x08];
    const SECONDS: &[u8; 2] = &[0x00, 0x01];
    const FLAGS: &[u8; 2] = &[0x11, 0x12];

    #[rustfmt::skip]
    fn test_message_no_option() -> Vec<u8> {
        let single_bytes = vec![OPERATION, HARDWARE_TYPE, HARDWARE_LEN, HOPS];
        let xid = XID.to_vec();
        let seconds = SECONDS.to_vec();
        let flags = FLAGS.to_vec();
        let rest = vec![0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0x44, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x45, 0x46, 0x47, 0x48
        ];
        [single_bytes, xid, seconds, flags, rest].concat()
    }

    #[test]
    fn should_parse_dhcp_message() {
        let timeout_ms = 600_u32;
        let timeout_bytes = &timeout_ms.to_be_bytes();
        let bytes = [
            test_message_no_option().as_slice(),
            &[DHCP_OPTION_ARP_CACHE_TIMEOUT, 0x04],
            timeout_bytes,
        ]
        .concat();
        let (remainder, dhcp) = parse_dhcp(&bytes).unwrap();
        assert!(remainder.is_empty());
        assert_eq!(dhcp.operation, DHCPOperation::Discover);
        assert_eq!(dhcp.hardware_type, HardwareType::Ethernet);
        assert_eq!(dhcp.hardware_len, HARDWARE_LEN);
        assert_eq!(dhcp.hops, HOPS);
        assert_eq!(dhcp.xid, u32::from_be_bytes(*XID));
        assert_eq!(dhcp.seconds, u16::from_be_bytes(*SECONDS));
        assert_eq!(dhcp.flags, u16::from_be_bytes(*FLAGS));
        assert_eq!(dhcp.options, vec![DHCPOption::ArpCacheTimeout(timeout_ms)]);
    }

    #[test]
    fn should_parse_with_ieee_802_11_wireless_hardware_type() {
        let mut bytes = test_message_no_option();
        bytes[1] = 40;
        let (remainder, result) = parse_dhcp(&bytes).unwrap();
        assert!(remainder.is_empty());
        assert_eq!(result.hardware_type, HardwareType::Ieee802_11Wireless);
    }

    #[test]
    fn should_parse_arp_cache_timeout_option() {
        let timeout = 600_u32;
        let timeout_bytes: [u8; 4] = timeout.to_be_bytes();
        let dhcp_options: [u8; 2] = [DHCP_OPTION_ARP_CACHE_TIMEOUT, 0x04];
        let bytes = [
            &test_message_no_option(),
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
            &test_message_no_option(),
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
            &test_message_no_option(),
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
            &test_message_no_option(),
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
            &test_message_no_option(),
            dhcp_option.as_slice(),
            sizes_bytes.as_slice(),
        ]
        .concat();
        let (_, result) = parse_dhcp(&bytes).unwrap();
        assert_eq!(result.options, vec![DHCPOption::PathMTUPlateauTable(sizes)])
    }
}
