use std::net::Ipv4Addr;

use nom::combinator::map;
use nom::multi::many0;
use nom::sequence::tuple;
use nom::{bytes::complete::take, IResult};

use super::error::DHCPMessageError;

#[derive(Debug, Default)]
pub struct DHCPMessage<'a> {
    pub op: DHCPOperation,
    pub hardware_type: u8,
    pub hardware_len: u8,
    pub hops: u8, // number of relays
    pub xid: [u8; 4],
    pub seconds: [u8; 2],
    pub flags: u16,
    pub client_address: [u8; 4],
    pub your_address: [u8; 4],
    pub server_address: [u8; 4],
    pub gateway_address: [u8; 4],
    // This can be more than just a mac address, hence why it's 16 bytes. For example
    // it could be a GUID up to 128 bits in length. The length that needs to be
    // parsed is defined in hardware_len.
    pub client_hardware_address: &'a [u8],
    pub options: Vec<DHCPOption>,
}

impl DHCPMessage<'_> {
    const BROADCAST_FLAG_BIT: usize = 15;

    pub fn is_broadcast(&self) -> bool {
        self.is_bit_set_in_flags(Self::BROADCAST_FLAG_BIT)
    }

    fn is_bit_set_in_flags(&self, n: usize) -> bool {
        self.flags & (1 << n) != 0
    }
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

pub fn parse_dhcp(bytes: &[u8]) -> IResult<&[u8], DHCPMessage, DHCPMessageError<&[u8]>> {
    match bytes {
        &[op, hardware_type, hardware_len, hops, ref rem @ ..] => {
            type ParsedRemainder<'a> = (
                &'a [u8],
                (
                    [u8; 4],   // xid
                    [u8; 2],   // seconds
                    [u8; 2],   // flags
                    [u8; 4],   // client addr
                    [u8; 4],   // your addr
                    [u8; 4],   // server address
                    [u8; 4],   // gateway address
                    &'a [u8],  // client hardware address
                    [u8; 192], // bootp
                    [u8; 4],   // magic cookie
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
                ),
            ): ParsedRemainder = tuple((
                take_n_bytes::<4>,
                take_n_bytes::<2>,
                take_n_bytes::<2>,
                take_n_bytes::<4>,
                take_n_bytes::<4>,
                take_n_bytes::<4>,
                take_n_bytes::<4>,
                take(16usize),
                take_n_bytes::<192>,
                take_n_bytes::<4>,
            ))(rem)?;
            let (rem, options) = many0(parse_dhcp_option)(rem)?;
            let (_, client_hardware_address) = take(hardware_len)(client_hardware_address)?;
            let flags = u16::from_be_bytes(flags);
            let discover = DHCPMessage {
                op: op_from_byte(op)?.1,
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

const DHCP_OPTION_ARP_CACHE_TIMEOUT: u8 = 0x035;
const DHCP_OPTION_SUBNET_MASK: u8 = 0x01;
const DHCP_OPTION_LOG_SERVER: u8 = 0x07;
const DHCP_OPTION_RESOURCE_LOCATION_SERVER: u8 = 0x11;
const DHCP_OPTION_PATH_MTU_PLATEAU_TABLE: u8 = 0x25;

// For reference see <https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml>.
fn parse_dhcp_option(bytes: &[u8]) -> IResult<&[u8], DHCPOption, DHCPMessageError<&[u8]>> {
    match bytes {
        [DHCP_OPTION_ARP_CACHE_TIMEOUT, _, ref rem @ ..] => {
            let (rem, data) = take_n_bytes::<4>(rem)?;
            let timeout: u32 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            Ok((rem, DHCPOption::ArpCacheTimeout(timeout / 100)))
        }
        [DHCP_OPTION_SUBNET_MASK, _, ref rem @ ..] => {
            let (rem, data) = take_n_bytes::<4>(rem)?;
            let subnet_mask = Ipv4Addr::from(data);
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
            let (_, sizes) = many0(map(take_n_bytes::<2>, u16::from_be_bytes))(data)?;
            tracing::debug!("MTU PLATEAU [ len: {len}, sizes: {sizes:#?}]");
            Ok((rem, DHCPOption::PathMTUPlateauTable(sizes)))
        }
        _ => Err(nom::Err::Error(DHCPMessageError::NotYetImplemented)),
    }
}

fn take_n_bytes<const N: usize>(bytes: &[u8]) -> IResult<&[u8], [u8; N], DHCPMessageError<&[u8]>> {
    map(take(N), |client_address: &[u8]| {
        client_address.try_into().unwrap()
    })(bytes)
}

fn parse_ip_addresses(bytes: &[u8]) -> IResult<&[u8], Vec<Ipv4Addr>, DHCPMessageError<&[u8]>> {
    many0(map(take_n_bytes::<4>, Ipv4Addr::from))(bytes)
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
        parse_dhcp, DHCPMessage, DHCPOperation, DHCPOption, DHCP_OPTION_ARP_CACHE_TIMEOUT,
        DHCP_OPTION_LOG_SERVER, DHCP_OPTION_PATH_MTU_PLATEAU_TABLE,
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

    #[test]
    fn should_parse_dhcp_discover() {
        let hardware_type = 0x01;
        let hardware_len = 0x06;
        let hops = 0x04;
        let xid = [0x05, 0x06, 0x07, 0x08];
        let seconds = [0x09, 0x10];
        let flags = u16::from_be_bytes([0x11, 0x12]);
        let client_address = [0x13, 0x14, 0x15, 0x16];
        let your_address = [0x17, 0x18, 0x19, 0x20];
        let server_address = [0x21, 0x22, 0x23, 0x24];
        let gateway_address = [0x25, 0x26, 0x27, 0x28];
        let client_hardware_address = &[0x29, 0x30, 0x31, 0x32, 0x33, 0x34];
        let expected = DHCPMessage {
            op: DHCPOperation::Discover,
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
        assert!(rem.is_empty());
    }

    #[test]
    fn should_parse_arp_cache_timeout_option() {
        let timeout = 60000_u32;
        let timeout_bytes: [u8; 4] = timeout.to_be_bytes();
        let dhcp_options: [u8; 2] = [DHCP_OPTION_ARP_CACHE_TIMEOUT, 0x04];
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

    #[test]
    fn should_have_broadcast_flag_set() {
        let mut dhcp_with_flag = Vec::from(TEST_MESSAGE_NO_OPTION);
        dhcp_with_flag[10] = 0b10000000;
        dhcp_with_flag[11] = 0b00000000;
        let (_, dhcp) = parse_dhcp(&dhcp_with_flag).unwrap();
        println!("{:b}", u16::from_be_bytes([0b10000000, 0b00000000]));
        println!("{}", u16::from_be_bytes([0b10000000, 0b00000000]));
        assert!(dhcp.is_broadcast());
    }
}
