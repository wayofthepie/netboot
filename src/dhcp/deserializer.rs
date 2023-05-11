use std::net::Ipv4Addr;

use nom::bytes::complete::take;
use nom::combinator::map;
use nom::multi::many0;
use nom::sequence::tuple;
use nom::IResult;

use super::error::DhcpMessageError;
use super::models::{
    DhcpMessage, DhcpOptionValue, DhcpOptions, Flags, HardwareType, MessageType, Operation,
    RawDhcpMessage, ACKNOWLEDGEMENT_OPERATION, DISCOVER_OPERATION, ETHERNET_HARDWARE_TYPE,
    IEE801_11WIRELESS_HARDWARE_TYPE, OFFER_OPERATION, OPTION_ARP_CACHE_TIMEOUT, OPTION_LOG_SERVER,
    OPTION_MESSAGE_TYPE, OPTION_MESSAGE_TYPE_ACKNOWLEDGEMENT, OPTION_MESSAGE_TYPE_DISCOVER,
    OPTION_MESSAGE_TYPE_OFFER, OPTION_MESSAGE_TYPE_RELEASE, OPTION_MESSAGE_TYPE_REQUEST,
    OPTION_PATH_MTU_PLATEAU_TABLE, OPTION_RESOURCE_LOCATION_SERVER, OPTION_ROUTER,
    OPTION_SUBNET_MASK,
};
use super::REQUEST_OPERATION;

pub fn deserialize_dhcp(bytes: &[u8]) -> Result<DhcpMessage, DhcpMessageError> {
    match deserialize_dhcp_internal(bytes) {
        Ok(msg) => Ok(msg),
        Err(nom::Err::Error(e)) => Err(e),
        Err(nom::Err::Failure(e)) => Err(e),
        Err(nom::Err::Incomplete(_)) => Err(DhcpMessageError::IncompleteData),
    }
}

fn deserialize_dhcp_internal(bytes: &[u8]) -> Result<DhcpMessage, nom::Err<DhcpMessageError>> {
    // TODO make sure rest is empty
    let (_, raw) = deserialize_raw_dhcp(bytes)?;
    let operation = op_from_byte(raw.operation)?;
    let hardware_len = raw.hardware_len;
    let hardware_type = hardware_type_from_byte(raw.hardware_type)?;
    let xid = u32::from_be_bytes(raw.xid.to_owned());
    let seconds = u16::from_be_bytes(raw.seconds.to_owned());
    let flags = deserialize_flags(raw.flags);
    let client_address = Ipv4Addr::from(*raw.client_address);
    let your_address = Ipv4Addr::from(*raw.your_address);
    let server_address = Ipv4Addr::from(*raw.server_address);
    let gateway_address = Ipv4Addr::from(*raw.gateway_address);
    let (_, client_hardware_address) = take(hardware_len)(raw.client_hardware_address.as_slice())?;
    let (_, options) = many0(deserialize_dhcp_option)(raw.options)?;
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
        client_hardware_address: client_hardware_address.to_vec(),
        options: DhcpOptions::from_iter(options),
    };
    Ok(dhcp)
}

fn deserialize_raw_dhcp(bytes: &[u8]) -> IResult<&[u8], RawDhcpMessage, DhcpMessageError> {
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
        _ => Err(nom::Err::Error(DhcpMessageError::InvalidData)),
    }
}

// For reference see <https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml>.
fn deserialize_dhcp_option(bytes: &[u8]) -> IResult<&[u8], DhcpOptionValue, DhcpMessageError> {
    match bytes {
        [OPTION_MESSAGE_TYPE, _, ref rest @ ..] => match rest {
            [OPTION_MESSAGE_TYPE_DISCOVER, rest @ ..] => {
                Ok((rest, DhcpOptionValue::MessageType(MessageType::Discover)))
            }
            [OPTION_MESSAGE_TYPE_OFFER, rest @ ..] => {
                Ok((rest, DhcpOptionValue::MessageType(MessageType::Offer)))
            }
            [OPTION_MESSAGE_TYPE_REQUEST, rest @ ..] => {
                Ok((rest, DhcpOptionValue::MessageType(MessageType::Request)))
            }
            [OPTION_MESSAGE_TYPE_ACKNOWLEDGEMENT, rest @ ..] => Ok((
                rest,
                DhcpOptionValue::MessageType(MessageType::Acknowledgement),
            )),
            [OPTION_MESSAGE_TYPE_RELEASE, rest @ ..] => {
                Ok((rest, DhcpOptionValue::MessageType(MessageType::Release)))
            }
            _ => Err(nom::Err::Error(
                DhcpMessageError::InvalidValueForOptionMessageType(rest[0]),
            )),
        },
        [OPTION_ARP_CACHE_TIMEOUT, _, ref rest @ ..] => {
            let (rest, data) = take_n_bytes::<4>(rest)?;
            let timeout: u32 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            Ok((rest, DhcpOptionValue::ArpCacheTimeout(timeout)))
        }
        [OPTION_SUBNET_MASK, _, ref rest @ ..] => {
            let (rest, data) = take_n_bytes::<4>(rest)?;
            let subnet_mask = Ipv4Addr::from(*data);
            Ok((rest, DhcpOptionValue::SubnetMask(subnet_mask)))
        }
        [OPTION_LOG_SERVER, len, ref rest @ ..] => {
            let (rest, data) = take(*len as usize)(rest)?;
            // TODO: Make sure there are no bytes leftover here.
            let (_, addresses) = deserialize_ip_addresses(data)?;
            Ok((rest, DhcpOptionValue::LogServer(addresses)))
        }
        [OPTION_RESOURCE_LOCATION_SERVER, len, ref rest @ ..] => {
            let (rest, data) = take(*len as usize)(rest)?;
            // TODO: Make sure there are no bytes leftover here.
            let (_, addresses) = deserialize_ip_addresses(data)?;
            Ok((
                rest,
                DhcpOptionValue::ResourceLocationProtocolServer(addresses),
            ))
        }
        [OPTION_PATH_MTU_PLATEAU_TABLE, len, ref rest @ ..] => {
            let (rest, data) = take(*len as usize)(rest)?;
            let (_, sizes) =
                many0(map(take_n_bytes::<2>, |&bytes| u16::from_be_bytes(bytes)))(data)?;
            Ok((rest, DhcpOptionValue::PathMTUPlateauTable(sizes)))
        }
        [OPTION_ROUTER, _, ref rest @ ..] => {
            let (rest, data) = take_n_bytes::<4>(rest)?;
            let address = Ipv4Addr::from(*data);
            Ok((rest, DhcpOptionValue::Router(address)))
        }
        _ => Err(nom::Err::Error(DhcpMessageError::NotYetImplemented)),
    }
}

const BROADCAST_BIT: usize = 15;
fn deserialize_flags(flags: &[u8; 2]) -> Flags {
    let flags = u16::from_be_bytes(*flags);
    Flags {
        broadcast: is_bit_set(BROADCAST_BIT, flags),
    }
}

fn is_bit_set(index: usize, num: u16) -> bool {
    num & (1 << index) != 0
}

fn take_n_bytes<const N: usize>(bytes: &[u8]) -> IResult<&[u8], &[u8; N], DhcpMessageError> {
    map(take(N), |client_address: &[u8]| {
        client_address.try_into().unwrap()
    })(bytes)
}

fn deserialize_ip_addresses(bytes: &[u8]) -> IResult<&[u8], Vec<Ipv4Addr>, DhcpMessageError> {
    many0(map(take_n_bytes::<4>, |&bytes| Ipv4Addr::from(bytes)))(bytes)
}

fn op_from_byte(byte: u8) -> Result<Operation, nom::Err<DhcpMessageError>> {
    match byte {
        DISCOVER_OPERATION => Ok(Operation::Discover),
        OFFER_OPERATION => Ok(Operation::Offer),
        REQUEST_OPERATION => Ok(Operation::Request),
        ACKNOWLEDGEMENT_OPERATION => Ok(Operation::Acknowledgement),
        _ => Err(nom::Err::Error(DhcpMessageError::InvalidOperation)),
    }
}

fn hardware_type_from_byte(byte: u8) -> Result<HardwareType, nom::Err<DhcpMessageError>> {
    match byte {
        ETHERNET_HARDWARE_TYPE => Ok(HardwareType::Ethernet),
        IEE801_11WIRELESS_HARDWARE_TYPE => Ok(HardwareType::Ieee802_11Wireless),
        _ => Err(nom::Err::Error(DhcpMessageError::InvalidHardwareType(byte))),
    }
}
