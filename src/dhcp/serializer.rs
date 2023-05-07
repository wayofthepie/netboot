use std::collections::HashMap;

use super::{
    error::DhcpSerializeError,
    models::{
        DhcpMessage, DhcpOption, DhcpOptionValue, HardwareType, MessageType, Operation,
        ACKNOWLEDGEMENT_OPERATION, DISCOVER_OPERATION, ETHERNET_HARDWARE_TYPE,
        IEE801_11WIRELESS_HARDWARE_TYPE, MAGIC_COOKIE, OFFER_OPERATION, OPTION_ARP_CACHE_TIMEOUT,
        OPTION_LOG_SERVER, OPTION_MESSAGE_TYPE, OPTION_MESSAGE_TYPE_ACKNOWLEDGEMENT,
        OPTION_MESSAGE_TYPE_DISCOVER, OPTION_MESSAGE_TYPE_OFFER, OPTION_MESSAGE_TYPE_RELEASE,
        OPTION_MESSAGE_TYPE_REQUEST, OPTION_PATH_MTU_PLATEAU_TABLE,
        OPTION_RESOURCE_LOCATION_SERVER, OPTION_ROUTER, OPTION_SUBNET_MASK,
    },
};

pub fn serialize_dhcp(dhcp: &DhcpMessage) -> Result<Vec<u8>, DhcpSerializeError> {
    let mut bytes = Vec::with_capacity(750);
    let operation = match dhcp.operation {
        Operation::Discover => DISCOVER_OPERATION,
        Operation::Offer => OFFER_OPERATION,
        Operation::Acknowledgement => ACKNOWLEDGEMENT_OPERATION,
    };
    let hardware_type = match dhcp.hardware_type {
        HardwareType::Ethernet => ETHERNET_HARDWARE_TYPE,
        HardwareType::Ieee802_11Wireless => IEE801_11WIRELESS_HARDWARE_TYPE,
    };
    let flags = if dhcp.flags.broadcast { 32768u16 } else { 0 };
    let mut client_hardware_address_padded = dhcp.client_hardware_address.to_vec();
    client_hardware_address_padded.resize(16, 0);
    bytes.extend_from_slice(&[operation, hardware_type, dhcp.hardware_len, dhcp.hops]);
    bytes.extend_from_slice(&dhcp.xid.to_be_bytes());
    bytes.extend_from_slice(&dhcp.seconds.to_be_bytes());
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes.extend_from_slice(&dhcp.client_address.octets());
    bytes.extend_from_slice(&dhcp.your_address.octets());
    bytes.extend_from_slice(&dhcp.server_address.octets());
    bytes.extend_from_slice(&dhcp.gateway_address.octets());
    bytes.extend_from_slice(&client_hardware_address_padded);
    bytes.extend_from_slice(&[0; 192]);
    bytes.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    bytes.extend_from_slice(&serialize_dhcp_options(&dhcp.options)?);
    Ok(bytes)
}

fn serialize_dhcp_options(
    options: &HashMap<DhcpOption, DhcpOptionValue>,
) -> Result<Vec<u8>, DhcpSerializeError> {
    let mut bytes = vec![];
    for option in options.iter() {
        match option {
            (DhcpOption::MessageType, DhcpOptionValue::MessageType(message_type)) => {
                bytes.extend_from_slice(&serialize_dhcp_message_type(message_type))
            }
            (DhcpOption::ArpCacheTimeout, DhcpOptionValue::ArpCacheTimeout(timeout)) => {
                let option = [OPTION_ARP_CACHE_TIMEOUT, 4];
                let timeout_bytes: [u8; 4] = timeout.to_be_bytes();
                bytes.extend_from_slice(&option);
                bytes.extend_from_slice(&timeout_bytes);
            }
            (DhcpOption::SubnetMask, DhcpOptionValue::SubnetMask(mask)) => {
                let option = [OPTION_SUBNET_MASK, 4];
                bytes.extend_from_slice(&option);
                bytes.extend_from_slice(&mask.octets());
            }
            (DhcpOption::LogServer, DhcpOptionValue::LogServer(servers)) => {
                let len = servers.len() as u8 * 4;
                let option = [OPTION_LOG_SERVER, len];
                bytes.extend_from_slice(&option);
                for server in servers {
                    let server_bytes = server.octets();
                    bytes.extend_from_slice(&server_bytes);
                }
            }
            (
                DhcpOption::ResourceLocationProtocolServer,
                DhcpOptionValue::ResourceLocationProtocolServer(addresses),
            ) => {
                let len = addresses.len() as u8 * 4;
                let option = [OPTION_RESOURCE_LOCATION_SERVER, len];
                bytes.extend_from_slice(&option);
                for address in addresses {
                    let address_bytes = address.octets();
                    bytes.extend_from_slice(&address_bytes);
                }
            }
            (DhcpOption::PathMTUPlateauTable, DhcpOptionValue::PathMTUPlateauTable(table)) => {
                let len = table.len() as u8 * 2;
                let option = [OPTION_PATH_MTU_PLATEAU_TABLE, len];
                bytes.extend_from_slice(&option);
                for num in table {
                    let num_bytes = num.to_be_bytes();
                    bytes.extend_from_slice(&num_bytes);
                }
            }
            (DhcpOption::Router, DhcpOptionValue::Router(address)) => {
                let address_bytes = address.octets();
                let len = address_bytes.len() as u8;
                let option = [OPTION_ROUTER, len];
                bytes.extend_from_slice(&option);
                bytes.extend_from_slice(&address_bytes)
            }
            _ => Err(DhcpSerializeError::InvalidDhcpOptionValue)?,
        }
    }
    Ok(bytes)
}

fn serialize_dhcp_message_type(message_type: &MessageType) -> [u8; 3] {
    let mut bytes = [OPTION_MESSAGE_TYPE, 1, 0];
    let value = match message_type {
        MessageType::Discover => OPTION_MESSAGE_TYPE_DISCOVER,
        MessageType::Offer => OPTION_MESSAGE_TYPE_OFFER,
        MessageType::Request => OPTION_MESSAGE_TYPE_REQUEST,
        MessageType::Acknowledgement => OPTION_MESSAGE_TYPE_ACKNOWLEDGEMENT,
        MessageType::Release => OPTION_MESSAGE_TYPE_RELEASE,
    };
    bytes[2] = value;
    bytes
}
