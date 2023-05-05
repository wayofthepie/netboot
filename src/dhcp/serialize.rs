use std::collections::HashMap;

use super::models::{
    DhcpMessage, DhcpOption, DhcpOptionValue, HardwareType, MessageType, Operation,
    ACKNOWLEDGEMENT_OPERATION, DISCOVER_OPERATION, ETHERNET_HARDWARE_TYPE,
    IEE801_11WIRELESS_HARDWARE_TYPE, MAGIC_COOKIE, OFFER_OPERATION, OPTION_ARP_CACHE_TIMEOUT,
    OPTION_MESSAGE_TYPE, OPTION_MESSAGE_TYPE_ACKNOWLEDGEMENT, OPTION_MESSAGE_TYPE_DISCOVER,
    OPTION_MESSAGE_TYPE_OFFER, OPTION_MESSAGE_TYPE_RELEASE, OPTION_MESSAGE_TYPE_REQUEST,
    OPTION_PATH_MTU_PLATEAU_TABLE, OPTION_RESOURCE_LOCATION_SERVER, OPTION_SUBNET_MASK,
};

pub fn serialize_dhcp(dhcp: &DhcpMessage) -> Vec<u8> {
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
    [
        [operation, hardware_type, dhcp.hardware_len, dhcp.hops].as_slice(),
        dhcp.xid.to_be_bytes().as_slice(),
        dhcp.seconds.to_be_bytes().as_slice(),
        flags.to_be_bytes().as_slice(),
        dhcp.client_address.octets().as_slice(),
        dhcp.your_address.octets().as_slice(),
        dhcp.server_address.octets().as_slice(),
        dhcp.gateway_address.octets().as_slice(),
        client_hardware_address_padded.as_ref(),
        [0; 192].as_slice(),                   // bootp
        MAGIC_COOKIE.to_be_bytes().as_slice(), // magic cookie
        serialize_dhcp_options(&dhcp.options).as_ref(),
    ]
    .concat()
}

fn serialize_dhcp_options(options: &HashMap<DhcpOption, DhcpOptionValue>) -> Vec<u8> {
    let mut bytes = vec![];
    for option in options.iter() {
        match option {
            (DhcpOption::MessageType, DhcpOptionValue::MessageType(message_type)) => {
                bytes.append(&mut serialize_dhcp_message_type(message_type))
            }
            (DhcpOption::ArpCacheTimeout, DhcpOptionValue::ArpCacheTimeout(timeout)) => {
                let timeout_bytes = timeout.to_be_bytes();
                let mut data = [
                    [OPTION_ARP_CACHE_TIMEOUT, 4].as_slice(),
                    timeout_bytes.as_slice(),
                ]
                .concat();
                bytes.append(&mut data)
            }
            (DhcpOption::SubnetMask, DhcpOptionValue::SubnetMask(mask)) => {
                let mut data =
                    [[OPTION_SUBNET_MASK, 4].as_slice(), mask.octets().as_slice()].concat();
                bytes.append(&mut data);
            }
            (DhcpOption::LogServer, DhcpOptionValue::LogServer(_)) => todo!(),
            (
                DhcpOption::ResourceLocationProtocolServer,
                DhcpOptionValue::ResourceLocationProtocolServer(addresses),
            ) => {
                let len = addresses.len() as u8 * 4;
                let address_bytes: Vec<u8> = addresses
                    .iter()
                    .flat_map(|&address| address.octets())
                    .collect();
                let mut data = [
                    [OPTION_RESOURCE_LOCATION_SERVER, len].as_slice(),
                    address_bytes.as_slice(),
                ]
                .concat();
                bytes.append(&mut data);
            }
            (DhcpOption::PathMTUPlateauTable, DhcpOptionValue::PathMTUPlateauTable(table)) => {
                let len = table.len() as u8 * 2;
                let table_bytes: Vec<u8> = table.iter().flat_map(|num| num.to_be_bytes()).collect();
                let mut data = [
                    [OPTION_PATH_MTU_PLATEAU_TABLE, len].as_slice(),
                    &table_bytes,
                ]
                .concat();
                bytes.append(&mut data);
            }
            (DhcpOption::Router, DhcpOptionValue::Router(address)) => todo!(),
            _ => todo!(),
        }
    }
    bytes
}

fn serialize_dhcp_message_type(message_type: &MessageType) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(3);
    bytes.push(OPTION_MESSAGE_TYPE);
    bytes.push(1);
    let value = match message_type {
        MessageType::Discover => OPTION_MESSAGE_TYPE_DISCOVER,
        MessageType::Offer => OPTION_MESSAGE_TYPE_OFFER,
        MessageType::Request => OPTION_MESSAGE_TYPE_REQUEST,
        MessageType::Acknowledgement => OPTION_MESSAGE_TYPE_ACKNOWLEDGEMENT,
        MessageType::Release => OPTION_MESSAGE_TYPE_RELEASE,
    };
    bytes.push(value);
    bytes
}
