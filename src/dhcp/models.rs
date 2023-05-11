use std::{collections::HashMap, hash::Hash, net::Ipv4Addr, ops::Deref};

use super::{
    deserializer::deserialize_dhcp,
    error::{DhcpMessageError, DhcpSerializeError},
    serializer::serialize_dhcp,
};

pub const MAGIC_COOKIE: u32 = 0x63825363;
pub const OPTION_MESSAGE_TYPE: u8 = 53;
pub const OPTION_MESSAGE_TYPE_DISCOVER: u8 = 1;
pub const OPTION_MESSAGE_TYPE_OFFER: u8 = 2;
pub const OPTION_MESSAGE_TYPE_REQUEST: u8 = 3;
pub const OPTION_MESSAGE_TYPE_ACKNOWLEDGEMENT: u8 = 5;
pub const OPTION_MESSAGE_TYPE_RELEASE: u8 = 7;

pub const OPTION_ARP_CACHE_TIMEOUT: u8 = 35;
pub const OPTION_SUBNET_MASK: u8 = 1;
pub const OPTION_LOG_SERVER: u8 = 7;
pub const OPTION_RESOURCE_LOCATION_SERVER: u8 = 11;
pub const OPTION_PATH_MTU_PLATEAU_TABLE: u8 = 25;
pub const OPTION_ROUTER: u8 = 3;

pub const DISCOVER_OPERATION: u8 = 1;
pub const OFFER_OPERATION: u8 = 2;
pub const REQUEST_OPERATION: u8 = 3;
pub const ACKNOWLEDGEMENT_OPERATION: u8 = 4;

pub const ETHERNET_HARDWARE_TYPE: u8 = 1;
pub const IEE801_11WIRELESS_HARDWARE_TYPE: u8 = 40;

#[derive(Debug, PartialEq)]
pub struct DhcpMessage {
    pub operation: Operation,
    pub hardware_type: HardwareType,
    pub hardware_len: u8,
    pub hops: u8,
    pub xid: u32,
    pub seconds: u16,
    pub flags: Flags,
    pub client_address: Ipv4Addr,
    pub your_address: Ipv4Addr,
    pub server_address: Ipv4Addr,
    pub gateway_address: Ipv4Addr,
    pub client_hardware_address: Vec<u8>,
    pub options: DhcpOptions,
}

impl DhcpMessage {
    pub fn serialize(&self) -> Result<Vec<u8>, DhcpSerializeError> {
        serialize_dhcp(self)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<DhcpMessage, DhcpMessageError> {
        deserialize_dhcp(bytes)
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Operation {
    Discover,
    Offer,
    Request,
    Acknowledgement,
}

#[derive(Clone, Debug, Hash, PartialEq)]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Acknowledgement,
    Release,
}

// The hardware types are defined in https://www.rfc-editor.org/rfc/rfc1700.
#[derive(Debug, PartialEq)]
pub enum HardwareType {
    Ethernet,
    Ieee802_11Wireless,
}

#[derive(Debug, PartialEq)]
pub struct Flags {
    pub broadcast: bool,
}

#[derive(Debug, PartialEq)]
pub struct DhcpOptions(HashMap<DhcpOption, DhcpOptionValue>);

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum DhcpOption {
    MessageType,
    ArpCacheTimeout,
    SubnetMask,
    LogServer,
    ResourceLocationProtocolServer,
    PathMTUPlateauTable,
    Router,
}

impl Deref for DhcpOptions {
    type Target = HashMap<DhcpOption, DhcpOptionValue>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromIterator<(DhcpOption, DhcpOptionValue)> for DhcpOptions {
    fn from_iter<T: IntoIterator<Item = (DhcpOption, DhcpOptionValue)>>(iter: T) -> Self {
        let mut options = HashMap::new();
        for (key, value) in iter {
            options.insert(key, value);
        }
        DhcpOptions(options)
    }
}

impl DhcpOptions {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn insert(&mut self, option: DhcpOptionValue) -> Option<DhcpOptionValue> {
        let (key, value) = match option {
            value @ DhcpOptionValue::MessageType(_) => (DhcpOption::MessageType, value),
            value @ DhcpOptionValue::ArpCacheTimeout(_) => (DhcpOption::ArpCacheTimeout, value),
            value @ DhcpOptionValue::SubnetMask(_) => (DhcpOption::SubnetMask, value),
            value @ DhcpOptionValue::LogServer(_) => (DhcpOption::LogServer, value),
            value @ DhcpOptionValue::ResourceLocationProtocolServer(_) => {
                (DhcpOption::ResourceLocationProtocolServer, value)
            }
            value @ DhcpOptionValue::PathMTUPlateauTable(_) => {
                (DhcpOption::PathMTUPlateauTable, value)
            }
            value @ DhcpOptionValue::Router(_) => (DhcpOption::Router, value),
        };
        self.0.insert(key, value)
    }
}

#[derive(Clone, Debug, Hash, PartialEq)]
pub enum DhcpOptionValue {
    MessageType(MessageType),
    ArpCacheTimeout(u32),
    SubnetMask(Ipv4Addr),
    LogServer(Vec<Ipv4Addr>),
    ResourceLocationProtocolServer(Vec<Ipv4Addr>),
    PathMTUPlateauTable(Vec<u16>),
    Router(Ipv4Addr),
}

#[derive(Debug)]
pub struct RawDhcpMessage<'a> {
    pub operation: u8,
    pub hardware_type: u8,
    pub hardware_len: u8,
    pub hops: u8, // number of relays
    pub xid: &'a [u8; 4],
    pub seconds: &'a [u8; 2],
    pub flags: &'a [u8; 2],
    pub client_address: &'a [u8; 4],
    pub your_address: &'a [u8; 4],
    pub server_address: &'a [u8; 4],
    pub gateway_address: &'a [u8; 4],
    pub client_hardware_address: &'a [u8; 16],
    pub options: &'a [u8],
}

#[cfg(test)]
mod test {
    use std::{net::Ipv4Addr, str::FromStr};

    use crate::dhcp::DhcpOption;

    use super::{DhcpOptionValue, DhcpOptions, MessageType};

    #[test]
    fn should_store_all_options_correctly() {
        let ip = Ipv4Addr::from_str("255.255.255.255").unwrap();
        let mut options = DhcpOptions::new();
        let mappings = vec![
            (
                DhcpOption::MessageType,
                DhcpOptionValue::MessageType(MessageType::Discover),
            ),
            (DhcpOption::SubnetMask, DhcpOptionValue::SubnetMask(ip)),
            (
                DhcpOption::ArpCacheTimeout,
                DhcpOptionValue::ArpCacheTimeout(10),
            ),
            (DhcpOption::Router, DhcpOptionValue::Router(ip)),
            (DhcpOption::LogServer, DhcpOptionValue::LogServer(vec![ip])),
            (
                DhcpOption::ResourceLocationProtocolServer,
                DhcpOptionValue::ResourceLocationProtocolServer(vec![ip]),
            ),
            (
                DhcpOption::PathMTUPlateauTable,
                DhcpOptionValue::PathMTUPlateauTable(vec![0]),
            ),
        ];
        for (option, value) in mappings {
            options.insert(value.clone());
            assert_eq!(options.get(&option).unwrap(), &value);
        }
    }
}
