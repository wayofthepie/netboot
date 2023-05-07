use std::{collections::HashMap, net::Ipv4Addr};

use super::{error::DhcpSerializeError, serializer::serialize_dhcp};

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
pub const ACKNOWLEDGEMENT_OPERATION: u8 = 4;

pub const ETHERNET_HARDWARE_TYPE: u8 = 1;
pub const IEE801_11WIRELESS_HARDWARE_TYPE: u8 = 40;

#[derive(Debug, PartialEq)]
pub struct DhcpMessage<'a> {
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
    pub client_hardware_address: &'a [u8],
    pub options: DhcpOptions,
}

impl DhcpMessage<'_> {
    pub fn as_byte_vec(&self) -> Result<Vec<u8>, DhcpSerializeError> {
        serialize_dhcp(self)
    }
}

#[derive(Debug, PartialEq)]
pub enum Operation {
    Discover,
    Offer,
    Acknowledgement,
}

#[derive(Debug, Hash, PartialEq)]
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

pub type DhcpOptions = HashMap<DhcpOption, DhcpOptionValue>;

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

#[derive(Debug, Hash, PartialEq)]
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
