mod deserializer;
mod error;
mod models;
mod pool;
mod serializer;

use bytes::{BufMut, BytesMut};
pub use error::*;
pub use models::*;
use tokio_util::codec::{Decoder, Encoder};

pub struct DhcpCodec;

impl DhcpCodec {
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for DhcpCodec {
    type Item = DhcpMessage;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }
        let msg = DhcpMessage::deserialize(src)?;
        let _ = src.split_to(src.len());
        Ok(Some(msg))
    }
}

impl Encoder<DhcpMessage> for DhcpCodec {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn encode(&mut self, item: DhcpMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = item.serialize()?;
        dst.put(bytes.as_slice());
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::{net::Ipv4Addr, str::FromStr};

    use crate::dhcp::models::{
        DhcpMessage, DhcpOption, DhcpOptionValue, Flags, HardwareType, Operation, MAGIC_COOKIE,
        OPTION_ARP_CACHE_TIMEOUT,
    };

    use super::DhcpOptions;

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
    fn build_dhcp_message_bytes_no_option() -> Vec<u8> {
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

    fn build_dhcp_message() -> DhcpMessage {
        DhcpMessage {
            operation: Operation::Discover,
            hardware_type: HardwareType::Ethernet,
            hardware_len: 6,
            hops: 0,
            xid: 0,
            seconds: 0,
            flags: Flags { broadcast: true },
            client_address: Ipv4Addr::from_str("0.0.0.0").unwrap(),
            your_address: Ipv4Addr::from_str("0.0.0.0").unwrap(),
            server_address: Ipv4Addr::from_str("0.0.0.0").unwrap(),
            gateway_address: Ipv4Addr::from_str("0.0.0.0").unwrap(),
            client_hardware_address: vec![0, 0, 0, 0, 0, 0],
            options: DhcpOptions::new(),
        }
    }

    #[test]
    fn should_parse_dhcp_message() {
        let timeout_ms = 600_u32;
        let timeout_bytes = &timeout_ms.to_be_bytes();
        let bytes = [
            build_dhcp_message_bytes_no_option().as_slice(),
            &[OPTION_ARP_CACHE_TIMEOUT, 4],
            timeout_bytes,
        ]
        .concat();
        let dhcp = DhcpMessage::deserialize(&bytes).unwrap();
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
        assert_eq!(
            dhcp.options.get(&DhcpOption::ArpCacheTimeout).unwrap(),
            &DhcpOptionValue::ArpCacheTimeout(timeout_ms)
        );
    }

    mod dhcp_codec {
        use bytes::BytesMut;
        use tokio_util::codec::{Decoder, Encoder};

        use crate::dhcp::{DhcpCodec, DhcpMessage};

        use super::{build_dhcp_message, build_dhcp_message_bytes_no_option};

        #[test]
        fn should_encode() {
            let mut buf = BytesMut::new();
            let mut codec = DhcpCodec::new();
            let dhcp = build_dhcp_message();
            let expected_bytes = dhcp.serialize().unwrap();
            codec.encode(dhcp, &mut buf).unwrap();
            assert_eq!(expected_bytes, buf.as_ref());
        }

        #[test]
        fn should_decode() {
            let mut dhcp_bytes = BytesMut::from_iter(build_dhcp_message_bytes_no_option());
            let mut codec = DhcpCodec::new();
            let expected_dhcp = DhcpMessage::deserialize(&dhcp_bytes).unwrap();
            let result = codec.decode(&mut dhcp_bytes).unwrap().unwrap();
            assert_eq!(expected_dhcp, result);
        }

        #[test]
        fn decode_should_return_none_if_empty() {
            let mut bytes = BytesMut::new();
            let mut codec = DhcpCodec::new();
            let result = codec.decode(&mut bytes).unwrap();
            assert!(result.is_none());
        }
    }

    mod dhcp_serialize {
        use std::collections::HashMap;

        use crate::dhcp::{
            error::DhcpSerializeError,
            models::{DhcpMessage, DhcpOption, DhcpOptionValue},
            test::build_dhcp_message_bytes_no_option,
            DhcpOptions, Operation,
        };

        use super::build_dhcp_message;

        #[test]
        fn serialize_all_operations() {
            let ops = [
                (1, Operation::Discover),
                (2, Operation::Offer),
                (3, Operation::Request),
                (4, Operation::Acknowledgement),
            ];
            let mut test_dhcp_message = build_dhcp_message();
            for (byte, operation) in ops {
                test_dhcp_message.operation = operation;
                let bytes = test_dhcp_message.serialize().unwrap();
                assert_eq!(
                    bytes[0], byte,
                    "byte value {} does not match expected {} for option {:?}",
                    bytes[0], byte, operation
                );
            }
        }

        #[test]
        fn parsing_then_serializing_back_to_bytes_should_be_isomorphic() {
            let dhcp_options = [53, 1, 2];
            let bytes = [
                &build_dhcp_message_bytes_no_option(),
                dhcp_options.as_slice(),
            ]
            .concat();
            let dhcp = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(dhcp.serialize().unwrap(), bytes);
        }

        #[test]
        fn message_type() {
            for message_type_byte in [1, 2, 3, 5, 7] {
                let dhcp_options = [53, 1, message_type_byte];
                let bytes = [
                    &build_dhcp_message_bytes_no_option(),
                    dhcp_options.as_slice(),
                ]
                .concat();
                let dhcp = DhcpMessage::deserialize(&bytes).unwrap();
                assert_eq!(dhcp.serialize().unwrap(), bytes);
            }
        }

        #[test]
        fn arp_cache_timeout() {
            let dhcp_options = [35, 4, 1, 2, 3, 4];
            let bytes = [
                &build_dhcp_message_bytes_no_option(),
                dhcp_options.as_slice(),
            ]
            .concat();
            let dhcp = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(dhcp.serialize().unwrap(), bytes);
        }

        #[test]
        fn path_mtu_table() {
            let options = [25, 4, 10, 32, 100, 23];
            let bytes = [&build_dhcp_message_bytes_no_option(), options.as_slice()].concat();
            let dhcp = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(dhcp.serialize().unwrap(), bytes);
        }

        #[test]
        fn router() {
            let options = [3, 4, 10, 10, 10, 10];
            let bytes = [&build_dhcp_message_bytes_no_option(), options.as_slice()].concat();
            let dhcp = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(dhcp.serialize().unwrap(), bytes);
        }

        #[test]
        fn resource_location_protocol_server() {
            let options = [11, 4, 1, 2, 3, 4];
            let bytes = [&build_dhcp_message_bytes_no_option(), options.as_slice()].concat();
            let dhcp = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(dhcp.serialize().unwrap(), bytes);
        }

        #[test]
        fn log_server() {
            let options = [7, 4, 1, 2, 3, 4];
            let bytes = [&build_dhcp_message_bytes_no_option(), options.as_slice()].concat();
            let dhcp = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(dhcp.serialize().unwrap(), bytes);
        }
    }

    mod dhcp_hardware_types {
        use crate::dhcp::{
            models::{DhcpMessage, HardwareType},
            test::build_dhcp_message_bytes_no_option,
        };

        #[test]
        fn ethernet() {
            let mut bytes = build_dhcp_message_bytes_no_option();
            bytes[1] = 1;
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(result.hardware_type, HardwareType::Ethernet);
        }

        #[test]
        fn ieee_802_11_wireless() {
            let mut bytes = build_dhcp_message_bytes_no_option();
            bytes[1] = 40;
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(result.hardware_type, HardwareType::Ieee802_11Wireless);
        }
    }

    mod dhcp_operations {
        use crate::dhcp::{
            models::{DhcpMessage, Operation},
            test::build_dhcp_message_bytes_no_option,
        };

        #[test]
        fn discover() {
            let mut bytes = build_dhcp_message_bytes_no_option();
            bytes[0] = 1;
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(result.operation, Operation::Discover);
        }

        #[test]
        fn offer() {
            let mut bytes = build_dhcp_message_bytes_no_option();
            bytes[0] = 2;
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(result.operation, Operation::Offer);
        }

        #[test]
        fn request() {
            let mut bytes = build_dhcp_message_bytes_no_option();
            bytes[0] = 3;
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(result.operation, Operation::Request);
        }

        #[test]
        fn acknowledgement() {
            let mut bytes = build_dhcp_message_bytes_no_option();
            bytes[0] = 4;
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(result.operation, Operation::Acknowledgement);
        }
    }

    mod dhcp_flags {
        use crate::dhcp::{models::DhcpMessage, test::build_dhcp_message_bytes_no_option};

        #[test]
        fn acknowledgement() {
            let mut bytes = build_dhcp_message_bytes_no_option();
            bytes[10] = 0b10000000;
            bytes[11] = 0x00;
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert!(result.flags.broadcast)
        }
    }

    mod dhcp_options {
        use std::{net::Ipv4Addr, str::FromStr};

        use crate::dhcp::{
            models::{
                DhcpMessage, DhcpOption, DhcpOptionValue, MessageType, OPTION_ARP_CACHE_TIMEOUT,
                OPTION_LOG_SERVER, OPTION_PATH_MTU_PLATEAU_TABLE, OPTION_RESOURCE_LOCATION_SERVER,
                OPTION_ROUTER, OPTION_SUBNET_MASK,
            },
            test::build_dhcp_message_bytes_no_option,
        };

        #[test]
        fn dhcp_message_type_discover() {
            let dhcp_options = [53, 1, 1];
            let bytes = [
                &build_dhcp_message_bytes_no_option(),
                dhcp_options.as_slice(),
            ]
            .concat();
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(
                result.options.get(&DhcpOption::MessageType).unwrap(),
                &DhcpOptionValue::MessageType(MessageType::Discover)
            );
        }

        #[test]
        fn dhcp_message_type_offer() {
            let dhcp_options = [53, 1, 2];
            let bytes = [
                &build_dhcp_message_bytes_no_option(),
                dhcp_options.as_slice(),
            ]
            .concat();
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(
                result.options.get(&DhcpOption::MessageType).unwrap(),
                &DhcpOptionValue::MessageType(MessageType::Offer)
            );
        }

        #[test]
        fn dhcp_message_type_request() {
            let dhcp_options = [53, 1, 3];
            let bytes = [
                &build_dhcp_message_bytes_no_option(),
                dhcp_options.as_slice(),
            ]
            .concat();
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(
                result.options.get(&DhcpOption::MessageType).unwrap(),
                &DhcpOptionValue::MessageType(MessageType::Request)
            );
        }

        #[test]
        fn dhcp_message_type_acknowledgement() {
            let dhcp_options = [53, 1, 5];
            let bytes = [
                &build_dhcp_message_bytes_no_option(),
                dhcp_options.as_slice(),
            ]
            .concat();
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(
                result.options.get(&DhcpOption::MessageType).unwrap(),
                &DhcpOptionValue::MessageType(MessageType::Acknowledgement)
            );
        }

        #[test]
        fn dhcp_message_type_release() {
            let dhcp_options = [53, 1, 7];
            let bytes = [
                &build_dhcp_message_bytes_no_option(),
                dhcp_options.as_slice(),
            ]
            .concat();
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(
                result.options.get(&DhcpOption::MessageType).unwrap(),
                &DhcpOptionValue::MessageType(MessageType::Release)
            );
        }

        #[test]
        fn arp_cache_timeout_option() {
            let timeout = 600_u32;
            let timeout_bytes: [u8; 4] = timeout.to_be_bytes();
            let dhcp_options: [u8; 2] = [OPTION_ARP_CACHE_TIMEOUT, 4];
            let bytes = [
                &build_dhcp_message_bytes_no_option(),
                dhcp_options.as_slice(),
                timeout_bytes.as_slice(),
            ]
            .concat();
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(
                result.options.get(&DhcpOption::ArpCacheTimeout).unwrap(),
                &DhcpOptionValue::ArpCacheTimeout(timeout)
            )
        }

        #[test]
        fn subnet_mask_option() {
            let subnet_mask = Ipv4Addr::new(255, 255, 255, 0);
            let subnet_mask_bytes: u32 = subnet_mask.into();
            let subnet_mask_bytes: [u8; 4] = subnet_mask_bytes.to_be_bytes();
            let dhcp_option: [u8; 2] = [OPTION_SUBNET_MASK, 4];
            let bytes = [
                &build_dhcp_message_bytes_no_option(),
                dhcp_option.as_slice(),
                subnet_mask_bytes.as_slice(),
            ]
            .concat();
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(
                result.options.get(&DhcpOption::SubnetMask).unwrap(),
                &DhcpOptionValue::SubnetMask(subnet_mask)
            )
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
                &build_dhcp_message_bytes_no_option(),
                dhcp_option.as_slice(),
                log_servers_bytes.as_slice(),
            ]
            .concat();
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(
                result.options.get(&DhcpOption::LogServer).unwrap(),
                &DhcpOptionValue::LogServer(log_servers)
            )
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
                &build_dhcp_message_bytes_no_option(),
                dhcp_option.as_slice(),
                rlp_servers_bytes.as_slice(),
            ]
            .concat();
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(
                result
                    .options
                    .get(&DhcpOption::ResourceLocationProtocolServer)
                    .unwrap(),
                &DhcpOptionValue::ResourceLocationProtocolServer(rlp_servers)
            )
        }

        #[test]
        fn mtu_plateau_table() {
            let sizes = vec![10u16, 20];
            let sizes_bytes: Vec<u8> = sizes.iter().copied().flat_map(u16::to_be_bytes).collect();
            let dhcp_option: [u8; 2] = [OPTION_PATH_MTU_PLATEAU_TABLE, 4];
            let bytes = [
                &build_dhcp_message_bytes_no_option(),
                dhcp_option.as_slice(),
                sizes_bytes.as_slice(),
            ]
            .concat();
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(
                result
                    .options
                    .get(&DhcpOption::PathMTUPlateauTable)
                    .unwrap(),
                &DhcpOptionValue::PathMTUPlateauTable(sizes)
            )
        }

        #[test]
        fn router() {
            let address = Ipv4Addr::from_str("192.168.1.1").unwrap();
            let dhcp_option: [u8; 2] = [OPTION_ROUTER, 4];
            let bytes = [
                &build_dhcp_message_bytes_no_option(),
                dhcp_option.as_slice(),
                address.octets().as_slice(),
            ]
            .concat();
            let result = DhcpMessage::deserialize(&bytes).unwrap();
            assert_eq!(
                result.options.get(&DhcpOption::Router).unwrap(),
                &DhcpOptionValue::Router(address)
            )
        }
    }
}
