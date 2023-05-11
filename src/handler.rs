use std::{
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
};

use futures::{Sink, SinkExt, TryStream, TryStreamExt};

use crate::dhcp::{self, DhcpMessage, DhcpOptionValue, DhcpOptions, MessageType, Operation};

pub struct Handler<St, Si> {
    stream: St,
    sink: Si,
}

impl<St, Si> Handler<St, Si>
where
    St: TryStreamExt + Unpin,
    St: TryStream<Ok = (DhcpMessage, SocketAddr), Error = Box<dyn std::error::Error + Send + Sync>>,
    Si: Sink<(DhcpMessage, SocketAddr), Error = Box<dyn std::error::Error + Send + Sync>> + Unpin,
    Si: SinkExt<(DhcpMessage, SocketAddr)>,
{
    pub fn new(stream: St, sink: Si) -> Self {
        Self { stream, sink }
    }

    pub async fn handle(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        while let Some((msg, addr)) = self.stream.try_next().await? {
            tracing::debug!("{:#?}", msg);
            tracing::debug!("{:#?}", addr);
            match msg.operation {
                dhcp::Operation::Discover => self.handle_discover(msg).await,
                dhcp::Operation::Offer => todo!(),
                dhcp::Operation::Request => todo!(),
                dhcp::Operation::Acknowledgement => todo!(),
            }
        }
        Ok(())
    }

    async fn handle_discover(&mut self, mut dhcp: DhcpMessage) {
        dhcp.operation = Operation::Offer;
        dhcp.your_address = Ipv4Addr::from_str("192.168.122.204").unwrap();
        dhcp.server_address = Ipv4Addr::from_str("192.168.122.1").unwrap();
        let mut options = DhcpOptions::new();
        options.insert(DhcpOptionValue::MessageType(MessageType::Offer));
        options.insert(DhcpOptionValue::SubnetMask(
            Ipv4Addr::from_str("255.255.255.0").unwrap(),
        ));
        options.insert(DhcpOptionValue::Router(
            Ipv4Addr::from_str("192.168.122.1").unwrap(),
        ));
        dhcp.options = options;
        self.sink
            .send((dhcp, SocketAddr::from_str("255.255.255.255:68").unwrap()))
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod test {
    use std::{
        error::Error,
        net::{Ipv4Addr, SocketAddr},
        pin::Pin,
        str::FromStr,
        task::{Context, Poll},
    };

    use futures::Sink;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;

    use crate::dhcp::{
        DhcpMessage, DhcpOptionValue, DhcpOptions, Flags, HardwareType, MessageType,
        Operation,
    };

    use super::Handler;
    pub struct FakeSink<'a> {
        buffer: &'a mut Vec<(DhcpMessage, SocketAddr)>,
    }

    impl<'a> FakeSink<'a> {
        pub fn new(buffer: &'a mut Vec<(DhcpMessage, SocketAddr)>) -> Self {
            Self { buffer }
        }
    }

    impl<'a> Sink<(DhcpMessage, SocketAddr)> for FakeSink<'a> {
        type Error = Box<dyn Error + Send + Sync>;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(
            mut self: Pin<&mut Self>,
            item: (DhcpMessage, SocketAddr),
        ) -> Result<(), Self::Error> {
            self.buffer.push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
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

    fn expected_offer() -> DhcpMessage {
        let options_vec = vec![
            DhcpOptionValue::MessageType(MessageType::Offer),
            DhcpOptionValue::SubnetMask(Ipv4Addr::from_str("255.255.255.0").unwrap()),
            DhcpOptionValue::Router(Ipv4Addr::from_str("192.168.122.1").unwrap()),
        ];
        let options = DhcpOptions::from_iter(options_vec);
        DhcpMessage {
            operation: Operation::Offer,
            hardware_type: HardwareType::Ethernet,
            hardware_len: 6,
            hops: 0,
            xid: 0,
            seconds: 0,
            flags: Flags { broadcast: true },
            client_address: Ipv4Addr::from_str("0.0.0.0").unwrap(),
            your_address: Ipv4Addr::from_str("192.168.122.204").unwrap(),
            server_address: Ipv4Addr::from_str("192.168.122.1").unwrap(),
            gateway_address: Ipv4Addr::from_str("0.0.0.0").unwrap(),
            client_hardware_address: vec![0, 0, 0, 0, 0, 0],
            options,
        }
    }

    #[tokio::test]
    async fn should_handle_discover() {
        let (tx, rx) = mpsc::channel::<
            Result<(DhcpMessage, SocketAddr), Box<dyn std::error::Error + Send + Sync>>,
        >(16);
        tx.send(Ok((
            build_dhcp_message(),
            SocketAddr::from_str("255.255.255.255:0").unwrap(),
        )))
        .await
        .unwrap();
        tx.send(Err("done".into())).await.unwrap();
        let fake_stream = ReceiverStream::new(rx);
        let mut buffer = vec![];
        let fake_sink = FakeSink::new(&mut buffer);
        let mut handler = Handler::new(fake_stream, fake_sink);
        let _ = handler.handle().await;
        let result = buffer.get(0).unwrap();
        let expected_result = expected_offer();
        assert_eq!(
            result.0, expected_result,
            "expected\n{:#?}\ngot\n{:#?}",
            expected_result, result.0
        );
    }
}
