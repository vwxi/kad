use crate::{node::NodeRef, util::{Addr, Peer, RpcArgs, SinglePeer}};
use async_trait::async_trait;
use futures::{future, prelude::*};
use std::{error::Error, net::SocketAddr};
use tarpc::{
    client, context,
    server::{self, incoming::Incoming, Channel},
    tokio_serde::formats::Json,
};
use tokio::time::timeout;
use std::time::Duration;

pub(crate) const TIMEOUT: u64 = 15;
pub(crate) const OP_TIMEOUT: u64 = 30;

#[tarpc::service]
pub(crate) trait RpcService {
    async fn key() -> String;
    async fn ping(args: RpcArgs) -> bool;
    //async fn find_node(args: RpcArgs, id: Hash) -> Vec<SinglePeer>;
}

#[derive(Clone)]
pub(crate) struct Service {
    pub(crate) node: NodeRef,
    pub(crate) addr: SocketAddr,
}

impl Service {
    fn verify_args(&self, args: RpcArgs) -> bool {
        let binding = self.node.blocking_lock();
        let mut crypto = binding.crypto.blocking_lock();

        let ctx = args.0.clone();

        crypto.verify(
            args.0.id,
            serde_json::to_string(&ctx).unwrap().as_str(),
            &args.1,
        )
    }
}

impl RpcService for Service {
    async fn key(self, _: context::Context) -> String {
        let binding = self.node.lock().await;
        let crypto = binding.crypto.lock().await;

        crypto.public_key_as_string().unwrap()
    }

    async fn ping(self, _: context::Context, args: RpcArgs) -> bool {
        self.verify_args(args.clone())
    }
}

#[async_trait]
pub(crate) trait Network {
    async fn spawn<F: Future<Output = ()> + Send + 'static>(fut: F) {
        tokio::spawn(fut);
    }

    async fn serve(&self, node: NodeRef) -> Result<(), Box<dyn Error>> {
        let addr;

        {
            let n = node.lock().await;
            addr = n.addr;
        }

        let mut listener = tarpc::serde_transport::tcp::listen(&addr, Json::default).await?;

        listener.config_mut().max_frame_length(usize::MAX);

        listener
            .filter_map(|r| future::ready(r.ok()))
            .map(server::BaseChannel::with_defaults)
            .max_channels_per_key(1, |t| t.transport().peer_addr().unwrap().ip())
            .map(|channel| {
                let server = Service {
                    node: node.clone(),
                    addr: channel.transport().peer_addr().unwrap(),
                };

                channel.execute(server.serve()).for_each(Self::spawn)
            })
            .buffer_unordered(10)
            .for_each(|()| async {})
            .await;

        Ok(())
    }

    async fn connect(&self, addr: Addr) -> Result<RpcServiceClient, Box<dyn Error>> {
        let mut transport = tarpc::serde_transport::tcp::connect(&addr, Json::default);
        transport.config_mut().max_frame_length(usize::MAX);

        Ok(RpcServiceClient::new(client::Config::default(), transport.await?).spawn())
    }

    async fn connect_peer(&self, peer: Peer) -> Result<(RpcServiceClient, SinglePeer), SinglePeer> {
        let mut addr = peer.addresses.iter().peekable();

        let mut last_addr = addr.peek().unwrap().0;

        let connection: Option<RpcServiceClient> = loop {
            match addr.peek() {
                Some(current) => {
                    last_addr = current.0;

                    if let Ok(Ok(client)) = timeout(Duration::from_secs(TIMEOUT), self.connect(current.0)).await {
                        break Some(client);
                    }
                }
                None => break None,
            }
        };

        let single_peer = SinglePeer {
            id: peer.id,
            addr: last_addr,
        };

        if let Some(conn) = connection {
            Ok((conn, single_peer))
        } else {
            Err(single_peer)
        }
    }
}

#[derive(Default)]
pub(crate) struct RealNetwork {}
impl Network for RealNetwork {}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;
    use crate::node::Node;

    #[test]
    #[traced_test]
    fn ping() {
        if let (Ok(node1), Ok(node2)) = (Node::new(16161, false, true), Node::new(16162, false, true)) {
            let (handle1, handle2) = (Node::serve(node1.clone()), Node::serve(node2.clone()));
            
            handle1.abort();
            handle2.abort();
        }
    }
}