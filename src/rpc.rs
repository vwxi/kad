use crate::{node::NodeRef, util::{Addr, Peer, RpcArgs, SinglePeer}};
use async_trait::async_trait;
use futures::{future, prelude::*};
#[cfg(test)]
use mockall::{automock, predicate::*};
use std::{error::Error, net::SocketAddr};
use tarpc::{
    client, context,
    server::{self, incoming::Incoming, Channel},
    tokio_serde::formats::Json,
};

pub const TIMEOUT: u64 = 15;
pub const OP_TIMEOUT: u64 = 30;

#[tarpc::service]
pub trait RpcService {
    async fn key() -> String;
    async fn ping(args: RpcArgs) -> bool;
    //async fn find_node(args: RpcArgs, id: Hash) -> Vec<SinglePeer>;
}

#[derive(Clone)]
pub struct Service {
    pub node: NodeRef,
    pub addr: SocketAddr,
}

impl RpcService for Service {
    async fn key(self, _: context::Context) -> String {
        let binding = self.node.lock().unwrap();
        let crypto = binding.crypto.lock().unwrap();

        crypto.public_key_as_string().unwrap()
    }

    async fn ping(self, _: context::Context, args: RpcArgs) -> bool {
        let binding = self.node.lock().unwrap();
        let mut crypto = binding.crypto.lock().unwrap();

        let ctx = args.0.clone();

        crypto.verify(
            args.0.id,
            serde_json::to_string(&ctx).unwrap().as_str(),
            &args.1,
        )
    }
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait Network {
    async fn spawn<F: Future<Output = ()> + Send + 'static>(fut: F) {
        tokio::spawn(fut);
    }

    async fn serve(&self, node: NodeRef) -> Result<(), Box<dyn Error>> {
        let addr;

        {
            let n = node.lock().unwrap();
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

    async fn check_liveness(&self, peer: Peer, args: RpcArgs) -> Result<SinglePeer, SinglePeer> {
        let mut addr = peer.addresses.iter().peekable();

        let mut last_addr = addr.peek().unwrap().0;

        let connection: Option<RpcServiceClient> = loop {
            match addr.peek() {
                Some(current) => {
                    last_addr = current.0;

                    if let Ok(client) = self.connect(current.0).await {
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

        match connection {
            Some(client) => {
                if client.ping(context::current(), args).await.is_ok() {
                    Ok(single_peer)
                } else {
                    Err(single_peer)
                }
            }
            None => Err(single_peer),
        }
    }
}

pub struct RealNetwork {}
impl Network for RealNetwork {}
