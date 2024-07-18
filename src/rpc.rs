use crate::{
    node::KadNodeRef,
    util::{Addr, Peer, RpcArgs, RpcOp, SinglePeer},
};
use async_trait::async_trait;
use futures::{future, prelude::*};
use std::time::Duration;
use std::{error::Error, net::SocketAddr};
use tarpc::{
    client, context,
    server::{self, incoming::Incoming, Channel},
    tokio_serde::formats::Json,
};
use tokio::{task::JoinHandle, time::timeout};
use tracing::debug;

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
    pub(crate) node: KadNodeRef,
    pub(crate) addr: SocketAddr,
}

impl Service {
    fn verify<F>(&self, args: &RpcArgs, backup: F) -> bool
    where
        F: Fn(&RpcArgs),
    {
        let binding = self.node.blocking_lock();
        let mut crypto = binding.crypto.blocking_lock();

        let ctx = args.0.clone();

        if crypto.keystore.contains_key(&ctx.id) {
            crypto.verify(
                args.0.id,
                serde_json::to_string(&ctx).unwrap().as_str(),
                &args.1,
            )
        } else {
            // if key doesn't exist, try and get it. if it still doesn't exist, give up.
            backup(args);

            if crypto.keystore.contains_key(&ctx.id) {
                crypto.verify(
                    args.0.id,
                    serde_json::to_string(&ctx).unwrap().as_str(),
                    &args.1,
                )
            } else {
                false
            }
        }
    }
}

impl RpcService for Service {
    async fn key(self, _: context::Context) -> String {
        let binding = self.node.lock().await;
        let crypto = binding.crypto.lock().await;

        crypto.public_key_as_string().unwrap()
    }

    // pings are not IDENTIFICATION. we're just seeing if we speak the same language
    async fn ping(self, _: context::Context, args: RpcArgs) -> bool {
        debug!("ping called!");
        args.0.op == RpcOp::Ping
    }

    // async fn find_node(self, _: context::Context, args: RpcArgs, id: Hash) -> Vec<SinglePeer> {
    //     if self.verify(args, |arg: RpcArgs| {
    //         block_on()
    //     }) {

    //     }
    // }
}

#[async_trait]
pub(crate) trait Network {
    async fn spawn<F: Future<Output = ()> + Send + 'static>(fut: F) {
        tokio::spawn(fut);
    }

    async fn serve(node: KadNodeRef) -> JoinHandle<Result<(), ()>> {
        tokio::spawn(async move {
            let addr;

            {
                let n = node.lock().await;
                addr = n.addr;
            }

            if let Ok(mut listener) =
                tarpc::serde_transport::tcp::listen(&addr, Json::default).await
            {
                listener.config_mut().max_frame_length(usize::MAX);

                debug!("now listening for calls at {:?}:{}", addr.0, addr.1);

                listener
                    .filter_map(|r| future::ready(r.ok()))
                    .map(server::BaseChannel::with_defaults)
                    .max_channels_per_key(1, |t| t.transport().peer_addr().unwrap().ip())
                    .map(|channel| {
                        let server = Service {
                            node: node.clone(),
                            addr: channel.transport().peer_addr().unwrap(),
                        };

                        debug!("peer {:?} connecting", server.addr);

                        channel.execute(server.serve()).for_each(Self::spawn)
                    })
                    .buffer_unordered(10)
                    .for_each(|()| async {})
                    .await;

                Ok(())
            } else {
                Err(())
            }
        })
    }

    async fn connect(addr: Addr) -> Result<RpcServiceClient, Box<dyn Error>> {
        let mut transport = tarpc::serde_transport::tcp::connect(&addr, Json::default);
        transport.config_mut().max_frame_length(usize::MAX);

        Ok(RpcServiceClient::new(client::Config::default(), transport.await?).spawn())
    }

    async fn connect_peer(peer: Peer) -> Result<(RpcServiceClient, SinglePeer), SinglePeer> {
        let mut addr = peer.addresses.iter().peekable();

        let mut last_addr = addr.peek().unwrap().0;

        let connection: Option<RpcServiceClient> = loop {
            match addr.peek() {
                Some(current) => {
                    last_addr = current.0;

                    if let Ok(Ok(client)) =
                        timeout(Duration::from_secs(TIMEOUT), Self::connect(current.0)).await
                    {
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
pub(crate) struct KadNetwork {}
impl Network for KadNetwork {}

#[cfg(test)]
mod tests {
    use crate::{node::Kad, util::Peer};
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn serve() {
        let kad = Kad::new(16161, false, true);
        let handle = kad.serve();

        handle.abort();
    }

    #[test]
    #[traced_test]
    fn ping() {
        let (kad1, kad2) = (Kad::new(16161, false, true), Kad::new(16162, false, true));
        let (handle1, handle2) = (kad1.clone().serve(), kad2.clone().serve());

        let peer1;
        let addr1;
        {
            let kad = kad1.clone();
            let lock = kad.node.blocking_lock();
            let lock2 = lock.table.as_ref().unwrap().blocking_lock();

            addr1 = lock.addr;

            peer1 = Peer {
                id: lock2.id,
                addresses: vec![(lock.addr, 0)],
            };
        }

        let peer2;
        let addr2;
        {
            let kad = kad2.clone();
            let lock = kad.node.blocking_lock();
            let lock2 = lock.table.as_ref().unwrap().blocking_lock();

            addr2 = lock.addr;

            peer2 = Peer {
                id: lock2.id,
                addresses: vec![(lock.addr, 0)],
            };
        }

        {
            let kad = kad1.clone();
            let res = kad.ping(peer2.clone()).unwrap();

            assert_eq!(res.id, peer2.id);
            assert_eq!(res.addr, addr2);
        }

        {
            let kad = kad2.clone();
            let res = kad.ping(peer1.clone()).unwrap();

            assert_eq!(res.id, peer1.id);
            assert_eq!(res.addr, addr1);
        }

        handle1.abort();
        handle2.abort();
    }
}
