use crate::{
    node::{KadNode, KadNodeRef},
    routing::RoutingTable,
    util::{Addr, Hash, Peer, RpcArgs, RpcOp, RpcResult, RpcResults, SinglePeer},
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
    async fn key() -> RpcResults;
    async fn ping() -> RpcResults;
    async fn find_node(args: RpcArgs, id: Hash) -> RpcResults;
}

#[derive(Clone)]
pub(crate) struct Service {
    pub(crate) node: KadNodeRef,
    pub(crate) addr: SocketAddr,
}

impl Service {
    // get_addresses, find_node, find_value and store will have a two-step arg validation
    pub(crate) async fn verify(&self, args: &RpcArgs) -> Result<(), RpcResults> {
        let binding = self.node.lock().await;
        let crypto = binding.crypto.lock().await;

        if crypto
            .verify_args(args, || async {
                let kad = binding.kad.upgrade().unwrap();
                let handle = kad.runtime.handle();
                let args_copy = args.clone();
                let node_copy = self.node.clone();

                let _ = handle
                    .spawn_blocking(move || {
                        let _ =
                            KadNode::key(node_copy, Peer::new(args_copy.0.id, args_copy.0.addr));
                    })
                    .await;
            })
            .await
        {
            Ok(())
        } else {
            Err(crypto.results(RpcResult::Bad))
        }
    }
}

impl RpcService for Service {
    async fn key(self, _: context::Context) -> RpcResults {
        let binding = self.node.lock().await;
        let crypto = binding.crypto.lock().await;

        crypto.results(if let Ok(k) = crypto.public_key_as_string() {
            RpcResult::Key(k)
        } else {
            RpcResult::Bad
        })
    }

    // pings are not IDENTIFICATION. we're just seeing if we speak the same language
    async fn ping(self, _: context::Context) -> RpcResults {
        let binding = self.node.lock().await;
        let crypto = binding.crypto.lock().await;

        crypto.results(RpcResult::Ping)
    }

    async fn find_node(self, _: context::Context, args: RpcArgs, id: Hash) -> RpcResults {
        if let Err(r) = self.verify(&args).await {
            return r;
        }

        let binding = self.node.lock().await;
        let crypto = binding.crypto.lock().await;

        let bkt = RoutingTable::find_bucket(binding.table.as_ref().unwrap().clone(), id);

        crypto.results(RpcResult::FindNode(bkt))
    }
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
    use crate::{
        node::{Kad, KadNode, ResponsiveMockPinger},
        routing::{RoutingTable, BUCKET_SIZE, KEY_SIZE},
        util::{generate_peer, Hash, Peer},
    };
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn find_node() {
        let (kad1, kad2) = (Kad::new(16161, false, true), Kad::new(16162, false, true));
        let (handle1, handle2) = (kad1.clone().serve(), kad2.clone().serve());

        let to_find = Hash::from(1);

        let addr1 = kad1.clone().addr();
        let peer1 = Peer::new(kad1.clone().id(), addr1);

        let addr2 = kad2.clone().addr();
        let peer2 = Peer::new(kad2.clone().id(), addr2);

        let table;
        {
            let kad = kad2.clone();
            let binding = kad.node.blocking_lock();
            table = binding.table.as_ref().unwrap().clone();
        }

        let temp = Hash::from(1) << (KEY_SIZE - 1);

        {
            let mut lock = table.blocking_lock();
            lock.id = temp;
        }

        for i in 0..BUCKET_SIZE {
            RoutingTable::update::<ResponsiveMockPinger>(
                table.clone(),
                generate_peer(Some(Hash::from(i))),
            );
        }

        RoutingTable::update::<ResponsiveMockPinger>(
            table.clone(),
            generate_peer(Some(Hash::from(3) << (KEY_SIZE - 2))),
        );

        {
            let reference;
            {
                let kad = kad2.clone();
                let binding = kad.node.blocking_lock();
                let table = binding.table.as_ref().unwrap().clone();
                reference = RoutingTable::find_bucket(table, to_find);
            }

            let res = KadNode::find_node(kad1.node.clone(), peer2.clone(), to_find).unwrap();

            assert!(!res.is_empty());
            assert!(reference.iter().zip(res.iter()).all(|(x, y)| x.id == y.id));
        }

        handle1.abort();
        handle2.abort();
    }
}
