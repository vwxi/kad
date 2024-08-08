use crate::{
    crypto::Crypto,
    routing::{RoutingTable, TableRef},
    rpc::{KadNetwork, Network},
    util::{timestamp, Addr, Hash, Peer, RpcOp, RpcResult, RpcResults, SinglePeer},
};
use bigint::U256;
use rsa::sha2::{Digest, Sha256};
use std::sync::{Arc, Weak};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr}
};
use tarpc::context;
use tokio::{
    runtime::{Handle, Runtime},
    task::JoinHandle
};
use tracing::debug;

pub(crate) struct KadNode {
    pub(crate) addr: Addr,
    pub(crate) crypto: Crypto,
    pub(crate) table: TableRef,
    pub(crate) kad: Weak<Kad>,
}

pub struct Kad {
    pub(crate) node: KadNodeRef,
    pub(crate) runtime: Runtime,
}

pub(crate) type KadNodeRef = Arc<KadNode>;
pub(crate) type WeakNodeRef = Weak<KadNode>;

impl Kad {
    pub fn new(port: u16, ipv6: bool, local: bool) -> Arc<Self> {
        Arc::new_cyclic(|gadget| Kad {
            node: KadNode::new(port, ipv6, local, gadget.clone())
                .expect("could not create KadNode object"),
            runtime: Runtime::new().expect("could not create runtime for Kad object"),
        })
    }

    pub fn serve(self: Arc<Self>) -> JoinHandle<()> {
        KadNode::serve(self.runtime.handle(), self.node.clone())
    }

    pub fn ping(self: Arc<Self>, peer: Peer) -> Result<SinglePeer, SinglePeer> {
        KadNode::ping(self.node.clone(), peer)
    }

    pub fn addr(self: Arc<Self>) -> Addr {
        self.node.addr
    }

    pub fn id(self: Arc<Self>) -> Hash {
        let table = self.node.table.blocking_lock();

        table.id
    }
}

macro_rules! kad_fn {
    // without rpc arguments
    ($func:ident, $op:expr, $return_type:ty, $closure:expr) => {
        #[allow(clippy::redundant_closure_call)] // not too sure
        pub(crate) fn $func(node: KadNodeRef, peer: Peer) -> Result<$return_type, SinglePeer> {
            // hacky
            let kad = node.kad.upgrade().unwrap();

            if peer.addresses.is_empty() {
                let nothing = SinglePeer {
                    id: U256::from(0),
                    addr: (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                };

                return Err(nothing);
            }

            let handle = kad.runtime.handle();

            handle.block_on(async {
                match KadNetwork::connect_peer(kad.clone(), peer).await {
                    Ok((conn, responding_peer)) => {
                        match conn.client.$func(context::current()).await {
                            Ok(res) => {
                                $closure(node.clone(), res, responding_peer).await
                            },
                            Err(err) => {
                                debug!("{} operation failed ({:?})", stringify!($func), err);
                                Err(responding_peer)
                            },
                        }
                    }
                    Err(single_peer) => Err(single_peer),
                }
            })
        }
    };

    // with rpc arguments
    ($func:ident, $op:expr, $return_type:ty, $closure:expr, ($($arg:ident : $type:ty),*)) => {
        #[allow(clippy::redundant_closure_call)] // not too sure
        pub(crate) fn $func(node: KadNodeRef, peer: Peer, $( $arg : $type ),*) -> Result<$return_type, SinglePeer> {
            let kad = node.kad.upgrade().unwrap();

            if peer.addresses.is_empty() {
                let nothing = SinglePeer {
                    id: U256::from(0),
                    addr: (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                };

                return Err(nothing);
            }

            let args;
            {
                let table = node.table.blocking_lock();
                args = node.crypto.args(table.id, $op($( $arg ),*), node.addr, timestamp());
            }

            let handle = kad.runtime.handle();

            handle.block_on(async {
                match KadNetwork::connect_peer(kad.clone(), peer).await {
                    Ok((conn, responding_peer)) => {
                        if node.crypto.if_unknown(responding_peer.id, || async {
                            if let Ok((RpcResult::Key(key), _)) = conn.client.key(context::current()).await {
                                let mut hasher = Sha256::new();
                                hasher.update(key.as_bytes());
                                let key_hash = Hash::from_little_endian(hasher.finalize().as_mut_slice());
                
                                if key_hash == responding_peer.id {
                                    node.crypto.entry(responding_peer.id, key.as_str()).await
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        }).await {
                            match conn.client.$func(context::current(), args, $( $arg ),*).await {
                                Ok(res) => {
                                    $closure(node.clone(), res, responding_peer).await
                                },
                                Err(err) => {
                                    debug!("{} operation failed ({:?})", stringify!($func), err);
                                    Err(responding_peer)
                                },
                            }
                        } else {
                            debug!("could not acquire key");
                            Err(responding_peer)
                        }
                    }
                    Err(single_peer) => Err(single_peer),
                }
            })
        }
    }
}

impl KadNode {
    // TODO: implement non-local forwarding of some sort
    pub(crate) fn new(
        port: u16,
        ipv6: bool,
        local: bool,
        k: Weak<Kad>,
    ) -> Result<KadNodeRef, Box<dyn Error>> {
        let a = (
            if ipv6 {
                if local {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                } else {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                }
            } else if local {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            },
            port,
        );

        let c = Crypto::new()?;
        let mut hasher = Sha256::new();

        hasher.update(c.public_key_as_string().unwrap().as_bytes());

        let id = Hash::from_little_endian(hasher.finalize().as_mut_slice());

        Ok(Arc::new_cyclic(|gadget| KadNode {
            addr: a,
            table: RoutingTable::new(id, gadget.clone()),
            crypto: c,
            kad: k,
        }))
    }

    pub(crate) fn serve(handle: &Handle, node: KadNodeRef) -> JoinHandle<()> {
        handle.block_on(KadNetwork::serve(node))
    }

    // key and ping do not update routing table

    kad_fn!(
        key,
        RpcOp::Key,
        SinglePeer,
        |node: KadNodeRef, res: RpcResults, resp: SinglePeer| async move {
            // check if hash(key) == id then add to keystore
            if let RpcResult::Key(result) = res.0 {
                let mut hasher = Sha256::new();
                hasher.update(result.as_bytes());
                let key_hash = Hash::from_little_endian(hasher.finalize().as_mut_slice());

                if key_hash == resp.id {
                    if node.crypto.entry(resp.id, result.as_str()).await {
                        Ok(resp)
                    } else {
                        Err(resp)
                    }
                } else {
                    Err(resp)
                }
            } else {
                Err(resp)
            }
        }
    );

    kad_fn!(
        ping,
        RpcOp::Ping,
        SinglePeer,
        |_, res: RpcResults, resp: SinglePeer| async move {
            if let RpcResult::Ping = res.0 {
                Ok(resp)
            } else {
                Err(resp)
            }
        }
    );

    // get_addresses, find_node, find_value and store will update the routing table

    kad_fn!(
        find_node,
        |id: Hash| RpcOp::FindNode(id),
        Vec<SinglePeer>,
        |node: KadNodeRef, res: RpcResults, resp: SinglePeer| async move {    
            // check if results are okay
            if let RpcResult::FindNode(peers) = res.0.clone() {
                if node.crypto.verify_results(resp.id, &res).await {
                    RoutingTable::update::<RealPinger>(node.table.clone(), resp).await;

                    Ok(peers)
                } else {
                    Err(resp)
                }
            } else {
                Err(resp)
            }
        },
        (id: Hash)
    );
}

pub(crate) trait Pinger {
    // this function only exists to facilitate easier test mocking
    fn ping_peer(node: KadNodeRef, peer: Peer) -> Result<SinglePeer, SinglePeer> {
        KadNode::ping(node, peer)
    }
}

#[derive(Default)]
pub(crate) struct RealPinger {}
impl Pinger for RealPinger {}

#[derive(Default)]
pub(crate) struct ResponsiveMockPinger {}
impl Pinger for ResponsiveMockPinger {
    fn ping_peer(_: KadNodeRef, p: Peer) -> Result<SinglePeer, SinglePeer> {
        Ok(SinglePeer {
            id: p.id,
            addr: p.addresses.first().unwrap().0,
        })
    }
}

#[derive(Default)]
pub(crate) struct UnresponsiveMockPinger {}
impl Pinger for UnresponsiveMockPinger {
    fn ping_peer(_: KadNodeRef, p: Peer) -> Result<SinglePeer, SinglePeer> {
        Err(SinglePeer {
            id: p.id,
            addr: p.addresses.first().unwrap().0,
        })
    }
}
