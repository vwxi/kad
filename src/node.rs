use crate::{
    crypto::Crypto,
    routing::{RoutingTable, TableRef},
    rpc::{KadNetwork, Network, TIMEOUT},
    util::{timestamp, Addr, Hash, Peer, RpcOp, RpcResult, RpcResults, SinglePeer},
};
use bigint::U256;
use rsa::sha2::{Digest, Sha256};
use std::sync::{Arc, Weak};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tarpc::context;
use tokio::{
    runtime::{Handle, Runtime},
    sync::{Mutex, MutexGuard},
    task::JoinHandle,
    time::timeout,
};
use tracing::debug;

pub(crate) struct KadNode {
    pub(crate) addr: Addr,
    pub(crate) crypto: Mutex<Crypto>,
    pub(crate) table: Option<TableRef>,
    pub(crate) kad: Weak<Kad>,
}

pub struct Kad {
    pub(crate) node: KadNodeRef,
    pub(crate) runtime: Runtime,
}

pub(crate) type KadNodeRef = Arc<Mutex<KadNode>>;
pub(crate) type WeakNodeRef = Weak<Mutex<KadNode>>;

impl Kad {
    pub fn new(port: u16, ipv6: bool, local: bool) -> Arc<Self> {
        Arc::new_cyclic(|gadget| Kad {
            node: KadNode::new(port, ipv6, local, gadget.clone())
                .expect("could not create KadNode object"),
            runtime: Runtime::new().expect("could not create runtime for Kad object"),
        })
    }

    pub fn serve(self: Arc<Self>) -> JoinHandle<Result<(), ()>> {
        KadNode::serve(self.runtime.handle(), self.node.clone())
    }

    pub fn ping(self: Arc<Self>, peer: Peer) -> Result<SinglePeer, SinglePeer> {
        KadNode::ping(self.node.clone(), peer)
    }

    pub fn addr(self: Arc<Self>) -> Addr {
        let lock = self.node.blocking_lock();

        lock.addr
    }

    pub fn id(self: Arc<Self>) -> Hash {
        let lock = self.node.blocking_lock();
        let table = lock.table.as_ref().unwrap().blocking_lock();

        table.id
    }
}

macro_rules! kad_fn {
    // without rpc arguments
    ($func:ident, $op:expr, $return_type:ty, $closure:expr) => {
        #[allow(clippy::redundant_closure_call)] // not too sure
        pub(crate) fn $func(node: KadNodeRef, peer: Peer) -> Result<$return_type, SinglePeer> {
            // hacky
            let lock = node.blocking_lock();
            let kad = lock.kad.upgrade().unwrap();

            if peer.addresses.is_empty() {
                let nothing = SinglePeer {
                    id: U256::from(0),
                    addr: (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                };

                return Err(nothing);
            }

            let handle = kad.runtime.handle();

            handle.block_on(async {
                match KadNetwork::connect_peer(peer).await {
                    Ok((conn, responding_peer)) => {
                        if let Ok(Ok(result)) = timeout(Duration::from_secs(TIMEOUT), conn.$func(context::current())).await {
                            let f = |lock: MutexGuard<KadNode>, res: RpcResults, resp: SinglePeer| -> Result<$return_type, SinglePeer> {
                                $closure(lock, res, resp)
                            };

                            f(lock, result, responding_peer)
                        } else {
                            debug!("{} operation timed out", stringify!($func));
                            Err(responding_peer)
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
            let lock = node.blocking_lock();
            let kad = lock.kad.upgrade().unwrap();

            if peer.addresses.is_empty() {
                let nothing = SinglePeer {
                    id: U256::from(0),
                    addr: (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                };

                return Err(nothing);
            }

            let args;
            {
                let table = lock.table.as_ref().unwrap().blocking_lock();
                let crypto = lock.crypto.blocking_lock();
                args = crypto.args(table.id, $op($( $arg ),*), lock.addr, timestamp());
            }

            let handle = kad.runtime.handle();

            handle.block_on(async {
                match KadNetwork::connect_peer(peer).await {
                    Ok((conn, responding_peer)) => {
                        if let Ok(Ok(result)) = timeout(Duration::from_secs(TIMEOUT), conn.$func(context::current(), args, $( $arg ),*)).await {
                            let f = |lock: MutexGuard<KadNode>, res: RpcResults, resp: SinglePeer| -> Result<$return_type, SinglePeer> {
                                $closure(lock, res, resp)
                            };

                            f(lock, result, responding_peer)
                        } else {
                            debug!("{} operation timed out", stringify!($func));
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

        let node = Arc::new_cyclic(|gadget| {
            Mutex::new(KadNode {
                addr: a,
                table: Some(RoutingTable::new(id, gadget.clone())),
                crypto: Mutex::new(c),
                kad: k,
            })
        });

        Ok(node)
    }

    pub(crate) fn serve(handle: &Handle, node: KadNodeRef) -> JoinHandle<Result<(), ()>> {
        handle.block_on(KadNetwork::serve(node))
    }

    // key and ping do not update routing table

    kad_fn!(
        key,
        RpcOp::Key,
        SinglePeer,
        |lock: MutexGuard<KadNode>, res: RpcResults, resp: SinglePeer| {
            // check if hash(key) == id then add to keystore
            if let RpcResult::Key(result) = res.0 {
                let mut crypto = lock.crypto.blocking_lock();

                let mut hasher = Sha256::new();
                hasher.update(result.as_bytes());
                let key_hash = Hash::from_little_endian(hasher.finalize().as_mut_slice());

                if key_hash == resp.id {
                    if crypto.entry(resp.id, result.as_str()) {
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
        |_, res: RpcResults, resp: SinglePeer| {
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
        |lock: MutexGuard<KadNode>, res: RpcResults, resp: SinglePeer| {
            // check if results are okay
            let crypto = lock.crypto.blocking_lock();

            if let RpcResult::FindNode(peers) = res.0.clone() {
                if crypto.verify_results(resp.id, &res) {
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
