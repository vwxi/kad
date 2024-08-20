use crate::{
    crypto::Crypto,
    routing::{RoutingTable, TableRef},
    rpc::{KadNetwork, Network},
    store::{Store, StoreEntry},
    util::{
        hash, timestamp, Addr, FindValueResult, Hash, Peer, RpcOp, RpcResult, RpcResults,
        SinglePeer,
    },
    U256,
};
use futures::executor::block_on;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Weak};
use tarpc::context;
use tokio::{runtime::Runtime, task::JoinHandle};
use tracing::debug;

pub(crate) struct KadNode {
    pub(crate) addr: Addr,
    pub(crate) crypto: Crypto,
    pub(crate) store: Store,
    pub(crate) table: TableRef,
    pub(crate) kad: Weak<Kad>,
}

pub struct Kad {
    pub(crate) node: Arc<KadNode>,
    pub(crate) runtime: Runtime,
}

impl Kad {
    #[must_use]
    pub fn new(port: u16, ipv6: bool, local: bool) -> Arc<Self> {
        Arc::new_cyclic(|gadget| Kad {
            node: KadNode::new(port, ipv6, local, gadget.clone()),
            runtime: Runtime::new().expect("could not create runtime for Kad object"),
        })
    }

    pub fn serve(self: Arc<Self>) -> std::io::Result<JoinHandle<()>> {
        self.node.clone().serve()
    }

    pub fn ping(self: Arc<Self>, peer: Peer) -> Result<SinglePeer, Box<SinglePeer>> {
        self.node.clone().ping(peer)
    }

    pub fn addr(self: &Arc<Self>) -> Addr {
        self.node.addr
    }

    pub fn id(self: &Arc<Self>) -> Hash {
        self.node.table.id
    }

    pub(crate) fn as_single_peer(self: &Arc<Self>) -> SinglePeer {
        SinglePeer {
            id: self.id(),
            addr: self.node.addr,
        }
    }

    pub(crate) fn as_peer(self: &Arc<Self>) -> Peer {
        self.as_single_peer().as_peer()
    }
}

macro_rules! kad_fn {
    // without rpc arguments
    ($func:ident, $op:expr, $return_type:ty, $closure:expr) => {
        #[allow(clippy::redundant_closure_call)] // not too sure
        pub(in crate) fn $func(self: Arc<Self>, peer: Peer) -> Result<$return_type, Box<SinglePeer>> {
            // hacky
            let kad = self.kad.upgrade().unwrap();

            if peer.addresses.is_empty() {
                let nothing = SinglePeer {
                    id: U256::from(0),
                    addr: Addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                };

                return Err(Box::new(nothing));
            }

            let handle = kad.runtime.handle();

            handle.block_on(async {
                match KadNetwork::connect_peer(kad.clone(), peer).await {
                    Ok((conn, responding_peer)) => {
                        match conn.client.$func(context::current()).await {
                            Ok(res) => {
                                $closure(self.clone(), res, responding_peer).await
                            },
                            Err(err) => {
                                debug!("{} operation failed ({:?})", stringify!($func), err);
                                Err(Box::new(responding_peer))
                            },
                        }
                    }
                    Err(single_peer) => {
                        debug!("could not connect to peer {:?}", single_peer.addr);
                        Err(Box::new(single_peer))
                    },
                }
            })
        }
    };

    // with rpc arguments
    ($func:ident, $op:expr, $return_type:ty, $closure:expr, ($($arg:ident : $type:ty),*)) => {
        #[allow(clippy::redundant_closure_call)] // not too sure
        pub(in crate) fn $func(self: Arc<Self>, peer: Peer, $( $arg : $type ),*) -> Result<($return_type, SinglePeer), Box<SinglePeer>> {
            let kad = self.kad.upgrade().unwrap();

            if peer.addresses.is_empty() {
                let nothing = SinglePeer {
                    id: U256::from(0),
                    addr: Addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                };

                return Err(Box::new(nothing));
            }

            let args = self.crypto.args(self.table.id, $op($( $arg ),*), self.addr, timestamp());

            let handle = kad.runtime.handle();

            handle.block_on(async {
                match KadNetwork::connect_peer(kad.clone(), peer).await {
                    Ok((conn, responding_peer)) => {
                        if self.crypto.if_unknown(&responding_peer.id, || async {
                            if let Ok((RpcResult::Key(key), _)) = conn.client.key(context::current()).await {
                                if hash(key.as_str()) == responding_peer.id {
                                    self.crypto.entry(responding_peer.id, key.as_str()).await
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        }, || true).await {
                            match conn.client.$func(context::current(), args).await {
                                Ok(res) => {
                                    $closure(self.clone(), res, responding_peer).await
                                },
                                Err(err) => {
                                    debug!("{} operation failed ({:?})", stringify!($func), err);
                                    Err(Box::new(responding_peer))
                                },
                            }
                        } else {
                            debug!("could not acquire key");
                            Err(Box::new(responding_peer))
                        }
                    }
                    Err(single_peer) => {
                        debug!("could not connect to peer {:?}", single_peer.addr);
                        Err(Box::new(single_peer))
                    }
                }
            })
        }
    }
}

// TODO: join mechanism
// TODO: republish mechanism
// TODO: refresh mechanism
// TODO: iterative store mechanism
impl KadNode {
    // TODO: implement non-local forwarding of some sort
    pub(crate) fn new(port: u16, ipv6: bool, local: bool, k: Weak<Kad>) -> Arc<KadNode> {
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

        Arc::new_cyclic(|gadget| {
            let c = Crypto::new(gadget.clone()).expect("could not initialize crypto");
            let id = hash(
                c.public_key_as_string()
                    .expect("could not acquire public key for ID hash")
                    .as_str(),
            );

            let kn = KadNode {
                addr: Addr(a.0, a.1),
                table: RoutingTable::new(id, gadget.clone()),
                store: Store::new(gadget.clone()),
                crypto: c,
                kad: k,
            };

            // add own key
            block_on(
                kn.crypto.entry(
                    id,
                    kn.crypto
                        .public_key_as_string()
                        .expect("could not acquire public key for keyring")
                        .as_str(),
                ),
            );

            kn
        })
    }

    pub(crate) fn serve(self: Arc<Self>) -> std::io::Result<JoinHandle<()>> {
        let kad = self.kad.upgrade().unwrap();

        kad.runtime.handle().block_on(KadNetwork::serve(self))
    }

    // key, get_addresses and ping do not update routing table

    kad_fn!(
        key,
        RpcOp::Key,
        SinglePeer,
        |node: Arc<KadNode>, res: RpcResults, resp: SinglePeer| async move {
            // check if hash(key) == id then add to keystore
            if let RpcResult::Key(result) = res.0 {
                if hash(result.as_str()) == resp.id {
                    if node.crypto.entry(resp.id, result.as_str()).await {
                        Ok(resp)
                    } else {
                        Err(Box::new(resp))
                    }
                } else {
                    Err(Box::new(resp))
                }
            } else {
                Err(Box::new(resp))
            }
        }
    );

    kad_fn!(
        get_addresses,
        |id: Hash| RpcOp::GetAddresses(id),
        Vec<Addr>,
        |_: Arc<KadNode>, res: RpcResults, resp: SinglePeer| async move {
            if let RpcResult::GetAddresses(Some(addrs)) = res.0 {
                Ok((addrs, resp))
            } else {
                Err(Box::new(resp))
            }
        },
        (id: Hash)
    );

    kad_fn!(
        ping,
        RpcOp::Ping,
        SinglePeer,
        |_, res: RpcResults, resp: SinglePeer| async move {
            if let RpcResult::Ping = res.0 {
                Ok(resp)
            } else {
                Err(Box::new(resp))
            }
        }
    );

    // find_node, find_value and store will update the routing table

    kad_fn!(
        store,
        |key: Hash, entry: StoreEntry| RpcOp::Store(key, Box::new(entry)),
        bool,
        |node: Arc<KadNode>, res: RpcResults, resp: SinglePeer| async move {
            if let RpcResult::Store = res.0.clone() {
                if node.crypto.verify_results(&resp.id, &res).await {
                    node.table.clone().update::<RealPinger>(resp).await;

                    Ok((true, resp))
                } else {
                    Err(Box::new(resp))
                }
            } else {
                Ok((false, resp))
            }
        },
        (key: Hash, entry: StoreEntry)
    );

    kad_fn!(
        find_node,
        |id: Hash| RpcOp::FindNode(id),
        Vec<SinglePeer>,
        |node: Arc<KadNode>, res: RpcResults, resp: SinglePeer| async move {
            if let RpcResult::FindNode(peers) = res.0.clone() {
                if node.crypto.verify_results(&resp.id, &res).await {
                    node.table.clone().update::<RealPinger>(resp).await;

                    Ok((peers, resp))
                } else {
                    Err(Box::new(resp))
                }
            } else {
                Err(Box::new(resp))
            }
        },
        (id: Hash)
    );

    kad_fn!(
        find_value,
        |id: Hash| RpcOp::FindValue(id),
        Box<FindValueResult>,
        |node: Arc<KadNode>, res: RpcResults, resp: SinglePeer| async move {
            if let RpcResult::FindValue(result) = res.0.clone() {
                if node.crypto.verify_results(&resp.id, &res).await {
                    node.table.clone().update::<RealPinger>(resp).await;

                    Ok((result, resp))
                } else {
                    Err(Box::new(resp))
                }
            } else {
                Err(Box::new(resp))
            }
        },
        (id: Hash)
    );
}

pub(crate) trait Pinger {
    // this function only exists to facilitate easier test mocking
    fn ping_peer(node: Arc<KadNode>, peer: Peer) -> Result<SinglePeer, Box<SinglePeer>> {
        tokio::task::block_in_place(|| node.ping(peer))
    }
}

#[derive(Default)]
pub(crate) struct RealPinger {}
impl Pinger for RealPinger {}

#[derive(Default)]
pub(crate) struct ResponsiveMockPinger {}
impl Pinger for ResponsiveMockPinger {
    fn ping_peer(_: Arc<KadNode>, p: Peer) -> Result<SinglePeer, Box<SinglePeer>> {
        Ok(SinglePeer {
            id: p.id,
            addr: p.addresses.first().unwrap().0,
        })
    }
}

#[derive(Default)]
pub(crate) struct UnresponsiveMockPinger {}
impl Pinger for UnresponsiveMockPinger {
    fn ping_peer(_: Arc<KadNode>, p: Peer) -> Result<SinglePeer, Box<SinglePeer>> {
        Err(Box::new(SinglePeer {
            id: p.id,
            addr: p.addresses.first().unwrap().0,
        }))
    }
}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use crate::{routing::consts, util::generate_peer};

    use super::*;

    #[traced_test]
    #[test]
    fn refresh() {
        
    }
}