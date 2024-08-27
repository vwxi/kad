use crate::{
    crypto::Crypto,
    routing::{consts, RoutingTable, TableRef},
    rpc::{KadNetwork, Network},
    store::{Store, StoreEntry},
    util::{
        hash, timestamp, Addr, FindValueResult, Hash, Peer, RpcOp, RpcResult, RpcResults,
        SinglePeer,
    },
    U256,
};
use futures::executor::block_on;
#[cfg(test)]
use std::error::Error;
use std::sync::{Arc, Weak};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tarpc::context;
use tokio::{runtime::Runtime, sync::Mutex, task::AbortHandle, time::sleep};
use tracing::debug;

// all of the different facets of the protocol
#[derive(Debug)]
pub(crate) struct InnerKad {
    pub(crate) addr: Addr,
    pub(crate) crypto: Crypto,
    pub(crate) store: Store,
    pub(crate) table: TableRef,
    pub(crate) parent: Weak<Kad>,
}

// holds the inner node and its thread handles
#[derive(Debug)]
pub struct Kad {
    pub(crate) node: Arc<InnerKad>,
    pub(crate) runtime: Runtime,
    pub(crate) kad_handle: Mutex<Option<AbortHandle>>,
    pub(crate) refresh_handle: Mutex<Option<AbortHandle>>,
    // TODO: republish handle
}

impl Kad {
    #[must_use]
    pub fn new(port: u16, ipv6: bool, local: bool) -> Arc<Self> {
        Arc::new_cyclic(|gadget| {
            let n = InnerKad::new(port, ipv6, local, gadget.clone());
            let rt = Runtime::new().expect("could not create Kad runtime object");

            Kad {
                kad_handle: Mutex::new(None),
                refresh_handle: Mutex::new(None),
                node: n.clone(),
                runtime: rt,
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn mock(id: Hash, main: bool, refresh: bool) -> Result<Arc<Self>, Box<dyn Error>> {
        let rt = Runtime::new().expect("could not create Kad runtime object");

        let new = Arc::new_cyclic(|kad_gadget| {
            let n = Arc::new_cyclic(|innerkad_gadget| {
                let c = Crypto::new(innerkad_gadget.clone()).expect("could not initialize crypto");

                let kn = InnerKad {
                    addr: Addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 16161),
                    table: RoutingTable::new(id, innerkad_gadget.clone()),
                    store: Store::new(innerkad_gadget.clone()),
                    crypto: c,
                    parent: kad_gadget.clone(),
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
            });

            Kad {
                kad_handle: Mutex::new(if main {
                    // ignore error because testing
                    Some(n.clone().serve().unwrap())
                } else {
                    None
                }),
                refresh_handle: Mutex::new(if refresh {
                    let nc = n.clone();
                    Some(
                        rt.spawn(async move {
                            sleep(Duration::from_secs(consts::REFRESH_INTERVAL as u64)).await;
                            nc.table.clone().refresh_tree::<RealPinger>().await;
                        })
                        .abort_handle(),
                    )
                } else {
                    None
                }),
                node: n.clone(),
                runtime: rt,
            }
        });

        Ok(new)
    }

    pub fn serve(self: Arc<Self>) -> std::io::Result<()> {
        let rt = self.runtime.handle();
        let nc = self.node.clone();

        {
            let mut lock = self.kad_handle.blocking_lock();
            *lock = Some(self.node.clone().serve()?);
        }

        {
            let mut lock = self.refresh_handle.blocking_lock();
            *lock = Some(
                rt.spawn(async move {
                    sleep(Duration::from_secs(consts::REFRESH_INTERVAL as u64)).await;
                    nc.table.clone().refresh_tree::<RealPinger>().await;
                })
                .abort_handle(),
            );
        }

        Ok(())
    }

    pub fn stop(self: Arc<Self>) {
        if let Ok(r) = Arc::try_unwrap(self) {
            {
                let lock = r.kad_handle.blocking_lock();
                if let Some(x) = lock.as_ref() {
                    x.abort()
                }
            }

            {
                let lock = r.refresh_handle.blocking_lock();
                if let Some(x) = lock.as_ref() {
                    x.abort()
                }
            }
        }
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

    pub fn as_single_peer(self: &Arc<Self>) -> SinglePeer {
        SinglePeer {
            id: self.id(),
            addr: self.node.addr,
        }
    }

    pub fn as_peer(self: &Arc<Self>) -> Peer {
        self.as_single_peer().as_peer()
    }
}

macro_rules! kad_fn {
    // without rpc arguments
    ($func:ident, $op:expr, $return_type:ty, $closure:expr) => {
        #[allow(clippy::redundant_closure_call)] // not too sure
        pub(in crate) fn $func(self: Arc<Self>, peer: Peer) -> Result<$return_type, Box<SinglePeer>> {
            // hacky
            let kad = self.parent.upgrade().unwrap();

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
            let kad = self.parent.upgrade().unwrap();

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
// TODO: iterative store mechanism
impl InnerKad {
    // TODO: implement non-local forwarding of some sort
    pub(crate) fn new(port: u16, ipv6: bool, local: bool, k: Weak<Kad>) -> Arc<InnerKad> {
        let a = (
            match (local, ipv6) {
                (true, true) => IpAddr::V6(Ipv6Addr::LOCALHOST),
                (true, false) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                (false, true) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                (false, false) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
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

            let kn = InnerKad {
                addr: Addr(a.0, a.1),
                table: RoutingTable::new(id, gadget.clone()),
                store: Store::new(gadget.clone()),
                crypto: c,
                parent: k,
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

    pub(crate) fn serve(self: Arc<Self>) -> std::io::Result<tokio::task::AbortHandle> {
        let kad = self.parent.upgrade().unwrap();

        kad.runtime.handle().block_on(KadNetwork::serve(self))
    }

    // key, get_addresses and ping do not update routing table

    kad_fn!(
        key,
        RpcOp::Key,
        SinglePeer,
        |node: Arc<InnerKad>, res: RpcResults, resp: SinglePeer| async move {
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
        |_: Arc<InnerKad>, res: RpcResults, resp: SinglePeer| async move {
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
        |node: Arc<InnerKad>, res: RpcResults, resp: SinglePeer| async move {
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
        |node: Arc<InnerKad>, res: RpcResults, resp: SinglePeer| async move {
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
        |node: Arc<InnerKad>, res: RpcResults, resp: SinglePeer| async move {
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
    fn ping_peer(node: Arc<InnerKad>, peer: Peer) -> Result<SinglePeer, Box<SinglePeer>> {
        tokio::task::block_in_place(|| node.ping(peer))
    }
}

#[derive(Default)]
pub(crate) struct RealPinger {}
impl Pinger for RealPinger {}

#[derive(Default)]
pub(crate) struct ResponsiveMockPinger {}
impl Pinger for ResponsiveMockPinger {
    fn ping_peer(_: Arc<InnerKad>, p: Peer) -> Result<SinglePeer, Box<SinglePeer>> {
        Ok(SinglePeer {
            id: p.id,
            addr: p.addresses.first().unwrap().0,
        })
    }
}

#[derive(Default)]
pub(crate) struct UnresponsiveMockPinger {}
impl Pinger for UnresponsiveMockPinger {
    fn ping_peer(_: Arc<InnerKad>, p: Peer) -> Result<SinglePeer, Box<SinglePeer>> {
        Err(Box::new(SinglePeer {
            id: p.id,
            addr: p.addresses.first().unwrap().0,
        }))
    }
}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use crate::routing::consts;

    use super::*;

    #[traced_test]
    #[test]
    fn refresh() {
        let nodes: Vec<Arc<Kad>> = (0..4).map(|i| Kad::new(18000 + i, false, true)).collect();
        nodes.iter().for_each(|x| x.clone().serve().unwrap());

        // send find_nodes
        // A <-> B
        debug!("A <-> B");
        let _ = nodes[0]
            .node
            .clone()
            .find_node(nodes[1].as_peer(), Hash::from(1));
        // A <-> C
        debug!("A -> C");
        let _ = nodes[0]
            .node
            .clone()
            .find_node(nodes[2].as_peer(), Hash::from(1));
        // C <-> D
        debug!("C -> D");
        let _ = nodes[2]
            .node
            .clone()
            .find_node(nodes[3].as_peer(), Hash::from(1));

        std::thread::sleep(tokio::time::Duration::from_secs(consts::REFRESH_TIME));

        block_on(nodes[1].node.table.clone().refresh_tree::<RealPinger>());

        let bkt = block_on(nodes[1].node.table.clone().find_bucket(Hash::from(1)));

        assert!(
            bkt.iter().all(|x| x.id == nodes[0].node.table.id
                || x.id == nodes[1].node.table.id
                || x.id == nodes[2].node.table.id
                || x.id == nodes[3].node.table.id),
            "checking if bucket contains all nodes"
        );

        nodes.into_iter().for_each(Kad::stop);
    }
}
