use crate::{
    crypto::Crypto,
    routing::{consts as routing_consts, RoutingTable, TableRef},
    rpc::{KadNetwork, Network},
    store::{consts as store_consts, Entry, ProviderRecord, Store, StoreEntry, Value},
    util::{
        hash, timestamp, Addr, FindValueResult, Hash, Peer, RpcOp, RpcResult, RpcResults,
        SinglePeer,
    },
    U256,
};
use futures::executor::block_on;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::{Arc, Weak};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tarpc::context;
use tokio::{runtime::Runtime, sync::Mutex, task::AbortHandle, time::sleep};
use tracing::debug;

pub(crate) mod consts {
    pub(crate) const DISJOINT_PATHS: usize = 3;
    pub(crate) const QUORUM: usize = 3;
}

// all of the different facets of the protocol
pub(crate) struct InnerKad {
    pub(crate) addr: Addr,
    pub(crate) crypto: Crypto,
    pub(crate) store: Store,
    pub(crate) table: TableRef,
    pub(crate) parent: Weak<Kad>,
}

// holds the inner node and its thread handles
pub struct Kad {
    pub(crate) node: Arc<InnerKad>,
    pub(crate) runtime: Runtime,
    pub(crate) kad_handle: Mutex<Option<AbortHandle>>,
    pub(crate) refresh_handle: Mutex<Option<AbortHandle>>,
    pub(crate) republish_handle: Mutex<Option<AbortHandle>>,
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
                republish_handle: Mutex::new(None),
                node: n.clone(),
                runtime: rt,
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn mock(
        port: u16,
        id: Option<Hash>,
        main: bool,
        refresh: bool,
        republish: bool,
    ) -> Result<Arc<Self>, Box<dyn Error>> {
        let rt = Runtime::new().expect("could not create Kad runtime object");

        let new = Arc::new_cyclic(|kad_gadget| {
            let n = Arc::new_cyclic(|innerkad_gadget| {
                let c = Crypto::new(innerkad_gadget.clone()).expect("could not initialize crypto");
                let hkey = hash(c.public_key_as_string().unwrap().as_str());

                let kn = InnerKad {
                    addr: Addr(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                    table: RoutingTable::new(
                        if let Some(i) = id { i } else { hkey },
                        innerkad_gadget.clone(),
                    ),
                    store: Store::new(innerkad_gadget.clone()),
                    crypto: c,
                    parent: kad_gadget.clone(),
                };

                // add own key
                block_on(
                    kn.crypto.entry(
                        kn.table.id,
                        kn.crypto
                            .public_key_as_string()
                            .expect("could not acquire public key for keyring")
                            .as_str(),
                    ),
                );

                kn
            });

            Kad {
                kad_handle: Mutex::new(None),
                refresh_handle: Mutex::new(None),
                republish_handle: Mutex::new(None),
                node: n.clone(),
                runtime: rt,
            }
        });

        if main {
            let mut lock = new.kad_handle.blocking_lock();
            *lock = Some(new.node.clone().serve()?);
        }

        if refresh {
            let mut lock = new.refresh_handle.blocking_lock();
            let sc = new.clone();
            *lock = Some(
                new.runtime
                    .handle()
                    .spawn(async move {
                        loop {
                            sc.node.clone().refresh_buckets().await;
                        }
                    })
                    .abort_handle(),
            );
        }

        if republish {
            let mut lock = new.republish_handle.blocking_lock();
            let sc = new.clone();
            *lock = Some(
                new.runtime
                    .handle()
                    .spawn(async move {
                        loop {
                            sc.node.clone().republish_entries().await;
                        }
                    })
                    .abort_handle(),
            );
        }

        Ok(new)
    }

    pub fn serve(self: Arc<Self>) -> std::io::Result<()> {
        let rt = self.runtime.handle();

        {
            let mut lock = self.kad_handle.blocking_lock();
            *lock = Some(self.node.clone().serve()?);
        }

        {
            let mut lock = self.refresh_handle.blocking_lock();
            let sc = self.clone();
            *lock = Some(
                rt.spawn(async move {
                    loop {
                        sc.node.clone().refresh_buckets().await;
                    }
                })
                .abort_handle(),
            );
        }

        {
            let mut lock = self.republish_handle.blocking_lock();
            let sc = self.clone();
            *lock = Some(
                rt.spawn(async move {
                    loop {
                        sc.node.clone().republish_entries().await;
                    }
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
                    x.abort();
                }
            }

            {
                let lock = r.refresh_handle.blocking_lock();
                if let Some(x) = lock.as_ref() {
                    x.abort();
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

    pub fn put<'a, T: Serialize + Deserialize<'a>>(
        self: &Arc<Self>,
        key: &str,
        value: T,
    ) -> Result<Vec<SinglePeer>, Box<dyn Error>> {
        match serde_json::to_string(&value) {
            Ok(v) => Ok(self
                .runtime
                .handle()
                .block_on(self.node.clone().iter_store_new(hash(key), Value::Data(v)))),
            Err(e) => Err(Box::new(e)),
        }
    }

    pub fn provide(self: &Arc<Self>, key: &str) -> Result<Vec<SinglePeer>, Box<dyn Error>> {
        let record = self
            .node
            .store
            .create_new_entry(&Value::ProviderRecord(ProviderRecord {
                provider: self.id(),
                expiry: timestamp() + store_consts::REPUBLISH_TIME,
            }));

        self.put(key, record)
    }

    pub fn get(self: &Arc<Self>, key: &str, disjoint: bool) -> Vec<Entry> {
        let h = hash(key);
        let rt = self.runtime.handle();

        let results: Vec<FindValueResult> = if disjoint {
            rt.block_on(self.node.clone().disjoint_lookup_value(
                h,
                consts::DISJOINT_PATHS,
                consts::QUORUM,
            ))
        } else {
            let peers = rt.block_on(self.node.table.clone().find_alpha_peers(h));

            vec![rt.block_on(
                self.node
                    .clone()
                    .lookup_value(peers, None, h, consts::QUORUM),
            )]
        };

        results
            .iter()
            .filter_map(|r| match r {
                FindValueResult::Value(val) => Some((**val).0.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn get_providers(self: &Arc<Self>, key: &str, disjoint: bool) -> Vec<ProviderRecord> {
        let result = self.get(key, disjoint);

        result
            .iter()
            .filter_map(|r| match &r.value {
                Value::ProviderRecord(record) => Some(record.clone()),
                _ => None,
            })
            .collect()
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
// TODO: resolve mechanism
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
        let parent = self.parent.upgrade().unwrap();

        parent.runtime.handle().block_on(KadNetwork::serve(self))
    }

    pub(crate) async fn refresh_buckets(self: Arc<Self>) {
        sleep(Duration::from_secs(routing_consts::REFRESH_INTERVAL as u64)).await;
        self.table.clone().refresh_tree::<RealPinger>().await;
    }

    pub(crate) async fn republish_entries(self: Arc<Self>) {
        sleep(Duration::from_secs(store_consts::REPUBLISH_INTERVAL as u64)).await;

        let ts = timestamp();

        let parent = self.parent.upgrade().unwrap();

        for e in self
            .store
            .for_all(|key: Hash, entry: StoreEntry| {
                let sc = self.clone();

                async move {
                    if ts - entry.0.timestamp > store_consts::REPUBLISH_TIME {
                        Some(sc.republish(key, entry.clone()).await)
                    } else {
                        None
                    }
                }
            })
            .await
        {
            self.store.put(parent.as_single_peer(), e.0, e.1).await;
        }
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

    // returns a list with all nodes that have not responded
    async fn iter_store(self: Arc<Self>, key: Hash, entry: StoreEntry) -> Vec<SinglePeer> {
        let mut bad_peers: Vec<SinglePeer> = vec![];

        for peer in self.clone().iter_find_node(key).await {
            debug!("storing at {:#x}", peer.id);
            tokio::task::block_in_place(|| {
                if let Err(bad) = self.clone().store(peer, key, entry.clone()) {
                    bad_peers.push(*bad);
                }
            });
        }

        bad_peers
    }

    async fn iter_store_new(self: Arc<Self>, key: Hash, value: Value) -> Vec<SinglePeer> {
        let entry = self.clone().store.create_new_entry(&value);
        let parent = self.parent.upgrade().unwrap();

        // store in own store first
        self.store
            .put(parent.as_single_peer(), key, entry.clone())
            .await;

        self.iter_store(key, entry).await
    }

    async fn republish(self: Arc<Self>, key: Hash, entry: StoreEntry) -> (Hash, StoreEntry) {
        let new_entry = self.store.republish_entry(entry);

        self.iter_store(key, new_entry.clone()).await;

        (key, new_entry)
    }

    pub(crate) async fn resolve(self: Arc<Self>, key: Hash) -> Vec<Addr> {
        let mut addresses: Vec<Addr> = vec![];

        for peer in self.clone().iter_find_node(key).await {
            if let Ok((addrs, _)) = self.clone().get_addresses(peer, key) {
                addresses.extend(addrs.iter());
            }
        }

        addresses.dedup();

        addresses
    }

    pub(crate) async fn join(self: Arc<Self>, addr: Addr) -> Result<(), ()> {
        if let Ok(peer) = self.clone().ping(Peer::new(Hash::zero(), addr)) {
            self.table.clone().update::<RealPinger>(peer).await;

            let res = self.clone().iter_find_node(self.clone().table.id).await;

            // initially populate routing table
            for p in res {
                for a in p.addresses {
                    self.table
                        .clone()
                        .update::<RealPinger>(SinglePeer::new(p.id, a.0))
                        .await;
                }
            }

            // perform refreshing
            self.table.clone().refresh_tree::<RealPinger>().await;

            Ok(())
        } else {
            Err(())
        }
    }
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
    use std::str::FromStr;

    use tracing_test::traced_test;

    use super::*;

    fn setup(offset: u16) -> Vec<Arc<Kad>> {
        let nodes: Vec<Arc<Kad>> = (0..4)
            .map(|i| Kad::mock(offset + i, None, true, false, false).unwrap())
            .collect();

        // send find_nodes
        // A <-> B
        debug!("A <-> B");
        let _ = nodes[0]
            .node
            .clone()
            .find_node(nodes[1].as_peer(), Hash::from(1));
        // A <-> C
        debug!("A <-> C");
        let _ = nodes[0]
            .node
            .clone()
            .find_node(nodes[2].as_peer(), Hash::from(1));
        // C <-> D
        debug!("C <-> D");
        let _ = nodes[2]
            .node
            .clone()
            .find_node(nodes[3].as_peer(), Hash::from(1));

        nodes
    }

    #[traced_test]
    #[test]
    fn refresh() {
        let nodes = setup(18000);

        nodes[1]
            .runtime
            .handle()
            .block_on(nodes[1].node.clone().refresh_buckets());

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

    #[traced_test]
    #[test]
    fn iter_store() {
        let nodes = setup(18010);

        assert!(block_on(
            nodes[0]
                .node
                .clone()
                .iter_store_new(hash("good morning"), Value::Data(String::from("hello"))),
        )
        .is_empty()); // none of them should fail

        // check if every node got the value
        assert!(nodes
            .iter()
            .all(|n| { block_on(n.node.store.get(&hash("good morning"))).is_some() }));

        nodes.into_iter().for_each(Kad::stop);
    }

    #[traced_test]
    #[test]
    fn republish() {
        let nodes = setup(18020);

        let entry = nodes[0]
            .node
            .store
            .create_new_entry(&Value::Data(String::from("hello")));
        assert!(block_on(nodes[0].clone().node.store.put(
            nodes[0].as_single_peer(),
            hash("good morning"),
            entry.clone()
        )));

        assert!(nodes[0]
            .node
            .clone()
            .store(nodes[1].as_peer(), hash("good morning"), entry.clone())
            .is_ok());

        // republishing should happen
        std::thread::sleep(Duration::from_secs(1));
        nodes[0]
            .runtime
            .handle()
            .block_on(nodes[0].node.clone().republish_entries());

        // get from republishee
        let new = block_on(nodes[2].node.store.get(&hash("good morning"))).unwrap();

        // check if updated
        assert!(new.0.timestamp > entry.0.timestamp);

        // check if everyone got the new value
        nodes.iter().for_each(|n| {
            debug!("checking node {:#x}", n.id());
            assert_eq!(
                block_on(n.node.store.get(&hash("good morning"))).unwrap(),
                new
            );
        });

        nodes.into_iter().for_each(Kad::stop);
    }

    #[traced_test]
    #[test]
    fn resolve() {
        let nodes = setup(18030);

        for i in 0..(routing_consts::ADDRESS_LIMIT as u16 - 1) {
            block_on(
                nodes[1]
                    .node
                    .table
                    .clone()
                    .update::<ResponsiveMockPinger>(SinglePeer::new(
                        nodes[0].id(),
                        Addr(
                            IpAddr::V4(Ipv4Addr::from_str("127.0.0.1").unwrap()),
                            6969 + i,
                        ),
                    )),
            );
        }

        let res = block_on(nodes[2].node.clone().resolve(nodes[0].id()));

        assert_eq!(res.len(), routing_consts::ADDRESS_LIMIT);

        nodes.into_iter().for_each(Kad::stop);
    }
}
