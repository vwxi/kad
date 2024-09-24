//! Kad network node.
//!
//! Provides a key-value store, a routing table and methods for protocol primitives

use crate::{
    crypto::Crypto,
    forward::Forward,
    routing::{consts as routing_consts, RoutingTable, TableRef},
    rpc::{KadNetwork, Network},
    store::{consts as store_consts, Store, StoreEntry},
    util::{
        hash, timestamp, Addr, Data, FindValueResult, Hash, Kv, Peer, ProviderRecord, RpcContext,
        RpcOp, RpcResult, RpcResults, SinglePeer, Value,
    },
    U256,
};
use anyhow::Result;
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use futures::executor::block_on;
use resolve::resolve_host;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::{Arc, Weak};
use std::{
    fs,
    io::prelude::*,
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
    pub(crate) external_addr: Addr,
    pub(crate) crypto: Crypto,
    pub(crate) store: Store,
    pub(crate) table: TableRef,
    pub(crate) parent: Weak<Kad>,
}

/// ### Node
///
/// Object for holding the internals of a node (kv-store, crypto store, routing table, etc.)
/// along with the thread handles for various events (table refresh, store republishing, etc.)
pub struct Kad {
    pub(crate) node: Arc<InnerKad>,
    pub(crate) runtime: Runtime,
    pub(crate) kad_handle: Mutex<Option<AbortHandle>>,
    pub(crate) refresh_handle: Mutex<Option<AbortHandle>>,
    pub(crate) republish_handle: Mutex<Option<AbortHandle>>,
}

impl Kad {
    /// Create a new Kad object.
    ///
    /// # Arguments
    ///
    /// * `port` - port to bind to (0-65535)
    /// * `ipv6` - bind to ipv6 flag
    /// * `local` - bind to localhost flag
    ///
    /// # Errors
    ///
    /// Will return a `std::thread::Result` if the runtime could not be created or if there was an error initializing the inner object.
    ///
    /// # Results
    ///
    /// Returns Arc to Kad object if successful.
    ///
    /// # Panics
    ///
    /// All panics should be caught and returned as an `Err`
    pub fn new<F: Forward>(port: u16, ipv6: bool, local: bool) -> std::thread::Result<Arc<Self>> {
        std::panic::catch_unwind(|| {
            Arc::new_cyclic(|gadget| {
                let n = InnerKad::new::<F>(port, ipv6, local, gadget.clone());
                let rt = Runtime::new().expect("could not create Kad runtime object");

                Kad {
                    kad_handle: Mutex::new(None),
                    refresh_handle: Mutex::new(None),
                    republish_handle: Mutex::new(None),
                    node: n.clone(),
                    runtime: rt,
                }
            })
        })
    }

    /// Create a new Kad object, importing keys from files.
    ///
    /// # Arguments
    ///
    /// * `port` - port to bind to (0-65535)
    /// * `ipv6` - bind to ipv6 flag
    /// * `local` - bind to localhost flag
    /// * `priv_key` - path to private key file
    /// * `pub_key` - path to private key file
    /// * `table_file` - path to stored routing table state
    ///
    /// # Errors
    ///
    /// Will return a `std::thread::Result` if the runtime could not be created or if there was an error initializing the inner object.
    ///
    /// # Results
    ///
    /// Returns Arc to Kad object if successful.
    ///
    /// # Panics
    ///
    /// All panics should be caught and returned as an `Err`
    pub fn new_from_file<F: Forward>(
        port: u16,
        ipv6: bool,
        local: bool,
        priv_key: &str,
        pub_key: &str,
        table_file: Option<&str>,
    ) -> std::thread::Result<Arc<Self>> {
        std::panic::catch_unwind(|| {
            Arc::new_cyclic(|gadget| {
                let n = InnerKad::new_from_files::<F>(
                    port,
                    ipv6,
                    local,
                    gadget.clone(),
                    priv_key,
                    pub_key,
                    table_file,
                );
                let rt = Runtime::new().expect("could not create Kad runtime object");

                Kad {
                    kad_handle: Mutex::new(None),
                    refresh_handle: Mutex::new(None),
                    republish_handle: Mutex::new(None),
                    node: n.clone(),
                    runtime: rt,
                }
            })
        })
    }

    /// Export keys to file
    ///
    /// # Arguments
    ///
    /// * `priv_key` - path to private key file
    /// * `pub_key` - path to public key file
    /// * `table_file` - path to routing table state file
    ///
    /// # Return value
    ///
    /// Returns true if successful, false otherwise.
    pub fn to_file(
        self: &Arc<Self>,
        priv_key: &str,
        pub_key: &str,
        table_file: Option<&str>,
    ) -> bool {
        self.node.crypto.to_file(priv_key, pub_key).is_ok()
            && if let Some(tf) = table_file {
                let buckets = self
                    .runtime
                    .handle()
                    .block_on(self.node.table.clone().get_all_buckets());
                if let Ok(c) = serde_json::to_string(&buckets) {
                    fs::write(tf, c).is_ok()
                } else {
                    false
                }
            } else {
                false
            }
    }

    #[cfg(test)]
    pub(crate) fn mock(
        port: u16,
        id: Option<Hash>,
        main: bool,
        refresh: bool,
        republish: bool,
    ) -> Result<Arc<Self>> {
        let rt = Runtime::new().expect("could not create Kad runtime object");

        let new = Arc::new_cyclic(|kad_gadget| {
            let n = Arc::new_cyclic(|innerkad_gadget| {
                let c = Crypto::new(innerkad_gadget.clone()).expect("could not initialize crypto");
                let hkey = hash(c.public_key_as_string().unwrap().as_str());

                let a = Addr(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
                let kn = InnerKad {
                    addr: a,
                    external_addr: a,
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

    /// Start threads to receive messages.
    ///
    /// # Errors
    ///
    /// May return an `Err` if the serving thread was not successfully created.
    pub fn serve(self: Arc<Self>) -> Result<()> {
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

    /// Stop any running threads and consumes Kad object
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

    /// Ping a peer.
    ///
    /// # Arguments
    ///
    /// * `peer` - pinged peer
    ///
    /// # Errors
    ///
    /// Returns the unresponsive peer if unsuccessful.
    ///
    /// # Return value
    ///
    /// Returns the responding peer if successful.
    pub fn ping(self: Arc<Self>, peer: Peer) -> Result<SinglePeer, Box<SinglePeer>> {
        self.node.clone().ping(peer)
    }

    /// Returns the resolved address of a Kad object
    pub fn addr(self: &Arc<Self>) -> Addr {
        self.node.external_addr
    }

    /// Returns the node ID associated with a Kad object
    pub fn id(self: &Arc<Self>) -> Hash {
        self.node.table.id
    }

    /// Returns the node ID and resolved address in a `SinglePeer` object
    pub fn as_single_peer(self: &Arc<Self>) -> SinglePeer {
        SinglePeer {
            id: self.id(),
            addr: self.node.addr,
        }
    }

    /// Returns the node ID and resolved addresses in a `Peer` object
    pub fn as_peer(self: &Arc<Self>) -> Peer {
        self.as_single_peer().peer()
    }

    /// Put a key-value pair on the network.
    ///
    /// # Example
    ///
    /// ```
    /// use kad::{node::Kad, util::Kvs};
    ///
    /// let node = Kad::new(16161, false, true).unwrap();
    /// node.clone().serve().unwrap();
    ///
    /// // join etc...
    ///
    /// assert!(!node.put("hello", String::from("good morning"), false).unwrap().is_empty());
    ///
    /// node.stop();
    /// ```
    ///  
    /// # Arguments
    ///
    /// * `key` - Key to store
    /// * `value` - Value to store
    /// * `compress` - Apply compression flag
    ///
    /// # Errors
    ///
    /// Returns an error if any of the sends fail.
    pub fn put<T: Serialize + DeserializeOwned>(
        self: &Arc<Self>,
        key: &str,
        value: &T,
        compress: bool,
    ) -> Result<Vec<SinglePeer>> {
        // compress and serialize
        match serde_json::to_string(&value) {
            Ok(v) => Ok(self
                .runtime
                .handle()
                .block_on(self.node.clone().iter_store_new(
                    hash(key),
                    Value::Data(if compress {
                        let mut e = ZlibEncoder::new(Vec::new(), Compression::best());
                        let _ = e.write_all(v.as_bytes());

                        Data::Compressed(e.finish()?)
                    } else {
                        Data::Raw(v.into())
                    }),
                ))),
            Err(e) => Err(e.into()),
        }
    }

    /// Put a provider record on the network
    ///
    /// # Example
    ///
    /// ```
    /// use kad::{node::Kad, util::Kvs};
    ///
    /// let node = Kad::new(16161, false, true).unwrap();
    /// node.clone().serve().unwrap();
    ///
    /// // join etc...
    ///
    /// node.provide("thing").unwrap();
    ///
    /// node.stop();
    /// ```
    ///
    /// # Arguments
    ///
    /// * `key` - key to provide
    ///
    /// # Behavior
    ///
    /// Provider records will remain valid on the network for `REPUBLISH_TIME` seconds.  
    ///
    /// # Return value
    ///
    /// Returns a list of all peers contacted that did not store the value if successful.
    ///
    /// # Errors
    ///
    /// Returns any errors during the process.
    pub fn provide(self: &Arc<Self>, key: &str) -> Result<Vec<SinglePeer>> {
        let record = self
            .node
            .store
            .create_new_entry(&Value::ProviderRecord(ProviderRecord {
                provider: self.id(),
                expiry: timestamp() + store_consts::REPUBLISH_TIME,
            }));

        self.put(key, &record, false)
    }

    fn lookup(self: &Arc<Self>, key: Hash, disjoint: bool) -> Vec<FindValueResult> {
        let rt = self.runtime.handle();

        if disjoint {
            rt.block_on(self.node.clone().disjoint_lookup_value(
                key,
                consts::DISJOINT_PATHS,
                consts::QUORUM,
            ))
        } else {
            let peers = rt.block_on(self.node.table.clone().find_alpha_peers(key));

            vec![rt.block_on(
                self.node
                    .clone()
                    .lookup_value(peers, None, key, consts::QUORUM),
            )]
        }
    }

    /// Get values from the network.
    ///
    /// # Example
    ///
    /// ```
    /// use kad::{node::Kad, util::Kvs};
    ///
    /// let node = Kad::new(16161, false, true).unwrap();
    /// node.clone().serve().unwrap();
    ///
    /// // join etc...
    ///
    /// let values: Kvs<String> = node.get("hello", false);
    ///
    /// node.stop();
    /// ```
    ///
    /// # Arguments
    ///
    /// * `key` - search key
    /// * `disjoint` - use disjoint lookups
    ///
    /// # Behavior
    ///
    /// If `disjoint` is set to true, a disjoint lookup will take place. It is preferable to use disjoint lookups to prevent value poisoning.  
    /// ***NOTE:*** If the routing table contains less than `DISJOINT_PATHS` nodes during a disjoint lookup, then no values will return.
    ///
    /// All values of a different type than `T` will be rejected.  
    ///
    /// # Return value
    ///
    /// Returns a list of retrieved valid values.
    pub fn get<T: Serialize + DeserializeOwned>(
        self: &Arc<Self>,
        key: &str,
        disjoint: bool,
    ) -> Vec<Kv<T>> {
        self.get_hash(hash(key), disjoint)
    }

    /// Get values from the network.
    ///
    /// # Example
    ///
    /// ```
    /// use kad::{node::Kad, util::{Kvs, Hash}};
    ///
    /// let node = Kad::new(16161, false, true).unwrap();
    /// node.clone().serve().unwrap();
    ///
    /// // join etc...
    ///
    /// let values: Kvs<String> = node.get_hash(Hash::from(111), false);
    ///
    /// node.stop();
    /// ```
    ///
    /// # Arguments
    ///
    /// * `key` - search key
    /// * `disjoint` - use disjoint lookups
    ///
    /// # Behavior
    ///
    /// If `disjoint` is set to true, a disjoint lookup will take place. It is preferable to use disjoint lookups to prevent value poisoning.  
    /// ***NOTE:*** If the routing table contains less than `DISJOINT_PATHS` nodes during a disjoint lookup, then no values will return.
    ///
    /// All values of a different type than `T` will be rejected.  
    ///
    /// # Return value
    ///
    /// Returns a list of retrieved valid values.
    pub fn get_hash<T: Serialize + DeserializeOwned>(
        self: &Arc<Self>,
        key: Hash,
        disjoint: bool,
    ) -> Vec<Kv<T>> {
        let results = self.lookup(key, disjoint);

        results
            .iter()
            .filter_map(|r| match r {
                FindValueResult::Value(val) => {
                    let entry = (**val).0.clone();
                    match entry.value {
                        // decompress and deserialize
                        Value::Data(Data::Compressed(c)) => {
                            let mut d = ZlibDecoder::new(&c[..]);
                            let mut s = String::new();

                            if d.read_to_string(&mut s).is_err() {
                                None
                            } else if let Ok(v) = serde_json::from_str(s.as_str()) {
                                Some(Kv {
                                    value: v,
                                    origin: entry.origin,
                                    timestamp: entry.timestamp,
                                })
                            } else {
                                debug!("unknown value type from lookup");
                                None
                            }
                        }
                        Value::Data(Data::Raw(r)) => {
                            if let Ok(v) = serde_json::from_slice(r.as_slice()) {
                                Some(Kv {
                                    value: v,
                                    origin: entry.origin,
                                    timestamp: entry.timestamp,
                                })
                            } else {
                                None
                            }
                        }
                        Value::ProviderRecord(_) => None,
                    }
                }
                _ => None,
            })
            .collect()
    }

    /// Get nodes nearest to a given ID
    ///
    /// # Example
    ///
    /// ```
    /// use kad::{node::Kad, util::Hash};
    ///
    /// let node = Kad::new(16161, false, true).unwrap();
    /// node.clone().serve().unwrap();
    ///
    /// // join etc...
    ///
    /// let nodes = node.get_nodes(Hash::from(0));
    ///
    /// node.stop();
    /// ```
    pub fn get_nodes(self: &Arc<Self>, key: Hash) -> Vec<Peer> {
        self.runtime
            .handle()
            .block_on(self.node.clone().iter_find_node(key))
    }

    /// Get providers for a key on the network.
    ///
    /// # Example
    ///
    /// ```
    /// use kad::{node::Kad, util::Kvs};
    ///
    /// let node = Kad::new(16161, false, true).unwrap();
    /// node.clone().serve().unwrap();
    ///
    /// // join etc...
    ///
    /// let values: Vec<ProviderRecord> = node.get_providers("hello", false);
    ///
    /// node.stop();
    /// ```
    ///
    /// # Arguments
    ///
    /// * `key` - provider key string
    /// * `disjoint` - disjoint lookup flag
    ///
    /// # Behavior
    ///
    /// If `disjoint` is set to true, a disjoint lookup will take place. It is preferable to use disjoint lookups to prevent value poisoning.
    ///
    /// # Return value
    ///
    /// Returns a list of all peers contacted that did not store the value if successful.
    pub fn get_providers(self: &Arc<Self>, key: &str, disjoint: bool) -> Vec<ProviderRecord> {
        let results = self.lookup(hash(key), disjoint);

        results
            .into_iter()
            .filter_map(|x| match x {
                FindValueResult::Value(val) => {
                    let entry = val.0.clone();
                    match entry.value {
                        Value::ProviderRecord(pr) => Some(pr),
                        _ => None,
                    }
                }
                _ => None,
            })
            .collect()
    }

    /// Join the network from an address.
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to join from
    ///
    /// # Example
    ///
    /// ```
    /// use kad::{node::Kad, util::Kvs};
    ///
    /// let node = Kad::new(16161, false, true).unwrap();
    /// node.clone().serve().unwrap();
    ///
    /// assert!(node.join("127.0.0.1", 16162));
    ///
    /// node.stop();
    /// ```
    ///
    /// # Return value
    ///
    /// Returns true if the join procedure was successful.
    pub fn join(self: &Arc<Self>, ip: &str, port: u16) -> bool {
        if let Ok(ips) = resolve_host(ip) {
            if let Some(ip) = ips.peekable().peek() {
                let addr = Addr(*ip, port);
                self.runtime.handle().block_on(self.node.clone().join(addr))
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Resolve an ID into a peer
    ///
    /// # Arguments
    ///
    /// * `id` - ID to resolve
    ///
    /// # Return value
    ///
    /// If peer doesn't exist in routing table, returns a list of all addresses that respond with a valid key and ID.  
    /// Otherwise, returns addresses from routing table.
    pub fn resolve(self: &Arc<Self>, id: Hash) -> Vec<Addr> {
        let rt = self.runtime.handle();

        if let Some(n) = rt.block_on(self.node.table.clone().find(id)) {
            return n.addresses.iter().map(|x| x.0).collect();
        }

        let addresses = rt.block_on(self.node.clone().resolve(id));

        // remove all addresses whose keys don't resolve to desired ID
        addresses
            .iter()
            .filter_map(|a| Some(self.node.clone().key(Peer::new(Hash::zero(), *a)).ok())?)
            .map(|x| x.addr)
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
                    Ok((conn, mut responding_peer)) => {
                        if self.crypto.if_unknown(&responding_peer.id.clone(), || async {
                            if let Ok((RpcResult::Key(key), ctx, _)) = conn.client.key(context::current()).await {
                                responding_peer.id = ctx.id;
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

impl InnerKad {
    pub(crate) fn new<F: Forward>(
        port: u16,
        ipv6: bool,
        local: bool,
        k: Weak<Kad>,
    ) -> Arc<InnerKad> {
        let a = (
            match (local, ipv6) {
                (true, true) => IpAddr::V6(Ipv6Addr::LOCALHOST),
                (true, false) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                (false, true) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                (false, false) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            },
            port,
        );

        if !local {
            F::forward(ipv6, port, "kad").expect("could not forward port");
        }

        Arc::new_cyclic(|gadget| {
            let c = Crypto::new(gadget.clone()).expect("could not initialize crypto");
            let id = hash(
                c.public_key_as_string()
                    .expect("could not acquire public key for ID hash")
                    .as_str(),
            );

            let a = Addr(a.0, a.1);
            let kn = InnerKad {
                addr: a,
                external_addr: if local {
                    a
                } else {
                    Addr(
                        F::external_ip().expect("could not acquire external IP address"),
                        a.1,
                    )
                },
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

    pub(crate) fn new_from_files<F: Forward>(
        port: u16,
        ipv6: bool,
        local: bool,
        k: Weak<Kad>,
        priv_key: &str,
        pub_key: &str,
        table_file: Option<&str>,
    ) -> Arc<InnerKad> {
        let a = (
            match (local, ipv6) {
                (true, true) => IpAddr::V6(Ipv6Addr::LOCALHOST),
                (true, false) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                (false, true) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                (false, false) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            },
            port,
        );

        if !local {
            F::forward(ipv6, port, "kad").expect("could not forward port");
        }

        Arc::new_cyclic(|gadget| {
            let c = Crypto::from_file(gadget.clone(), priv_key, pub_key)
                .expect("could not initialize crypto");
            let id = hash(
                c.public_key_as_string()
                    .expect("could not acquire public key for ID hash")
                    .as_str(),
            );

            let a = Addr(a.0, a.1);
            let kn = InnerKad {
                addr: a,
                external_addr: if local {
                    a
                } else {
                    Addr(
                        F::external_ip().expect("could not acquire external IP address"),
                        a.1,
                    )
                },
                table: RoutingTable::new(id, gadget.clone()),
                store: Store::new(gadget.clone()),
                crypto: c,
                parent: k,
            };

            if let Some(tbl_file) = table_file {
                block_on(
                    kn.table.clone().make_from_buckets(
                        serde_json::from_str(
                            &fs::read_to_string(tbl_file)
                                .expect("routing table file could not be read"),
                        )
                        .expect("invalid routing table file format"),
                    ),
                );
            }

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

    pub(crate) fn serve(self: Arc<Self>) -> Result<tokio::task::AbortHandle> {
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
        |node: Arc<InnerKad>, res: RpcResults, mut resp: SinglePeer| async move {
            // check if hash(key) == id then add to keystore
            if let RpcResult::Key(result) = res.0 {
                resp.id = res.1.id;
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
        |_: Arc<InnerKad>, res: RpcResults, mut resp: SinglePeer| async move {
            if let RpcResult::GetAddresses(Some(addrs)) = res.0 {
                resp.id = res.1.id;
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
        |_, res: RpcResults, mut resp: SinglePeer| async move {
            if let RpcResult::Ping = res.0 {
                resp.id = res.1.id;
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
                if node.crypto.verify_results(&res).await {
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
                if node.crypto.verify_results(&res).await {
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
                if node.crypto.verify_results(&res).await {
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
            if let Ok((addrs, _)) =
                tokio::task::block_in_place(|| self.clone().get_addresses(peer, key))
            {
                addresses.extend(addrs.iter());
            }
        }

        addresses.dedup();

        addresses
    }

    pub(crate) async fn join(self: Arc<Self>, addr: Addr) -> bool {
        if let Ok(peer) =
            tokio::task::block_in_place(|| self.clone().ping(Peer::new(Hash::zero(), addr)))
        {
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

            return true;
        }

        false
    }

    pub(crate) fn create_ctx(self: &Arc<Self>) -> RpcContext {
        RpcContext {
            id: self.table.id,
            op: RpcOp::Nothing,
            addr: self.external_addr,
            timestamp: timestamp(),
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
                .iter_store_new(hash("good morning"), Value::Data(Data::Raw("hello".into())))
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
            .create_new_entry(&Value::Data(Data::Raw("hello".into())));
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
