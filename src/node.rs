use bigint::U256;
use futures::executor::block_on;
use rsa::sha2::{Digest, Sha256};
use tarpc::context;
use crate::{crypto::Crypto, routing::{RoutingTable, TableRef}, rpc::{Network, RealNetwork, TIMEOUT}, util::{timestamp, Addr, Hash, Peer, RpcOp, SinglePeer}};
use tokio::{sync::Mutex, time::timeout};
use std::sync::{Arc, Weak};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tokio::task;

pub struct Node {
    pub(crate) addr: Addr,
    pub(crate) crypto: Mutex<Crypto>,
    pub(crate) table: Option<TableRef>,
    pub(crate) network: RealNetwork,
}

pub type NodeRef = Arc<Mutex<Node>>;
pub(crate) type WeakNodeRef = Weak<Mutex<Node>>;

impl Node {
    // TODO: implement non-local forwarding of some sort
    pub fn new(port: u16, ipv6: bool, local: bool) -> Result<NodeRef, Box<dyn Error>> {
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

        let node = Arc::new(Mutex::new(Node {
            addr: a,
            table: None,
            crypto: Mutex::new(c),
            network: RealNetwork::default(),
        }));

        {
            let mut lock = node.blocking_lock();
            lock.table = Some(RoutingTable::new(id, Arc::downgrade(&node)));
        }

        Ok(node)
    }

    pub fn serve(node: NodeRef) -> task::JoinHandle<()> {
        task::spawn(async move {
            let lock = node.lock().await;
            let _ = lock.network.serve(node.clone()).await;
        })
    }

    pub(crate) fn ping(node: NodeRef, peer: Peer) -> Result<SinglePeer, SinglePeer> {
        let lock = node.blocking_lock();

        let nothing = SinglePeer {
            id: U256::from(0),
            addr: (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        
        if peer.addresses.is_empty() {
            return Err(nothing);
        }
        
        let args;
        {
            let table = lock.table.as_ref().unwrap().blocking_lock();
            let crypto = lock.crypto.blocking_lock();
            args = crypto.args(table.id, RpcOp::Ping, lock.addr, timestamp());
        }

        block_on(async {
            match lock.network.connect_peer(peer).await {
                Ok((conn, responding_peer)) => {
                    if timeout(Duration::from_secs(TIMEOUT), conn.ping(context::current(), args)).await.is_ok() {
                        Ok(responding_peer)
                    } else {
                        Err(responding_peer)
                    }
                },
                Err(single_peer) => Err(single_peer)
            }
        })
    }
}

pub(crate) trait Pinger {
    // this function only exists to facilitate easier test mocking
    fn ping_peer(node: NodeRef, peer: Peer) -> Result<SinglePeer, SinglePeer> {
        Node::ping(node, peer)
    }
}

#[derive(Default)]
pub(crate) struct RealPinger {}
impl Pinger for RealPinger {}

#[derive(Default)]
pub(crate) struct ResponsiveMockPinger {}
impl Pinger for ResponsiveMockPinger {
    fn ping_peer(_: NodeRef, p: Peer) -> Result<SinglePeer, SinglePeer> {
        Ok(SinglePeer {
            id: p.id,
            addr: p.addresses.first().unwrap().0
        })
    }
}

#[derive(Default)]
pub(crate) struct UnresponsiveMockPinger {}
impl Pinger for UnresponsiveMockPinger {
    fn ping_peer(_: NodeRef, p: Peer) -> Result<SinglePeer, SinglePeer> {
        Err(SinglePeer {
            id: p.id,
            addr: p.addresses.first().unwrap().0
        })
    }
}