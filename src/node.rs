use rsa::sha2::{Digest, Sha256};

use crate::{crypto::Crypto, routing::{RoutingTable, TableRef}, rpc::RealNetwork, util::{Addr, Hash}};
#[cfg(test)]
use no_deadlocks::Mutex;
#[cfg(not(test))]
use std::sync::Mutex;
use std::sync::{Arc, Weak};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub struct Node {
    pub addr: Addr,
    pub crypto: Mutex<Crypto>,
    pub table: Option<TableRef>,
    pub network: RealNetwork,
}

pub type NodeRef = Arc<Mutex<Node>>;
pub type WeakNodeRef = Weak<Mutex<Node>>;

impl Node {
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
            network: RealNetwork {},
        }));

        {
            let mut lock = node.lock().unwrap();
            lock.table = Some(RoutingTable::new(id, Arc::downgrade(&node)));
        }

        Ok(node)
    }
}
