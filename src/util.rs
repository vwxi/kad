use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use bigint::uint::U256;
use serde::{Deserialize, Serialize};

pub type Addr = (IpAddr, u16);
pub type Hash = U256;

#[derive(Clone, Debug)]
pub struct Peer {
    pub id: Hash,
    pub addresses: Vec<(Addr, usize)>,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct SinglePeer {
    pub id: Hash,
    pub addr: Addr,
}

pub fn timestamp() -> u64 {
    let t = SystemTime::now();
    t.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpcOp {
    Ping,
    FindNode(Hash),
    FindValue(Hash),
    Store(String, String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcContext {
    pub id: Hash,
    pub op: RpcOp,
    pub addr: Addr,
    pub timestamp: u64,
}

pub type RpcArgs = (RpcContext, String);
