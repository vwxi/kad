use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use bigint::uint::U256;
use serde::{Deserialize, Serialize};

pub(crate) type Addr = (IpAddr, u16);
pub(crate) type Hash = U256;

#[derive(Clone, Debug)]
pub(crate) struct Peer {
    pub(crate) id: Hash,
    pub(crate) addresses: Vec<(Addr, usize)>,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub(crate) struct SinglePeer {
    pub(crate) id: Hash,
    pub(crate) addr: Addr,
}

pub(crate) fn timestamp() -> u64 {
    let t = SystemTime::now();
    t.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum RpcOp {
    Ping,
    FindNode(Hash),
    FindValue(Hash),
    Store(String, String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RpcContext {
    pub(crate) id: Hash,
    pub(crate) op: RpcOp,
    pub(crate) addr: Addr,
    pub(crate) timestamp: u64,
}

pub(crate) type RpcArgs = (RpcContext, String);
