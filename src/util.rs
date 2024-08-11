use std::{
    net::{IpAddr, Ipv4Addr},
    num::ParseIntError,
    time::{SystemTime, UNIX_EPOCH},
};

use bigint::uint::U256;
use serde::{Deserialize, Serialize};

pub type Addr = (IpAddr, u16);
pub type Hash = U256;

macro_rules! pred_block {
    ($( #[$meta:meta] {$($item:item)*} )*) => {
        $($(
            #[$meta]
            $item
        )*)*
    }
}

pub(crate) use pred_block;

use crate::store::StoreEntry;

// a peer object with multiple addresses
#[derive(Debug, Clone)]
pub struct Peer {
    pub id: Hash,
    pub addresses: Vec<(Addr, usize)>,
}

impl Peer {
    #[must_use]
    pub fn new(id_: Hash, addr: Addr) -> Self {
        Peer {
            id: id_,
            addresses: vec![(addr, 0)],
        }
    }

    #[must_use]
    pub fn single_peer(&self) -> SinglePeer {
        let nothing: Addr = (IpAddr::from(Ipv4Addr::UNSPECIFIED), 0);

        SinglePeer {
            id: self.id,
            addr: if self.addresses.is_empty() {
                nothing
            } else {
                self.addresses.first().unwrap().0
            },
        }
    }
}

// a peer object with a single address
#[derive(Debug, Copy, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct SinglePeer {
    pub id: Hash,
    pub addr: Addr,
}

impl SinglePeer {
    #[must_use]
    pub fn new(id_: Hash, addr_: Addr) -> Self {
        SinglePeer {
            id: id_,
            addr: addr_,
        }
    }

    #[must_use]
    pub fn peer(&self) -> Peer {
        Peer {
            id: self.id,
            addresses: vec![(self.addr, 0)],
        }
    }
}

pub(crate) fn timestamp() -> u64 {
    let t = SystemTime::now();
    t.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub(crate) fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

#[cfg(test)]
pub(crate) fn generate_peer(pid: Option<Hash>) -> SinglePeer {
    SinglePeer {
        id: if let Some(pid_) = pid {
            pid_
        } else {
            let i = (0..32u8).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
            Hash::from(&i[..])
        },
        addr: (IpAddr::V4(Ipv4Addr::LOCALHOST), rand::random()),
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) enum RpcOp {
    Key,
    Ping,
    FindNode(Hash),
    FindValue(Hash),
    Store(StoreEntry),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum RpcResult {
    Bad,
    Key(String),
    Ping,
    Store,
    FindNode(Vec<SinglePeer>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RpcContext {
    pub(crate) id: Hash,
    pub(crate) op: RpcOp,
    pub(crate) addr: Addr,
    pub(crate) timestamp: u64,
}

pub(crate) type RpcArgs = (RpcContext, String);
pub(crate) type RpcResults = (RpcResult, String);
