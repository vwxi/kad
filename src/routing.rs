use crate::{node::{Node, NodeRef, WeakNodeRef, Pinger}, rpc::Network, util::{timestamp, Hash, Peer, RpcOp, SinglePeer}};
use tokio::sync::Mutex;
use std::sync::Arc;
use tracing::debug;

const KEY_SIZE: usize = 64;
const BUCKET_SIZE: usize = 3;
const ADDRESS_LIMIT: usize = 5;
const MISSED_PINGS_ALLOWED: usize = 3;
const MISSED_MESSAGES_ALLOWED: usize = 3;
const CACHE_SIZE: usize = 3;
const ALPHA: usize = 3;

pub(crate) struct Bucket {
    pub(crate) last_seen: u64,
    pub(crate) peers: Vec<Peer>,
    pub(crate) cache: Vec<Peer>,
}

pub(crate) struct Trie {
    pub(crate) prefix: Hash,
    pub(crate) cutoff: usize,
    pub(crate) bucket: Option<Bucket>,
    pub(crate) left: TrieRef,
    pub(crate) right: TrieRef,
}

pub(crate) struct RoutingTable {
    pub(crate) id: Hash,
    root: TrieRef,
    node: WeakNodeRef,
}

pub(crate) type InnerTrieRef = Arc<Mutex<Trie>>;
pub(crate) type TrieRef = Option<InnerTrieRef>;
pub(crate) type TableRef = Arc<Mutex<RoutingTable>>;

impl Bucket {
    fn new() -> Self {
        Bucket {
            last_seen: timestamp(),
            peers: Vec::new(),
            cache: Vec::new(),
        }
    }

    pub(crate) fn add_peer(&mut self, peer: Peer) {
        debug!("added peer {:#x}", peer.id);

        self.peers.push(peer);
        self.last_seen = timestamp();
    }

    pub(crate) fn update_cached_peer(&mut self, peer: Peer) {
        // exists in cache?
        if let Some(idx) = self.cache.iter().position(|x| x.id == peer.id) {
            // move to end
            let t = self.cache.remove(idx);
            self.cache.push(t);
        } else {
            // if cache is full, kick out oldest node
            if self.cache.len() > CACHE_SIZE {
                debug!("cache full, removing oldest candidate");
                self.cache.remove(0);
            }

            // add new node anyways
            debug!("adding new node to cache {:#x}", peer.id);
            self.cache.push(peer);
        }

        self.last_seen = timestamp();
    }

    fn update_nearby(&mut self, peer: Peer) {
        // exists in bucket?
        if let Some(idx) = self.peers.iter().position(|x| x.id == peer.id) {
            // move to bucket tail
            let t = self.peers.remove(idx);
            self.peers.push(t);

            let entry = self.peers.iter_mut().last().unwrap();

            // check if address is new and if address count is under limit
            let paddr = peer.addresses.first().unwrap();
            if !entry.addresses.iter().any(|x| x == paddr) && entry.addresses.len() < ADDRESS_LIMIT
            {
                // add to address list
                debug!("new address {:?} for node {:#x}", paddr, entry.id);
                entry.addresses.push(*paddr);
            }

            // sort by liveness
            entry.addresses.sort_by(|x, y| x.1.cmp(&y.1));
        } else if self.peers.len() < BUCKET_SIZE {
            // does not exist in bucket, add
            self.peers.push(peer);
        }

        self.last_seen = timestamp();
    }
}

impl Trie {
    // create a new trie node
    pub(crate) fn new(pre: Hash, cut: usize, leaf: bool) -> InnerTrieRef {
        Arc::new(Mutex::new(Trie {
            prefix: pre,
            cutoff: cut,
            bucket: if leaf { Some(Bucket::new()) } else { None },
            left: None,
            right: None,
        }))
    }

    fn split(&mut self) {
        if let Some(bkt) = &self.bucket {
            self.left = Some(Trie::new(self.prefix, self.cutoff + 1, true));

            let new_bit = Hash::from(1usize) << (KEY_SIZE - (self.cutoff + 1));

            self.right = Some(Trie::new(self.prefix | new_bit, self.cutoff + 1, true));

            let mut l_lock = self.left.as_ref().unwrap().blocking_lock();
            let l_bkt = l_lock.bucket.as_mut().unwrap();
            let mut r_lock = self.right.as_ref().unwrap().blocking_lock();
            let r_bkt = r_lock.bucket.as_mut().unwrap();

            // split based on new cutoff bit
            for peer in &bkt.peers {
                if (peer.id & new_bit) == Hash::zero() {
                    l_bkt.peers.push(peer.clone());
                } else {
                    r_bkt.peers.push(peer.clone());
                };
            }

            // truncate
            l_bkt.peers.truncate(BUCKET_SIZE);
            r_bkt.peers.truncate(BUCKET_SIZE);

            self.bucket = None;
        }
    }
}

impl RoutingTable {
    pub(crate) fn new(i: Hash, n: WeakNodeRef) -> TableRef {
        let rt = Arc::new(Mutex::new(RoutingTable {
            id: i,
            root: None,
            node: n,
        }));

        {
            let mut rt_ref = rt.blocking_lock();
            rt_ref.root = Some(Trie::new(Hash::zero(), 0, true));
        }

        rt
    }

    fn traverse(node: TrieRef, key: Hash, cutoff: usize) -> TrieRef {
        let current = node.as_ref().unwrap().blocking_lock();

        if let (None, None, Some(_)) = (&current.left, &current.right, &current.bucket) {
            drop(current);
            return node;
        }

        let next = if key & (Hash::from(1usize) << (KEY_SIZE - cutoff - 1)) == Hash::zero() {
            Some(current.left.as_ref().unwrap().clone())
        } else {
            Some(current.right.as_ref().unwrap().clone())
        };

        drop(current);
        if let Some(ref next_binding) = next {
            Self::traverse(Some(next_binding.clone()), key, cutoff + 1)
        } else {
            node
        }
    }

    pub(crate) fn find(table: TableRef, id: Hash) -> Option<Peer> {
        let lock = table.blocking_lock();
        let root = lock.root.as_ref().unwrap();

        if let Some(trie) = Self::traverse(Some(root.clone()), id, 0) {
            let lock = trie.blocking_lock();

            if let Some(bucket) = &lock.bucket {
                bucket.peers.iter().find(|x| x.id == id).cloned()
            } else {
                None
            }
        } else {
            None
        }
    }

    pub(crate) fn update<P: Pinger>(table: TableRef, peer: Peer) {
        let n;
        {
            let lock = table.as_ref().blocking_lock();
            let root = lock.root.as_ref().unwrap();

            n = Self::traverse(Some(root.clone()), peer.id, 0);
        }

        let mut trie = n.as_ref().unwrap().blocking_lock();

        Self::update_trie::<P>(table.clone(), &mut trie, peer);
    }

    fn responded(trie: &mut Trie, peer: &SinglePeer) {
        if let Some(bkt) = &mut trie.bucket {
            if let Some(bkt_idx) = bkt.peers.iter().position(|x| x.id == peer.id) {
                let bkt_entry = bkt.peers.get_mut(bkt_idx).unwrap();

                if let Some(addr_idx) = bkt_entry.addresses.iter().position(|x| x.0 == peer.addr) {
                    let addr_entry = bkt_entry.addresses.get_mut(addr_idx).unwrap();

                    if addr_entry.1 < MISSED_PINGS_ALLOWED {
                        if addr_entry.1 > 0 {
                            addr_entry.1 -= 1;
                        }

                        {
                            let t = bkt_entry.addresses.remove(addr_idx);
                            bkt_entry.addresses.push(t);
                        }

                        {
                            let t = bkt.peers.remove(bkt_idx);
                            bkt.peers.push(t);
                        }

                        debug!("pending node {:#x} updated", peer.id);
                    } else {
                        debug!(
                            "removed address {}:{} for {:#x}",
                            addr_entry.0 .0, addr_entry.0 .1, peer.id
                        );

                        bkt_entry.addresses.remove(addr_idx);
                    }
                } else if bkt_entry.addresses.len() < ADDRESS_LIMIT {
                    debug!(
                        "new address {}:{} for existing node {:#x}",
                        peer.id, peer.addr.0, peer.addr.1
                    );

                    bkt_entry.addresses.push((peer.addr, 0));
                }
            }

            bkt.last_seen = timestamp();
        }
    }

    fn stale(trie: &mut Trie, peer: &SinglePeer, to_add: Peer) {
        if let Some(bkt) = &mut trie.bucket {
            if let Some(bkt_idx) = bkt.peers.iter().position(|x| x.id == peer.id) {
                let bkt_entry = bkt.peers.get_mut(bkt_idx).unwrap();

                if let Some(addr_idx) = bkt_entry.addresses.iter().position(|x| x.0 == peer.addr) {
                    let addr_entry = bkt_entry.addresses.get_mut(addr_idx).unwrap();

                    addr_entry.1 += 1;

                    if addr_entry.1 > MISSED_PINGS_ALLOWED {
                        bkt_entry.addresses.remove(addr_idx);

                        if bkt_entry.addresses.is_empty() {
                            if let Some(replacement) = bkt.cache.pop() {
                                debug!(
                                    "adding {:#x} from cache to bucket and removing {:#x}",
                                    replacement.id, bkt_entry.id
                                );

                                bkt.peers.push(replacement);
                                bkt.update_cached_peer(to_add);
                            } else {
                                debug!("nothing in cache, erasing node {:#x} and adding peer {:#x}", bkt_entry.id, to_add.id);
                                bkt.peers.push(to_add);
                            }

                            bkt.peers.remove(bkt_idx);
                        } else {
                            debug!("node {:#x} still has addresses in entry", bkt_entry.id);
                        }
                    }
                }
            }
        }
    }

    fn update_trie<P: Pinger>(tbl: TableRef, trie: &mut Trie, peer: Peer) {
        if let Some(bkt) = &mut trie.bucket {
            let table = tbl.blocking_lock();

            let mask: Hash = Hash::max_value() << (KEY_SIZE - trie.cutoff);

            let exists = bkt.peers.iter().any(|x| x.id == peer.id);
            let fits = bkt.peers.len() < BUCKET_SIZE;
            let nearby = (peer.id & mask) == (table.id & mask);

            // bucket is not full and peer doesnt exist yet, add to bucket
            if !exists && fits {
                debug!("peer doesnt exist and bucket is not full, adding");
                bkt.add_peer(peer);
            } else if exists {
                if nearby {
                    // bucket is full but nearby, update node
                    debug!("bucket is full but nearby, update node");
                    bkt.update_nearby(peer);
                } else {
                    // node is known to us already but far so ping to check
                    debug!("bucket is known to us already but far so ping");
                    if bkt.peers.is_empty() {
                        return;
                    }

                    let front = bkt.peers.first().unwrap().clone();

                    let node = table.node.upgrade().unwrap();

                    match P::ping_peer(node, front) {
                        Ok(resp) => {
                            debug!("responded, updating");
                            Self::responded(trie, &resp);
                        }
                        Err(unresp) => {
                            debug!("did not respond, making stale");
                            Self::stale(trie, &unresp, peer);
                        }
                    }
                }
            } else if nearby {
                // bucket is full and within prefix, split
                debug!("bucket is full and within prefix, split");
                bkt.add_peer(peer);
                trie.split();
            } else {
                // add/update entry in replacement cache
                bkt.update_cached_peer(peer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::node::{Node, RealPinger, ResponsiveMockPinger, UnresponsiveMockPinger};

    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tracing_test::traced_test;

    fn generate_peer(pid: Option<Hash>) -> Peer {
        Peer {
            id: if let Some(pid_) = pid {
                pid_
            } else {
                let i = (0..32u8).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
                Hash::from(&i[..])
            },
            addresses: vec![(
                (
                    IpAddr::V4("127.0.0.1".parse::<Ipv4Addr>().unwrap()),
                    rand::random(),
                ),
                0,
            )],
        }
    }

    #[traced_test]
    #[test]
    fn add_single_peer() {
        if let Ok(node) = Node::new(16161, false, true) {
            let mut binding = node.blocking_lock();
            let table = binding.table.as_ref().unwrap().clone();
            let pinger = RealPinger::default();
            
            RoutingTable::update::<ResponsiveMockPinger>(table.clone(), generate_peer(None));

            let inner = table.blocking_lock();
            let root = inner.root.as_ref().unwrap().blocking_lock();
            let bkt = root.bucket.as_ref().unwrap();

            assert_eq!(bkt.peers.len(), 1);
        }
    }

    fn validate_tree(t: &Trie) {
        let mut left_ok = true;
        let mut right_ok = true;

        assert!(t.bucket.is_none());
        assert!(t.left.is_some());
        assert!(t.right.is_some());

        let mask: Hash = Hash::from(1) << (KEY_SIZE - (t.cutoff + 1));

        {
            let left = t.left.as_ref().unwrap().blocking_lock();
            if let Some(bkt) = &left.bucket {
                for entry in &bkt.peers {
                    if entry.id & mask != Hash::zero() {
                        left_ok = false;
                    }
                }
            } else {
                left_ok = false;
            }
        }

        {
            let right = t.right.as_ref().unwrap().blocking_lock();
            if let Some(bkt) = &right.bucket {
                for entry in &bkt.peers {
                    if entry.id & mask == Hash::zero() {
                        right_ok = false;
                    }
                }
            } else {
                right_ok = false;
            }
        }

        assert!(left_ok && right_ok);
    }

    #[traced_test]
    #[test]
    fn split() {
        if let Ok(node) = Node::new(16161, false, true) {
            let table;
            {
                let binding = node.blocking_lock();
                table = binding.table.as_ref().unwrap().clone();
            }

            let temp = Hash::from(1) << (KEY_SIZE - 1);

            {
                let mut lock = table.blocking_lock();
                lock.id = temp;
            }

            for i in 0..BUCKET_SIZE {
                RoutingTable::update::<ResponsiveMockPinger>(table.clone(), generate_peer(Some(Hash::from(i))));
            }

            RoutingTable::update::<ResponsiveMockPinger>(
                table.clone(),
                generate_peer(Some(Hash::from(3) << (KEY_SIZE - 2))),
            );

            {
                let inner = table.blocking_lock();
                let root = inner.root.as_ref().unwrap().blocking_lock();

                validate_tree(&root);

                {
                    let b = root.left.as_ref().unwrap();
                    let left = b.blocking_lock();
                    assert_eq!(left.bucket.as_ref().unwrap().peers.len(), BUCKET_SIZE);
                }

                {
                    let b = root.right.as_ref().unwrap();
                    let right = b.blocking_lock();
                    assert_eq!(right.bucket.as_ref().unwrap().peers.len(), 1);
                }
            }

            for i in 0..BUCKET_SIZE {
                RoutingTable::update::<ResponsiveMockPinger>(
                    table.clone(),
                    generate_peer(Some(temp | Hash::from(i))),
                );
            }

            {
                let inner = table.blocking_lock();
                let root = inner.root.as_ref().unwrap().blocking_lock();

                let r = root.right.as_ref().unwrap().clone();
                let lock = r.blocking_lock();

                validate_tree(&lock);

                {
                    let b = lock.left.as_ref().unwrap();
                    let left = b.blocking_lock();
                    assert_eq!(left.bucket.as_ref().unwrap().peers.len(), BUCKET_SIZE);
                }

                {
                    let b = lock.right.as_ref().unwrap();
                    let right = b.blocking_lock();
                    assert_eq!(right.bucket.as_ref().unwrap().peers.len(), 1);
                }
            }
        }
    }

    #[traced_test]
    #[test]
    fn far_responsive() {
        if let Ok(node) = Node::new(16161, false, true) {
            let table;
            {
                let binding = node.blocking_lock();
                table = binding.table.as_ref().unwrap().clone();
            }

            let temp = Hash::from(1) << (KEY_SIZE - 1);

            {
                let mut lock = table.blocking_lock();
                lock.id = temp;
            }

            for i in 0..BUCKET_SIZE {
                RoutingTable::update::<ResponsiveMockPinger>(
                    table.clone(),
                    generate_peer(Some(temp | Hash::from(i))),
                );
            }

            // insert far nodes
            for i in 0..(BUCKET_SIZE) {
                RoutingTable::update::<ResponsiveMockPinger>(table.clone(), generate_peer(Some(Hash::from(i))));
            }

            for i in 2..(BUCKET_SIZE + 2) {
                RoutingTable::update::<ResponsiveMockPinger>(
                    table.clone(),
                    generate_peer(Some(Hash::from(70 | i))),
                );
            }

            {
                let lock = table.blocking_lock();
                let root = lock.root.as_ref().unwrap().blocking_lock();
                let left = root.left.as_ref().unwrap().blocking_lock();

                assert_eq!(left.bucket.as_ref().unwrap().peers.len(), BUCKET_SIZE);
            }
        }
    }

    #[traced_test]
    #[test]
    fn far_unresponsive() {
        if let Ok(node) = Node::new(16161, false, true) {
            let table;
            {
                let binding = node.blocking_lock();
                table = binding.table.as_ref().unwrap().clone();
            }

            let temp = Hash::from(1) << (KEY_SIZE - 1);

            {
                let mut lock = table.blocking_lock();
                lock.id = temp;
            }

            for i in 0..BUCKET_SIZE {
                RoutingTable::update::<ResponsiveMockPinger>(
                    table.clone(),
                    generate_peer(Some(temp | Hash::from(i))),
                );
            }

            let to_stale = generate_peer(Some(Hash::from(1)));

            RoutingTable::update::<UnresponsiveMockPinger>(table.clone(), to_stale.clone());

            // insert far nodes
            for i in 2..(BUCKET_SIZE + 1) {
                RoutingTable::update::<UnresponsiveMockPinger>(table.clone(), generate_peer(Some(Hash::from(i))));
            }

            // fill replacement cache
            for i in 0..(CACHE_SIZE + 1) {
                RoutingTable::update::<UnresponsiveMockPinger>(
                    table.clone(),
                    generate_peer(Some(Hash::from(70 | i))),
                );
            }

            // should become max staleness
            for _ in 0..=(MISSED_PINGS_ALLOWED + 1) {
                RoutingTable::update::<UnresponsiveMockPinger>(table.clone(), to_stale.clone());
            }

            let stale = RoutingTable::find(table.clone(), to_stale.id);
            let added = RoutingTable::find(table.clone(), Hash::from(70 | CACHE_SIZE));

            assert!(stale.is_none());
            assert!(added.is_some());
        }
    }
}
