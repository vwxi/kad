use crate::{
    node::{InnerKad, Pinger},
    util::{timestamp, Hash, Peer, SinglePeer},
};
use futures::future::{BoxFuture, FutureExt};
use rand::Rng;
use std::{
    future::Future,
    sync::{Arc, Weak},
};
use tokio::sync::RwLock;
use tracing::debug;

pub(crate) mod consts {
    pub(crate) const HASH_SIZE: usize = 256;
    pub(crate) const ADDRESS_LIMIT: usize = 5;
    pub(crate) const MISSED_PINGS_ALLOWED: usize = 3;
    pub(crate) const MISSED_MESSAGES_ALLOWED: usize = 3;
    pub(crate) const CACHE_SIZE: usize = 3;
    pub(crate) const ALPHA: usize = 3;

    crate::util::pred_block! {
        #[cfg(test)] {
            pub(crate) const BUCKET_SIZE: usize = 10;
            pub(crate) const REFRESH_TIME: u64 = 5;
            pub(crate) const REFRESH_INTERVAL: usize = 10;
        }

        #[cfg(not(test))] {
            pub(crate) const BUCKET_SIZE: usize = 20;
            pub(crate) const REFRESH_TIME: u64 = 3600;
            pub(crate) const REFRESH_INTERVAL: usize = 600;
        }
    }
}

// the prefix trie model is used in this implementation.
// this may be changed in the future.

#[derive(Debug)]
pub(crate) struct Bucket {
    pub(crate) last_seen: u64,
    pub(crate) peers: Vec<Peer>,
    pub(crate) cache: Vec<SinglePeer>,
}

#[derive(Debug)]
pub(crate) struct Trie {
    pub(crate) prefix: Hash,
    pub(crate) cutoff: usize,
    pub(crate) bucket: Option<Bucket>,
    pub(crate) left: TrieRef,
    pub(crate) right: TrieRef,
}

#[derive(Debug)]
pub(crate) struct RoutingTable {
    pub(crate) id: Hash,
    root: TrieRef,
    node: Weak<InnerKad>,
}

pub(crate) type InnerTrieRef = Arc<RwLock<Trie>>;
pub(crate) type TrieRef = Option<InnerTrieRef>;
pub(crate) type TableRef = Arc<RoutingTable>;

impl Bucket {
    fn new() -> Self {
        Bucket {
            last_seen: timestamp(),
            peers: Vec::new(),
            cache: Vec::new(),
        }
    }

    fn add_peer(&mut self, peer: SinglePeer) {
        debug!("added peer {:#x}", peer.id);

        self.peers.push(peer.as_peer());
        self.last_seen = timestamp();
    }

    fn update_cached_peer(&mut self, peer: SinglePeer) {
        // exists in cache?
        if let Some(idx) = self.cache.iter().position(|x| x.id == peer.id) {
            // move to end
            let t = self.cache.remove(idx);
            self.cache.push(t);
        } else {
            // if cache is full, kick out oldest node
            if self.cache.len() > consts::CACHE_SIZE {
                debug!("cache full, removing oldest candidate");
                self.cache.remove(0);
            }

            // add new node anyways
            debug!("adding new node to cache {:#x}", peer.id);
            self.cache.push(peer);
        }

        self.last_seen = timestamp();
    }

    fn update_nearby(&mut self, peer: SinglePeer) {
        // exists in bucket?
        if let Some(idx) = self.peers.iter().position(|x| x.id == peer.id) {
            // move to bucket tail
            let t = self.peers.remove(idx);
            self.peers.push(t);

            let entry = self.peers.iter_mut().last().unwrap();

            // check if address is new and if address count is under limit
            if !entry.addresses.iter().any(|x| x.0 == peer.addr)
                && entry.addresses.len() < consts::ADDRESS_LIMIT
            {
                // add to address list
                debug!("new address {:?} for node {:#x}", peer.addr, entry.id);
                entry.addresses.push((peer.addr, 0));
            }

            // sort by liveness
            entry.addresses.sort_by(|x, y| x.1.cmp(&y.1));
        } else if self.peers.len() < consts::BUCKET_SIZE {
            // does not exist in bucket, add
            self.peers.push(peer.as_peer());
        }

        self.last_seen = timestamp();
    }
}

impl Trie {
    // create a new trie node
    pub(crate) fn new(pre: Hash, cut: usize, leaf: bool) -> InnerTrieRef {
        Arc::new(RwLock::new(Trie {
            prefix: pre,
            cutoff: cut,
            bucket: if leaf { Some(Bucket::new()) } else { None },
            left: None,
            right: None,
        }))
    }

    async fn split(&mut self) {
        if let Some(bkt) = &self.bucket {
            self.left = Some(Trie::new(self.prefix, self.cutoff + 1, true));

            let new_bit = Hash::from(1) << (consts::HASH_SIZE - (self.cutoff + 1));

            self.right = Some(Trie::new(self.prefix | new_bit, self.cutoff + 1, true));

            let mut l_lock = self.left.as_ref().unwrap().write().await;
            let l_bkt = l_lock.bucket.as_mut().unwrap();
            let mut r_lock = self.right.as_ref().unwrap().write().await;
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
            l_bkt.peers.truncate(consts::BUCKET_SIZE);
            r_bkt.peers.truncate(consts::BUCKET_SIZE);

            self.bucket = None;
        }
    }
}

// TODO: refresh mechanism
impl RoutingTable {
    pub(crate) fn new(i: Hash, n: Weak<InnerKad>) -> TableRef {
        Arc::new(RoutingTable {
            id: i,
            root: Some(Trie::new(Hash::zero(), 0, true)),
            node: n,
        })
    }

    fn traverse(node: TrieRef, key: Hash, cutoff: usize) -> BoxFuture<'static, TrieRef> {
        async move {
            let current = node.as_ref().unwrap().read().await;

            if let (None, None, Some(_)) = (&current.left, &current.right, &current.bucket) {
                drop(current);
                return node;
            }

            let next = if key & (Hash::from(1) << (consts::HASH_SIZE - cutoff - 1)) == Hash::zero()
            {
                current.left.as_ref().unwrap().clone()
            } else {
                current.right.as_ref().unwrap().clone()
            };

            drop(current);
            Self::traverse(Some(next.clone()), key, cutoff + 1).await
        }
        .boxed()
    }

    fn dfs<F, Fut>(self: Arc<Self>, node: TrieRef, f: F) -> BoxFuture<'static, ()>
    where
        Fut: Future<Output = ()> + Send,
        F: Fn(Arc<Self>, InnerTrieRef) -> Fut + Send + Clone + 'static,
    {
        async move {
            let inner = node.as_ref().unwrap();
            let current = inner.read().await;

            if let (None, None, Some(_)) = (&current.left, &current.right, &current.bucket) {
                debug!("reached leaf");
                drop(current);
                f(self, inner.to_owned()).await;
                return;
            }

            let (left, right) = (current.left.clone(), current.right.clone());

            drop(current);
            self.clone().dfs(left, f.clone()).await;
            self.dfs(right, f).await;
        }
        .boxed()
    }

    pub(crate) async fn find(self: Arc<Self>, id: Hash) -> Option<Peer> {
        let routing_table = self.clone();
        let root = routing_table.root.as_ref().unwrap();

        if let Some(trie) = Self::traverse(Some(root.clone()), id, 0).await {
            let lock = trie.read().await;

            if let Some(bucket) = &lock.bucket {
                bucket.peers.iter().find(|x| x.id == id).cloned()
            } else {
                None
            }
        } else {
            None
        }
    }

    pub(crate) async fn find_bucket(self: Arc<Self>, id: Hash) -> Vec<SinglePeer> {
        let routing_table = self.clone();
        let root = routing_table.root.as_ref().unwrap();

        if let Some(trie) = Self::traverse(Some(root.clone()), id, 0).await {
            let lock = trie.read().await;

            if let Some(bucket) = &lock.bucket {
                bucket.peers.clone().iter().map(Peer::single_peer).collect()
            } else {
                vec![]
            }
        } else {
            vec![]
        }
    }

    pub(crate) async fn find_alpha_peers(self: Arc<Self>, id: Hash) -> Vec<Peer> {
        let routing_table = self.clone();
        let root = routing_table.root.as_ref().unwrap();

        if let Some(trie) = Self::traverse(Some(root.clone()), id, 0).await {
            let lock = trie.read().await;

            if let Some(bucket) = &lock.bucket {
                let mut bkt = bucket.peers.clone();
                bkt.truncate(consts::ALPHA);
                bkt
            } else {
                vec![]
            }
        } else {
            vec![]
        }
    }

    pub(crate) async fn resolve(self: Arc<Self>, mut peer: Peer) -> Peer {
        if let Some(mut res) = self.find(peer.id).await {
            peer.addresses.append(&mut res.addresses);
        }

        peer
    }

    pub(crate) async fn update<P: Pinger>(self: Arc<Self>, peer: SinglePeer) {
        let n = Self::traverse(
            Some(self.clone().root.as_ref().unwrap().clone()),
            peer.id,
            0,
        )
        .await;

        let mut trie = n.as_ref().unwrap().write().await;

        self.update_trie::<P>(&mut trie, peer).await;
    }

    async fn responded(node: Arc<InnerKad>, trie: &mut Trie, peer: &SinglePeer) {
        if let Some(bkt) = &mut trie.bucket {
            if let Some(bkt_idx) = bkt.peers.iter().position(|x| x.id == peer.id) {
                if let Some(addr_idx) = bkt
                    .peers
                    .get(bkt_idx)
                    .unwrap()
                    .addresses
                    .iter()
                    .position(|x| x.0 == peer.addr)
                {
                    let addr_entry = bkt
                        .peers
                        .get(bkt_idx)
                        .unwrap()
                        .addresses
                        .get(addr_idx)
                        .unwrap();

                    let staleness = addr_entry.1;

                    if staleness < consts::MISSED_PINGS_ALLOWED {
                        if staleness > 0 {
                            bkt.peers
                                .get_mut(bkt_idx)
                                .unwrap()
                                .addresses
                                .get_mut(addr_idx)
                                .unwrap()
                                .1 -= 1;
                        }

                        {
                            let bkt_entry = bkt.peers.get_mut(bkt_idx).unwrap();

                            let t = bkt_entry.addresses.remove(addr_idx);
                            bkt_entry.addresses.push(t);
                        }

                        {
                            let t = bkt.peers.remove(bkt_idx);
                            bkt.peers.push(t);
                        }

                        debug!("pending node {:#x} updated", peer.id);
                    } else {
                        debug!("removed address {:?} for {:#x}", addr_entry.0, peer.id);

                        {
                            let addrs: &mut Vec<(_, usize)> =
                                bkt.peers.get_mut(bkt_idx).unwrap().addresses.as_mut();

                            addrs.remove(addr_idx);

                            if addrs.is_empty() {
                                if let Some(replacement) = bkt.cache.pop() {
                                    debug!(
                                        "adding {:#x} from cache to bucket and removing {:#x}",
                                        replacement.id, peer.id
                                    );

                                    bkt.add_peer(replacement);
                                } else {
                                    debug!("nothing in cache, erasing node {:#x}", peer.id);
                                }

                                bkt.peers.remove(bkt_idx);

                                // remove peer from keyring
                                node.crypto.remove(&peer.id).await;
                            } else {
                                debug!("node {:#x} still has addresses in entry", peer.id);
                            }
                        }
                    }
                } else {
                    let bkt_entry = bkt.peers.get_mut(bkt_idx).unwrap();

                    if bkt_entry.addresses.len() < consts::ADDRESS_LIMIT {
                        debug!(
                            "new address {:?} for existing node {:#x}",
                            peer.addr, peer.id
                        );

                        bkt_entry.addresses.push((peer.addr, 0));
                    }
                }
            }

            bkt.last_seen = timestamp();
        }
    }

    async fn stale(node: Arc<InnerKad>, trie: &mut Trie, peer: &SinglePeer, to_add: SinglePeer) {
        if let Some(bkt) = &mut trie.bucket {
            if let Some(bkt_idx) = bkt.peers.iter().position(|x| x.id == peer.id) {
                if let Some(addr_idx) = bkt
                    .peers
                    .get(bkt_idx)
                    .unwrap()
                    .addresses
                    .iter()
                    .position(|x| x.0 == peer.addr)
                {
                    let addr_entry = bkt
                        .peers
                        .get(bkt_idx)
                        .unwrap()
                        .addresses
                        .get(addr_idx)
                        .unwrap();

                    if addr_entry.1 < consts::MISSED_PINGS_ALLOWED {
                        bkt.peers
                            .get_mut(bkt_idx)
                            .unwrap()
                            .addresses
                            .get_mut(addr_idx)
                            .unwrap()
                            .1 += 1;
                    } else {
                        {
                            let addrs: &mut Vec<(_, usize)> =
                                bkt.peers.get_mut(bkt_idx).unwrap().addresses.as_mut();

                            addrs.remove(addr_idx);

                            if addrs.is_empty() {
                                if let Some(replacement) = bkt.cache.pop() {
                                    debug!(
                                        "adding {:#x} from cache to bucket and removing {:#x}",
                                        replacement.id, peer.id
                                    );

                                    bkt.add_peer(replacement);
                                } else {
                                    debug!(
                                        "nothing in cache, erasing node {:#x} and adding peer {:#x}",
                                        peer.id, to_add.id
                                    );

                                    bkt.add_peer(to_add);
                                }

                                bkt.peers.remove(bkt_idx);

                                // remove peer from keyring
                                node.crypto.remove(&peer.id).await;
                            }
                        }
                    }
                }
            }
        }
    }

    async fn update_trie<P: Pinger>(self: Arc<Self>, trie: &mut Trie, peer: SinglePeer) {
        if let Some(bkt) = &mut trie.bucket {
            let mask: Hash = Hash::max_value() << (consts::HASH_SIZE - trie.cutoff);

            let exists = bkt.peers.iter().any(|x| x.id == peer.id);
            let fits = bkt.peers.len() < consts::BUCKET_SIZE;
            let nearby = (peer.id & mask) == (self.id & mask);
            let root = trie.cutoff == 0;

            // bucket is not full and peer doesnt exist yet, add to bucket
            if !exists && fits {
                debug!("peer doesnt exist and bucket is not full, adding");
                bkt.add_peer(peer);
            } else if exists {
                // make sure it is not root node
                #[allow(clippy::if_not_else)]
                if nearby != root {
                    // bucket is full but nearby, update node
                    debug!("bucket is full but nearby, update node");
                    bkt.update_nearby(peer);
                } else {
                    // node is known to us already but far so ping to check
                    debug!("node is known to us already but far so ping");
                    if bkt.peers.is_empty() {
                        return;
                    }

                    let front = bkt.peers.first().unwrap().clone();
                    let node = self.node.upgrade().unwrap();

                    match P::ping_peer(node.clone(), front) {
                        Ok(resp) => {
                            debug!("responded, updating");
                            Self::responded(node, trie, &resp).await;
                        }
                        Err(unresp) => {
                            debug!("did not respond, making stale");
                            Self::stale(node, trie, &unresp, peer).await;
                        }
                    }
                }
            } else if nearby {
                // bucket is full and within prefix, split
                debug!("bucket is full and within prefix, split");
                bkt.add_peer(peer);
                trie.split().await;
            } else {
                // add/update entry in replacement cache
                bkt.update_cached_peer(peer);
            }
        }
    }

    async fn refresh<P: Pinger>(self: Arc<Self>, trie: TrieRef) {
        let mut randomness: Hash = Hash::zero();
        rand::thread_rng().fill(&mut randomness.0[..]);

        let mask: Hash;
        let random_id: Hash;

        {
            let lock = trie.as_ref().unwrap().read().await;

            mask = Hash::max_value() << (consts::HASH_SIZE - lock.cutoff);
            random_id = lock.prefix | (randomness & !mask);
        }

        let node = self.clone().node.upgrade().unwrap();
        let kad = node.parent.upgrade().unwrap();
        let handle = kad.runtime.handle();

        let bkt = node.iter_find_node(random_id).await;

        let mut lock = trie.as_ref().unwrap().write().await;

        if !bkt.is_empty() {
            if let Some(ref mut bucket) = &mut lock.bucket {
                bucket.peers.clear();

                tokio::task::block_in_place(|| {
                    for p in &bkt {
                        p.addresses.iter().for_each(|a| {
                            handle.block_on(
                                self.clone()
                                    .update_trie::<P>(&mut lock, SinglePeer::new(p.id, a.0)),
                            );
                        });
                    }
                });
            }
        }
    }

    pub(crate) async fn refresh_tree<P: Pinger>(self: Arc<Self>) {
        let root = self.root.clone();

        self.dfs(root, |s: Arc<Self>, i: InnerTrieRef| async move {
            let binding = i.clone();
            let lock = binding.read().await;

            if let Some(bkt) = &lock.bucket {
                if timestamp() - bkt.last_seen > consts::REFRESH_TIME {
                    debug!("refreshed bucket {:#x}", lock.cutoff);
                    drop(lock);
                    s.refresh::<P>(Some(i)).await;
                }
            }
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        node::{Kad, ResponsiveMockPinger, UnresponsiveMockPinger},
        util::generate_peer,
    };

    use super::*;
    use futures::executor::block_on;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn add_single_peer() {
        let kad = Kad::mock(rand::random(), false, false).unwrap();

        let table = kad.node.table.clone();

        block_on(
            table
                .clone()
                .update::<ResponsiveMockPinger>(generate_peer(None)),
        );

        let root = table.root.as_ref().unwrap().blocking_read();
        let bkt = root.bucket.as_ref().unwrap();

        assert_eq!(bkt.peers.len(), 1);
    }

    fn validate_tree(t: &Trie) {
        let mut left_ok = true;
        let mut right_ok = true;

        assert!(t.bucket.is_none());
        assert!(t.left.is_some());
        assert!(t.right.is_some());

        let mask: Hash = Hash::from(1) << (consts::HASH_SIZE - (t.cutoff + 1));

        {
            let left = t.left.as_ref().unwrap().blocking_read();
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
            let right = t.right.as_ref().unwrap().blocking_read();
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
        let kad = Kad::mock(Hash::from(1) << (consts::HASH_SIZE - 1), false, false).unwrap();
        let table = kad.node.table.clone();

        for i in 0..consts::BUCKET_SIZE {
            block_on(
                table
                    .clone()
                    .update::<ResponsiveMockPinger>(generate_peer(Some(Hash::from(i)))),
            );
        }

        // split root
        block_on(
            table
                .clone()
                .update::<ResponsiveMockPinger>(generate_peer(Some(
                    Hash::from(3) << (consts::HASH_SIZE - 2),
                ))),
        );

        {
            let root = table.root.as_ref().unwrap().blocking_read();

            validate_tree(&root);

            {
                let b = root.left.as_ref().unwrap();
                let left = b.blocking_read();
                assert_eq!(
                    left.bucket.as_ref().unwrap().peers.len(),
                    consts::BUCKET_SIZE
                );
            }

            {
                let b = root.right.as_ref().unwrap();
                let right = b.blocking_read();
                assert_eq!(right.bucket.as_ref().unwrap().peers.len(), 1);
            }
        }

        // fill right leaf with nearby peers
        for i in 0..consts::BUCKET_SIZE {
            block_on(
                table
                    .clone()
                    .update::<ResponsiveMockPinger>(generate_peer(Some(table.id | Hash::from(i)))),
            );
        }

        {
            let root = table.root.as_ref().unwrap().blocking_read();

            let r = root.right.as_ref().unwrap().clone();
            let lock = r.blocking_read();

            validate_tree(&lock);

            {
                let b = lock.left.as_ref().unwrap();
                let left = b.blocking_read();
                assert_eq!(
                    left.bucket.as_ref().unwrap().peers.len(),
                    consts::BUCKET_SIZE
                );
            }

            {
                let b = lock.right.as_ref().unwrap();
                let right = b.blocking_read();
                assert_eq!(right.bucket.as_ref().unwrap().peers.len(), 1);
            }
        }
    }

    #[traced_test]
    #[test]
    fn far_responsive() {
        let kad = Kad::mock(Hash::from(1) << (consts::HASH_SIZE - 1), false, false).unwrap();
        let table = kad.node.table.clone();

        for i in 0..consts::BUCKET_SIZE {
            block_on(
                table
                    .clone()
                    .update::<ResponsiveMockPinger>(generate_peer(Some(table.id | Hash::from(i)))),
            );
        }

        // insert far nodes
        for i in 0..(consts::BUCKET_SIZE) {
            block_on(
                table
                    .clone()
                    .update::<ResponsiveMockPinger>(generate_peer(Some(Hash::from(i)))),
            );
        }

        for i in 2..(consts::BUCKET_SIZE + 2) {
            block_on(
                table
                    .clone()
                    .update::<ResponsiveMockPinger>(generate_peer(Some(Hash::from(70 | i)))),
            );
        }

        {
            let root = table.root.as_ref().unwrap().blocking_read();
            let left = root.left.as_ref().unwrap().blocking_read();

            assert_eq!(
                left.bucket.as_ref().unwrap().peers.len(),
                consts::BUCKET_SIZE
            );
        }
    }

    #[traced_test]
    #[test]
    fn far_unresponsive() {
        let kad = Kad::mock(Hash::from(1) << (consts::HASH_SIZE - 1), false, false).unwrap();
        let table = kad.node.table.clone();

        for i in 0..consts::BUCKET_SIZE {
            block_on(
                table
                    .clone()
                    .update::<ResponsiveMockPinger>(generate_peer(Some(table.id | Hash::from(i)))),
            );
        }

        let to_stale = generate_peer(Some(Hash::from(1)));

        block_on(table.clone().update::<UnresponsiveMockPinger>(to_stale));

        // insert far nodes
        for i in 2..(consts::BUCKET_SIZE + 1) {
            block_on(
                table
                    .clone()
                    .update::<UnresponsiveMockPinger>(generate_peer(Some(Hash::from(i)))),
            );
        }

        // fill replacement cache
        for i in 0..(consts::CACHE_SIZE + 1) {
            block_on(
                table
                    .clone()
                    .update::<UnresponsiveMockPinger>(generate_peer(Some(Hash::from(70 | i)))),
            );
        }

        // should become max staleness
        for _ in 0..=(consts::MISSED_PINGS_ALLOWED + 1) {
            block_on(table.clone().update::<UnresponsiveMockPinger>(to_stale));
        }

        let stale = block_on(table.clone().find(to_stale.id));
        let added = block_on(table.clone().find(Hash::from(70 | consts::CACHE_SIZE)));

        assert!(stale.is_none());
        assert!(added.is_some());
    }
}
