use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use futures::{stream::FuturesUnordered, StreamExt};
use tokio::sync::Mutex;
use tracing::debug;

use crate::{
    node::KadNode,
    routing::{consts::ALPHA, RoutingTable},
    util::{FindValueResult, Hash, Peer, SinglePeer},
};

pub(crate) mod consts {
    pub(crate) const DISJOINT_PATHS: usize = 3;
    pub(crate) const QUORUM: usize = 3;
}

impl KadNode {
    // xlattice-style lookup
    pub(crate) async fn lookup_nodes(
        self: Arc<Self>,
        mut shortlist: VecDeque<Peer>,
        key: Hash,
    ) -> Vec<Peer> {
        // own id
        let id = self.table.lock().await.id;
        // all valid contacted peers
        let mut res: Vec<Peer> = vec![];
        // all peers contacted regardless of response
        let mut visited: Vec<SinglePeer> = vec![];

        if let Some(mut closest_node) = shortlist.iter().cloned().min_by_key(|x| (x.id ^ key)) {
            let mut first = true;
            while !shortlist.is_empty() {
                for _ in 0..ALPHA {
                    if let Some(item) = shortlist.pop_front() {
                        tokio::task::block_in_place(|| {
                            let result = self.clone().find_node(item.clone(), key);

                            // visited contains all contacted peers regardless of validity
                            visited.extend(
                                item.addresses
                                    .iter()
                                    .map(|addr| SinglePeer::new(item.id, addr.0)),
                            );

                            // res contains all valid contacted peers
                            if !res.iter().any(|x| x.id == item.id) {
                                res.push(item);
                            }

                            // check if:
                            // - we are about to query ourselves
                            // - we've already visited this specific IP:ID
                            // - we've already added this IP or ID to the shortlist
                            if let Ok(peers) = result {
                                for peer in peers.0 {
                                    if peer.id == id
                                        || visited
                                            .iter()
                                            .any(|x| x.id == peer.id && x.addr == peer.addr)
                                        || shortlist.iter().any(|x| {
                                            x.id == peer.id
                                                || x.addresses.iter().any(|y| y.0 == peer.addr)
                                        })
                                    {
                                        continue;
                                    }

                                    shortlist.push_back(peer.peer());
                                }
                            }
                        });
                    } else {
                        break;
                    }
                }

                if res.is_empty() {
                    break;
                }

                shortlist.make_contiguous().sort_by_key(|x| (x.id ^ key));

                if let Some(candidate) = shortlist
                    .iter()
                    .min_by(|x, y| (x.id ^ key).cmp(&(y.id ^ key)))
                {
                    if (candidate.id ^ key) < (closest_node.id ^ key) || first {
                        closest_node = candidate.clone();
                        first = false;
                    } else {
                        break;
                    }
                }
            }
        }

        res
    }

    // libp2p-style value retrieval
    pub(crate) async fn lookup_value(
        self: Arc<Self>,
        mut pn: Vec<Peer>,
        claimed: Option<Arc<Mutex<Vec<Hash>>>>,
        key: Hash,
        quorum: usize,
    ) -> FindValueResult {
        // own id
        let id = self.table.lock().await.id;
        // number of valid values found
        let found_count = AtomicUsize::new(0);
        // pending requests count
        let pending = AtomicUsize::new(0);
        // best value and collision bool
        let mut best: FindValueResult = FindValueResult::None;

        // pn - next query candidates SORTED

        // which peers returned the best values
        let mut pb: Vec<SinglePeer> = Vec::new();
        // peers already queried
        let mut pq: Vec<Hash> = Vec::new();
        // peers with outdated values
        let mut po: Vec<SinglePeer> = Vec::new();

        // search for key in local store, if Q==0,1 then the search is complete
        if let Some(val) = self.store.get(&key).await {
            if quorum < 2 {
                debug!("quorum < 2, found value in local store, search is complete");
                return FindValueResult::Value(val);
            } else {
                // otherwise, we count it as a found value
                found_count.fetch_add(1, Ordering::Relaxed);
                best = FindValueResult::Value(val);
                debug!("found already in local store, counting as a valid result");
            }
        }

        // `pn` will have been seeded with `alpha` initial peers

        loop {
            // if we've collected `quorum` or more answers, return `best`
            // if there are no requests pending and `pn` is empty, return `best`
            // send best value to all `po` nodes
            if found_count.load(Ordering::Relaxed) >= quorum
                || (pending.load(Ordering::Relaxed) == 0 && pn.is_empty())
            {
                debug!("quorum satisfied, updating outdated nodes");

                if let FindValueResult::Value(ref v) = best {
                    // don't forward entry, let's just store what was acquired
                    tokio::task::block_in_place(|| {
                        let _ = po.iter().map(|p| {
                            debug!("storing best value at {:#x}", p.id);
                            let _ = self.clone().store(p.peer(), key, v.clone());
                        });
                    });
                }

                return best;
            }

            // otherwise, send `alpha` `pn` peers a find_value call
            let mut tasks = FuturesUnordered::new();
            {
                let mut pn_it = pn.drain(..);

                // be quiet...
                #[allow(unused_assignments)]
                for mut i in 0..ALPHA {
                    if let Some(mut peer) = pn_it.next() {
                        // FOR DISJOINT PATH LOOKUPS, check if peer exists in any other search
                        if let Some(ref claimed_list) = claimed {
                            let mut lock = claimed_list.lock().await;

                            // if seen already, we exclude this "claimed" peer
                            if lock.iter().any(|&x| x == peer.id) {
                                debug!("disjoint: {:#x} already seen, excluding", peer.id);
                                i = i.saturating_sub(1);
                                continue;
                            } else {
                                // otherwise, add to `claimed` list
                                lock.push(peer.id);
                            }
                        }

                        pending.fetch_add(1, Ordering::Relaxed);

                        peer = RoutingTable::resolve(self.table.clone(), peer).await;

                        // spawn new task
                        debug!("querying peer {:#x}", peer.id);

                        let (new_self, new_peer) = (self.clone(), peer.clone());
                        tasks.push(async move {
                            tokio::task::block_in_place(|| {
                                match new_self.find_value(new_peer, key) {
                                    Ok((result, responding_peer)) => {
                                        (Some(result), responding_peer)
                                    }
                                    Err(p) => (None, p),
                                }
                            })
                        });

                        // mark as queried in `pq`
                        pq.push(peer.id);
                    }
                }
            }

            // just stop if things aren't sending
            if tasks.is_empty() {
                break;
            }

            // gather tasks
            while let Some(task) = tasks.next().await {
                if pending.load(Ordering::Relaxed) == 0 {
                    break;
                }

                pending.fetch_sub(1, Ordering::Relaxed);

                match task {
                    (Some(result), peer) => {
                        match result {
                            FindValueResult::Nodes(nodes) => {
                                // if without value, add unqueried closest nodes to `pn`
                                // ensure node isn't an element of `pq`, `pn` or is self
                                debug!("received bucket, adding unvisited peers...");

                                let kad = self.kad.upgrade().unwrap();
                                let handle = kad.runtime.handle();

                                tokio::task::block_in_place(|| {
                                    pn.extend(
                                        nodes
                                            .iter()
                                            .filter(|x| !pq.contains(&x.id) && x.id != id)
                                            .map(|x| {
                                                handle.block_on(RoutingTable::resolve(
                                                    self.table.clone(),
                                                    x.peer(),
                                                ))
                                            }),
                                    );
                                });
                            }
                            FindValueResult::Value(value) => {
                                debug!("received value");

                                match best {
                                    // if this is the first value seen,
                                    // store it in `best` and store peer in `pb`
                                    FindValueResult::None => {
                                        debug!("first value, storing in best and pb");
                                        best = FindValueResult::Value(value);
                                        pb.push(peer);
                                    }
                                    // resolve value conflict with validation
                                    FindValueResult::Value(ref best_value) => {
                                        debug!("resolving value conflict with validator");

                                        // select newest and valid between `best_value` and `value`
                                        // if equal just add peer to `pb`
                                        match value.0.timestamp.cmp(&best_value.0.timestamp) {
                                            // if new value wins, move all `pb` nodes to `po` to mark
                                            // as outdated, set new peer as `best` and add peer to `pb`
                                            std::cmp::Ordering::Greater => {
                                                // now check if valid.
                                                if self.store.validate(&peer, &value).await {
                                                    debug!(
                                                        "new value wins, marking peers as outdated"
                                                    );
                                                    po.append(&mut pb);

                                                    debug!("clearing pb and inserting new winner");
                                                    pb.clear();
                                                    best = FindValueResult::Value(value);
                                                    pb.push(peer);

                                                    found_count.fetch_add(1, Ordering::Relaxed);
                                                } else {
                                                    // value loses, add current peer to `po`
                                                    debug!("new value lost, adding peer to po");
                                                    po.push(peer);
                                                }
                                            }
                                            // if new value is equal, add to `pb`
                                            std::cmp::Ordering::Equal => {
                                                if self.store.validate(&peer, &value).await {
                                                    debug!("new value is equal to best value, adding to pb");
                                                    pb.push(peer);

                                                    found_count.fetch_add(1, Ordering::Relaxed);
                                                } else {
                                                    debug!("new value is equal and has lost, adding peer to po");
                                                    po.push(peer);
                                                }
                                            }
                                            // if new value is less, it has lost and add to po
                                            std::cmp::Ordering::Less => {
                                                debug!("new value is less and has lost, adding peer to po");
                                                po.push(peer);
                                            }
                                        }
                                    }

                                    // this should never reach
                                    FindValueResult::Nodes(_) => {
                                        panic!("best value should not be a node list");
                                    }
                                }
                            }
                            // timeout/error
                            FindValueResult::None => {
                                debug!("timeout/error from {:?}, discarding", peer.addr);
                                continue;
                            }
                        }
                    }
                    (None, peer) => {
                        debug!("timeout/error from {:#x}", peer.id);
                        continue;
                    }
                }
            }
        }

        best
    }

    async fn _lookup_value(
        self: Arc<Self>,
        portion: Vec<Peer>,
        claimed: Arc<Mutex<Vec<Hash>>>,
        key: Hash,
        quorum: usize,
    ) -> FindValueResult {
        self.lookup_value(portion.to_vec(), Some(claimed.clone()), key, quorum)
            .await
    }

    async fn disjoint_lookup_value(
        self: Arc<Self>,
        key: Hash,
        disjoint_paths: usize,
        quorum: usize,
    ) -> Vec<FindValueResult> {
        let mut initial: Vec<Peer> = RoutingTable::find_alpha_peers(self.table.clone(), key).await;
        let claimed: Arc<Mutex<Vec<Hash>>> = Arc::new(Mutex::new(vec![]));
        let mut tasks = FuturesUnordered::new();

        if initial.len() < disjoint_paths {
            return vec![];
        }

        let amount = initial.len() / disjoint_paths;

        for _ in 0..disjoint_paths {
            let portion = initial.drain(..amount).collect();

            tasks.push(Self::_lookup_value(
                self.clone(),
                portion,
                claimed.clone(),
                key,
                quorum,
            ));
        }

        let mut paths: Vec<FindValueResult> = vec![];
        while let Some(result) = tasks.next().await {
            paths.push(result);
        }

        paths
    }

    pub(crate) async fn iter_find_node(self: Arc<Self>, key: Hash) -> Vec<Peer> {
        let shortlist: VecDeque<Peer> =
            VecDeque::from(RoutingTable::find_alpha_peers(self.table.clone(), key).await);

        self.lookup_nodes(shortlist, key).await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        node::Kad,
        routing::RoutingTable,
        util::{FindValueResult, Hash},
    };
    use futures::{executor::block_on, future::join_all};
    use std::sync::Arc;
    use tracing_test::traced_test;
    use tracing::debug;

    fn setup(offset: u16) -> (Vec<Arc<Kad>>, Vec<tokio::task::JoinHandle<()>>) {
        let nodes: Vec<Arc<Kad>> = (0..5).map(|i| Kad::new(offset + i, false, true)).collect();
        let handles: Vec<_> = nodes.iter().map(|x| x.clone().serve().unwrap()).collect();

        // send find_nodes in this sequence:
        // A -> B
        let _ = nodes[0]
            .node
            .clone()
            .find_node(nodes[1].as_single_peer().peer(), Hash::from(1));
        debug!("A -> B");
        // A -> C
        let _ = nodes[0]
            .node
            .clone()
            .find_node(nodes[2].as_single_peer().peer(), Hash::from(1));
        debug!("A -> C");
        // C -> A
        let _ = nodes[2]
            .node
            .clone()
            .find_node(nodes[0].as_single_peer().peer(), Hash::from(1));
        debug!("C -> A");
        // B -> D
        let _ = nodes[1]
            .node
            .clone()
            .find_node(nodes[3].as_single_peer().peer(), Hash::from(1));
        debug!("B -> D");
        // D -> A
        let _ = nodes[3]
            .node
            .clone()
            .find_node(nodes[0].as_single_peer().peer(), Hash::from(1));
        debug!("D -> A");

        (nodes, handles)
    }

    mod lookup_nodes {
        use super::*;

        #[traced_test]
        #[test]
        fn find_all_nodes() {
            let (nodes, handles) = setup(17000);

            // call as C to get A, B and D
            let res = block_on(nodes[2].node.clone().iter_find_node(Hash::from(1)));

            assert!(!res.is_empty());
            assert!(res
                .iter()
                .all(|x| x.id == nodes[0].id() || x.id == nodes[1].id() || x.id == nodes[3].id()));

            block_on(join_all(handles));
        }
    }

    mod lookup_value {
        use super::*;

        #[traced_test]
        #[test]
        fn varying_values() {
            let (nodes, handles) = setup(17010);

            let shortlist = block_on(RoutingTable::find_alpha_peers(
                nodes[1].node.table.clone(),
                Hash::from(1),
            ));

            // no values
            assert_eq!(
                block_on(
                    nodes[1]
                        .node
                        .clone()
                        .lookup_value(shortlist, None, Hash::from(1), 2)
                ),
                FindValueResult::None,
                "checking when no values"
            );

            // 

            block_on(join_all(handles));
        }
    }
}
