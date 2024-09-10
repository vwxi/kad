use std::{
    collections::VecDeque,
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use futures::{stream::FuturesUnordered, StreamExt};
use tokio::sync::Mutex;
use tracing::debug;

use crate::{
    node::InnerKad,
    routing::{self, consts::ALPHA},
    store::StoreEntry,
    util::{FindValueResult, Hash, Peer, SinglePeer},
};

impl InnerKad {
    // xlattice-style lookup
    pub(crate) fn lookup_nodes(
        self: Arc<Self>,
        mut shortlist: VecDeque<Peer>,
        key: Hash,
    ) -> Vec<Peer> {
        // own id
        let id = self.table.id;
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

        // truncate results
        res.truncate(routing::consts::BUCKET_SIZE);

        res
    }

    async fn send_alpha_calls(
        self: Arc<Self>,
        pn: &mut Vec<Peer>,
        pq: &mut Vec<Hash>,
        claimed: Option<Arc<Mutex<Vec<Hash>>>>,
        pending_count: Arc<AtomicUsize>,
        key: Hash,
    ) -> FuturesUnordered<impl Future<Output = (Option<Box<FindValueResult>>, SinglePeer)>> {
        let tasks = FuturesUnordered::new();
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
                        }

                        // otherwise, add to `claimed` list
                        lock.push(peer.id);
                    }

                    pending_count.fetch_add(1, Ordering::Relaxed);

                    peer = self.table.clone().resolve(peer).await;

                    // spawn new task
                    debug!("querying peer {:#x}", peer.id);

                    let (new_self, new_peer) = (self.clone(), peer.clone());
                    tasks.push(async move {
                        tokio::task::block_in_place(|| match new_self.find_value(new_peer, key) {
                            Ok((result, responding_peer)) => (Some(result), responding_peer),
                            Err(p) => (None, *p),
                        })
                    });

                    // mark as queried in `pq`
                    pq.push(peer.id);
                }
            }
        }

        tasks
    }

    // if without value, add unqueried closest nodes to `pn`
    // ensure node isn't an element of `pq`, `pn` or is self
    fn handle_node_list(
        self: Arc<Self>,
        nodes: &[SinglePeer],
        pn: &mut Vec<Peer>,
        pq: &mut [Hash],
    ) {
        debug!("received bucket, adding unvisited peers...");

        let kad = self.parent.upgrade().unwrap();
        let handle = kad.runtime.handle();

        pn.extend(
            nodes
                .iter()
                .filter(|x| !pq.contains(&x.id) && x.id != self.table.id)
                .map(|x| handle.block_on(self.table.clone().resolve(x.peer()))),
        );
    }

    async fn handle_value(
        self: Arc<Self>,
        peer: SinglePeer,
        value: Box<StoreEntry>,
        best: &mut FindValueResult,
        found_count: Arc<AtomicUsize>,
        pb: &mut Vec<SinglePeer>,
        po: &mut Vec<SinglePeer>,
    ) {
        debug!("received value from {:#x}", peer.id);

        match best {
            // if this is the first value seen,
            // store it in `best` and store peer in `pb`
            FindValueResult::None => {
                debug!("first value, storing in best and pb");
                *best = FindValueResult::Value(value);
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
                            debug!("new value wins, marking peers as outdated");
                            po.append(pb);

                            debug!("clearing pb and inserting new winner");
                            pb.clear();
                            *best = FindValueResult::Value(value);
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

    // libp2p-style value retrieval
    pub(crate) async fn lookup_value(
        self: Arc<Self>,
        mut pn: Vec<Peer>,
        claimed: Option<Arc<Mutex<Vec<Hash>>>>,
        key: Hash,
        quorum: usize,
    ) -> FindValueResult {
        // number of valid values found
        let found_count = Arc::new(AtomicUsize::new(0));
        // pending requests count
        let pending = Arc::new(AtomicUsize::new(0));
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
        {
            if let Some(val) = self.store.get(&key).await {
                if quorum < 2 {
                    debug!("quorum < 2, found value in local store, search is complete");
                    return FindValueResult::Value(Box::new(val));
                }

                // otherwise, we count it as a found value
                found_count.fetch_add(1, Ordering::Relaxed);
                best = FindValueResult::Value(Box::new(val));
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
                debug!("quorum satisfied/no more new nodes, updating outdated nodes");

                if let FindValueResult::Value(ref v) = best {
                    // don't forward entry, let's just store what was acquired
                    let kad = self.parent.upgrade().unwrap();
                    let handle = kad.runtime.handle();

                    for p in &po {
                        debug!("storing best value at {:#x}", p.id);

                        tokio::task::block_in_place(|| {
                            let _ = self.clone().store(
                                handle.block_on(self.table.clone().resolve(p.peer())),
                                key,
                                self.store.forward_entry(*v.clone()),
                            );
                        });
                    }
                }

                return best;
            }

            // otherwise, send `alpha` `pn` peers a find_value call
            let mut tasks = self
                .clone()
                .send_alpha_calls(&mut pn, &mut pq, claimed.clone(), pending.clone(), key)
                .await;

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
                        match *result {
                            FindValueResult::Nodes(nodes) => {
                                tokio::task::block_in_place(|| {
                                    self.clone().handle_node_list(&nodes, &mut pn, &mut pq);
                                });
                            }
                            FindValueResult::Value(value) => {
                                self.clone()
                                    .handle_value(
                                        peer,
                                        value,
                                        &mut best,
                                        found_count.clone(),
                                        &mut pb,
                                        &mut po,
                                    )
                                    .await;
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
        self.lookup_value(portion.clone(), Some(claimed.clone()), key, quorum)
            .await
    }

    pub(crate) async fn disjoint_lookup_value(
        self: Arc<Self>,
        key: Hash,
        disjoint_paths: usize,
        quorum: usize,
    ) -> Vec<FindValueResult> {
        let mut initial: Vec<Peer> = self.table.clone().find_alpha_peers(key).await;
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
            VecDeque::from(self.table.clone().find_alpha_peers(key).await);

        self.lookup_nodes(shortlist, key)
    }
}

// these tests might take much longer because of key generation
#[cfg(test)]
mod tests {
    use crate::{
        forward::NoFwd,
        node::{consts, Kad},
        util::{hash, FindValueResult, Hash, Value},
    };
    use futures::executor::block_on;
    use std::sync::Arc;
    use tracing::debug;
    use tracing_test::traced_test;

    fn setup(offset: u16) -> Vec<Arc<Kad>> {
        let nodes: Vec<Arc<Kad>> = (0..5)
            .map(|i| Kad::new::<NoFwd>(offset + i, false, true).unwrap())
            .collect();
        nodes.iter().for_each(|x| x.clone().serve().unwrap());

        // send find_nodes in this sequence:
        // A -> B
        debug!("A -> B");
        let _ = nodes[0]
            .node
            .clone()
            .find_node(nodes[1].as_peer(), Hash::from(1));
        // A -> C
        debug!("A -> C");
        let _ = nodes[0]
            .node
            .clone()
            .find_node(nodes[2].as_peer(), Hash::from(1));
        // A -> E
        debug!("A -> E");
        let _ = nodes[0]
            .node
            .clone()
            .find_node(nodes[4].as_peer(), Hash::from(1));
        // B -> E
        debug!("B -> E");
        let _ = nodes[1]
            .node
            .clone()
            .find_node(nodes[4].as_peer(), Hash::from(1));
        // D -> A
        debug!("D -> A");
        let _ = nodes[3]
            .node
            .clone()
            .find_node(nodes[0].as_peer(), Hash::from(1));

        nodes
    }

    mod lookup_nodes {
        use super::*;

        #[traced_test]
        #[test]
        fn find_all_nodes() {
            let nodes = setup(17000);

            // call as C to get A, B, D, E
            let res = block_on(nodes[2].node.clone().iter_find_node(Hash::from(1)));

            assert!(!res.is_empty());
            assert!(res.iter().all(|x| x.id == nodes[0].id()
                || x.id == nodes[1].id()
                || x.id == nodes[3].id()
                || x.id == nodes[4].id()));
        }
    }

    mod lookup_value {
        use crate::util::Data;

        use super::*;

        // intersecting lookup with no/one valid value
        #[traced_test]
        #[test]
        fn ixn_single_valid() {
            let nodes = setup(17010);

            {
                let shortlist =
                    block_on(nodes[1].node.table.clone().find_alpha_peers(Hash::from(1)));

                // no values
                assert_eq!(
                    block_on(nodes[1].node.clone().lookup_value(
                        shortlist,
                        None,
                        Hash::from(1),
                        consts::QUORUM
                    )),
                    FindValueResult::None,
                    "checking when no values"
                );
            }

            // one value
            {
                let first_entry = nodes[0]
                    .node
                    .store
                    .create_new_entry(&Value::Data(Data::Raw("hello".into())));

                let _ = nodes[0].node.clone().store(
                    nodes[1].as_peer(),
                    hash("good morning"),
                    first_entry.clone(),
                );

                let shortlist = block_on(
                    nodes[0]
                        .node
                        .table
                        .clone()
                        .find_alpha_peers(hash("good morning")),
                );

                assert_eq!(
                    block_on(nodes[3].node.clone().lookup_value(
                        shortlist,
                        None,
                        hash("good morning"),
                        consts::QUORUM
                    )),
                    FindValueResult::Value(Box::new(first_entry)),
                    "checking when one value from node D"
                );
            }
        }

        // intersecting lookup with two valid values
        #[traced_test]
        #[test]
        fn ixn_two_valid() {
            // two values, one newer than the other
            // D should pick the newer value and A should be updated with the new value
            let nodes = setup(17020);

            // A and B
            let first_entry = nodes[0]
                .node
                .store
                .create_new_entry(&Value::Data(Data::Raw("hello".into())));

            // allow there to be a time difference
            std::thread::sleep(tokio::time::Duration::from_secs(1));

            let second_entry = nodes[1].node.store.republish_entry(first_entry.clone());

            // A -> C
            assert!(block_on(nodes[2].node.store.put(
                nodes[0].as_single_peer(),
                hash("good morning"),
                first_entry.clone(),
            )));

            // B just has value
            assert!(block_on(nodes[1].node.store.put(
                nodes[1].as_single_peer(),
                hash("good morning"),
                second_entry.clone(),
            )));

            // let D search for the best value
            let shortlist = block_on(
                nodes[3]
                    .node
                    .table
                    .clone()
                    .find_alpha_peers(hash("good morning")),
            );

            // see if new value was obtained
            assert_eq!(
                block_on(nodes[3].node.clone().lookup_value(
                    shortlist,
                    None,
                    hash("good morning"),
                    consts::QUORUM
                )),
                FindValueResult::Value(Box::new(second_entry.clone())),
                "checking if the newer of the two values was chosen"
            );

            // see if new value was stored in previous holding nodes
            assert_eq!(
                block_on(nodes[2].node.store.get(&hash("good morning")))
                    .expect("checking if old best peer received new node")
                    .0
                    .timestamp,
                second_entry.0.timestamp,
                "checking if new value was stored in previous node"
            );
        }

        #[traced_test]
        #[test]
        fn ixn_three_valid() {
            // three values, two equal and one newer
            // B and C have equal values, E has newer, search as D
            // make sure B, C get new entry from C and that C's value is the returned
            let nodes = setup(17030);

            // B and C
            let first_entry = nodes[0]
                .node
                .store
                .create_new_entry(&Value::Data(Data::Raw("hello".into())));

            assert!(block_on(nodes[1].node.store.put(
                nodes[0].as_single_peer(),
                hash("good morning"),
                first_entry.clone(),
            )));

            assert!(block_on(nodes[2].node.store.put(
                nodes[0].as_single_peer(),
                hash("good morning"),
                first_entry.clone(),
            )));

            // allow there to be a time difference
            std::thread::sleep(tokio::time::Duration::from_secs(1));

            // E
            let second_entry = nodes[4].node.store.republish_entry(first_entry.clone());
            block_on(nodes[4].node.store.put(
                nodes[4].as_single_peer(),
                hash("good morning"),
                second_entry.clone(),
            ));

            // let D search for the best value
            let shortlist = block_on(
                nodes[3]
                    .node
                    .table
                    .clone()
                    .find_alpha_peers(hash("good morning")),
            );

            // see if new value was obtained
            if let FindValueResult::Value(nv) = block_on(nodes[3].node.clone().lookup_value(
                shortlist,
                None,
                hash("good morning"),
                consts::QUORUM,
            )) {
                assert_eq!(
                    nv.0, second_entry.0,
                    "checking if the newer of the three values was chosen"
                );
            } else {
                panic!("new value was a nodes list");
            }

            // see if new value was stored in previous holding nodes
            assert_eq!(
                block_on(nodes[1].node.store.get(&hash("good morning")))
                    .unwrap()
                    .0,
                second_entry.0,
                "checking if B got new value"
            );

            assert_eq!(
                block_on(nodes[2].node.store.get(&hash("good morning")))
                    .unwrap()
                    .0,
                second_entry.0,
                "checking if C got new value"
            );
        }
    }
}
