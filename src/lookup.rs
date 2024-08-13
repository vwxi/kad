use std::{collections::{HashSet, VecDeque}, sync::Arc};

use tokio::sync::Mutex;

use crate::{node::KadNode, routing::{RoutingTable, ALPHA}, util::{Hash, Peer, SinglePeer}};

impl KadNode {
    async fn lookup_nodes(self: Arc<Self>, mut shortlist: VecDeque<Peer>, target_id: Hash) -> Vec<Peer> {
        let id = self.table.lock().await.id;

        let mut res: Vec<Peer> = vec![];
        let mut visited: Vec<SinglePeer> = vec![];
        let mut candidate: Peer;

        if let Some(mut closest_node) = shortlist.iter().min_by(|x, y| (x.id ^ target_id).cmp(&(y.id ^ target_id))) {
            let first = true;
            
            while !shortlist.is_empty() {
                for _ in 0..ALPHA {
                    if let Some(item) = shortlist.pop_front() {
                        tokio::task::block_in_place(|| {
                            let result = self.clone().find_node(item.clone(), target_id);

                            // visited contains all contacted peers regardless of validity
                            for addr in &item.addresses {
                                visited.push(SinglePeer::new(item.id, addr.0));
                            }

                            // res contains all valid contacted peers
                            if !res.iter().any(|x| x.id == item.id) {
                                res.push(item);
                            }

                            // check if:
                            // - we are about to query ourselves
                            // - we've already visited this specific IP:ID
                            // - we've already added this IP or ID to the shortlist
                            if let Ok(peers) = result {
                                for peer in peers {
                                    if peer.id == id || 
                                        visited.iter().any(|x| x.id == peer.id && x.addr == peer.addr) || 
                                        shortlist.iter().any(|x| x.id == peer.id || x.addresses.iter().any(|y| y.0 == peer.addr)) {
                                            continue
                                        }
                                    
                                    shortlist.push_back(peer.peer());
                                }
                            }

                            
                        });
                    } else {
                        break;
                    }
                }
            }
        }

        res
    }
}