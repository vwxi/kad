use crate::{
    node::KadNode,
    util::{hash, timestamp, Hash, SinglePeer},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Weak};
use tokio::sync::RwLock;

crate::util::pred_block! {
    #[cfg(test)] {
        pub(crate) const REPUBLISH_TIME: u64 = 10;
        pub(crate) const REPUBLISH_INTERVAL: usize = 10;
    }

    #[cfg(not(test))] {
        pub(crate) const REPUBLISH_TIME: u64 = 86400;
        pub(crate) const REPUBLISH_INTERVAL: usize = 86400;
    }

    #[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)] {
        pub(crate) struct ProviderRecord {
            pub(crate) provider: Hash,
            pub(crate) expiry: u64,
        }

        pub(crate) enum Value {
            Data(String),
            ProviderRecord(ProviderRecord),
        }

        pub(crate) struct Entry {
            pub(crate) value: Value,
            pub(crate) signature: String,
            pub(crate) origin: SinglePeer,
            pub(crate) timestamp: u64,
        }
    }
}

pub(crate) type StoreEntry = (Entry, String);

// key-value store
pub(crate) struct Store {
    pub(crate) store: RwLock<HashMap<Hash, StoreEntry>>,
    node: Weak<KadNode>,
}

impl Store {
    pub(crate) fn new(node_: Weak<KadNode>) -> Self {
        Store {
            store: RwLock::new(HashMap::new()),
            node: node_,
        }
    }

    // create a new entry. use when publishing new entries
    pub(crate) fn create_new_entry(&self, data: Value) -> StoreEntry {
        let node = self.node.upgrade().unwrap();
        let kad = node.kad.upgrade().unwrap();

        let entry = Entry {
            value: data.clone(),
            signature: node
                .crypto
                .sign(serde_json::to_string(&data).unwrap().as_str()),
            origin: kad.as_single_peer(),
            timestamp: timestamp(),
        };

        let signature = node
            .crypto
            .sign(serde_json::to_string(&entry).unwrap().as_str());

        (entry, signature)
    }

    // update existing entry, sign it using own key. use when republishing entries
    pub(crate) fn forward_entry(&self, mut entry: StoreEntry) -> StoreEntry {
        entry.0.timestamp = timestamp();

        let node = self.node.upgrade().unwrap();

        let signature = node
            .crypto
            .sign(serde_json::to_string(&entry.0).unwrap().as_str());

        (entry.0, signature)
    }

    pub(crate) async fn validate(&self, sender: &SinglePeer, entry: &StoreEntry) -> bool {
        let node = self.node.upgrade().unwrap();

        // determine if origin key exists in keyring,
        if node
            .crypto
            .if_unknown(&entry.0.origin.id, || async {
                KadNode::key(node.clone(), entry.0.origin.peer()).is_ok()
            })
            .await
        {
            // return if unable to acquire
            return false;
        }

        // determine if sender key exists in keyring,
        if node
            .crypto
            .if_unknown(&sender.id, || async {
                KadNode::key(node.clone(), sender.peer()).is_ok()
            })
            .await
        {
            // return if unable to acquire
            return false;
        }

        // check if sender signed entry
        if !node
            .crypto
            .verify(
                &sender.id,
                serde_json::to_string(&entry.0).unwrap().as_str(),
                entry.1.as_str(),
            )
            .await
        {
            return false;
        }

        // check if origin signed data
        if !node
            .crypto
            .verify(
                &entry.0.origin.id,
                serde_json::to_string(&entry.0.value).unwrap().as_str(),
                entry.0.signature.as_str(),
            )
            .await
        {
            return false;
        }

        let ts = timestamp();

        // check if entry timestamp is not older than allowed time
        if ts - entry.0.timestamp > REPUBLISH_TIME {
            return false;
        }

        // if provider record, check if expiry has not passed
        if let Value::ProviderRecord(ProviderRecord {
            provider: _,
            expiry: e,
        }) = entry.0.value
        {
            if ts > e {
                return false;
            }
        }

        true
    }

    pub(crate) async fn put(&self, sender: SinglePeer, key: &str, entry: StoreEntry) -> bool {
        if !self.validate(&sender, &entry).await {
            return false;
        }

        // add to hash table
        let mut lock = self.store.write().await;
        lock.insert(hash(key), entry);

        true
    }

    // get will re-sign the outer Entry object with its own key
    pub(crate) async fn get(&self, key: &Hash) -> Option<StoreEntry> {
        let lock = self.store.read().await;

        lock.get(key).map(|entry| self.forward_entry(entry.clone()))
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;
    use tracing_test::traced_test;

    use crate::{
        node::Kad,
        store::{ProviderRecord, Value, REPUBLISH_TIME},
        util::{timestamp, Hash},
    };

    #[traced_test]
    #[test]
    fn store_valid_data() {
        let kad = Kad::new(16161, false, true);
        let entry = kad
            .node
            .store
            .create_new_entry(Value::Data(String::from("hello")));

        assert!(block_on(kad.node.store.put(
            kad.as_single_peer(),
            "good morning",
            entry
        )));
    }

    #[traced_test]
    #[test]
    fn store_invalid_data() {
        // bad signatures
        let kad = Kad::new(16161, false, true);
        let mut entry = kad
            .node
            .store
            .create_new_entry(Value::Data(String::from("hello")));

        entry.0.signature = String::from("wlefplwefplwef");
        entry.1 = String::from("wefwefwef");

        assert!(!block_on(kad.node.store.put(
            kad.as_single_peer(),
            "good morning",
            entry
        )));

        // bad timestamp
        let mut entry = kad
            .node
            .store
            .create_new_entry(Value::Data(String::from("hello")));

        entry.0.timestamp += REPUBLISH_TIME + 1;

        assert!(!block_on(kad.node.store.put(
            kad.as_single_peer(),
            "good morning",
            entry
        )));

        // bad
        let entry = kad
            .node
            .store
            .create_new_entry(Value::ProviderRecord(ProviderRecord {
                provider: Hash::from(1),
                expiry: timestamp() - REPUBLISH_TIME,
            }));

        assert!(!block_on(kad.node.store.put(
            kad.as_single_peer(),
            "good morning",
            entry
        )));
    }
}
