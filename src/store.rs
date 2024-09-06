use crate::{
    node::InnerKad,
    util::{timestamp, Data, Entry, Hash, ProviderRecord, SinglePeer, Value},
};
use futures::Future;
use std::{collections::HashMap, sync::Weak};
use tokio::sync::RwLock;

pub(crate) mod consts {
    pub(crate) const MAX_ENTRY_SIZE: usize = 65535;

    crate::util::pred_block! {
        #[cfg(test)] {
            pub(crate) const REPUBLISH_TIME: u64 = 3;
            pub(crate) const REPUBLISH_INTERVAL: usize = 3;
        }

        #[cfg(not(test))] {
            pub(crate) const REPUBLISH_TIME: u64 = 86400;
            pub(crate) const REPUBLISH_INTERVAL: usize = 86400;
        }
    }
}

pub(crate) type StoreEntry = (Entry, String);

// key-value store
pub(crate) struct Store {
    pub(crate) store: RwLock<HashMap<Hash, StoreEntry>>,
    node: Weak<InnerKad>,
}

// TODO: store value compression
impl Store {
    pub(crate) fn new(node_: Weak<InnerKad>) -> Self {
        Store {
            store: RwLock::new(HashMap::new()),
            node: node_,
        }
    }

    // create a new entry. use when publishing new entries
    pub(crate) fn create_new_entry(&self, data: &Value) -> StoreEntry {
        let node = self.node.upgrade().unwrap();
        let kad = node.parent.upgrade().unwrap();

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
    pub(crate) fn republish_entry(&self, mut entry: StoreEntry) -> StoreEntry {
        entry.0.timestamp = timestamp();

        let node = self.node.upgrade().unwrap();

        let signature = node
            .crypto
            .sign(serde_json::to_string(&entry.0).unwrap().as_str());

        (entry.0, signature)
    }

    pub(crate) fn forward_entry(&self, entry: StoreEntry) -> StoreEntry {
        let node = self.node.upgrade().unwrap();

        let signature = node
            .crypto
            .sign(serde_json::to_string(&entry.0).unwrap().as_str());

        (entry.0, signature)
    }

    pub(crate) async fn validate(&self, sender: &SinglePeer, entry: &StoreEntry) -> bool {
        let node = self.node.upgrade().unwrap();

        // check if data is larger than maximum accepted size
        if let Value::Data(s) = &entry.0.value {
            match s {
                Data::Raw(st) | Data::Compressed(st) => {
                    if st.len() > consts::MAX_ENTRY_SIZE {
                        return false;
                    }
                }
            }
        }

        // determine if origin key exists in keyring,
        if node
            .crypto
            .if_unknown(
                &entry.0.origin.id,
                || async { InnerKad::key(node.clone(), entry.0.origin.peer()).is_ok() },
                || false,
            )
            .await
        {
            // return if unable to acquire
            return false;
        }

        // determine if sender key exists in keyring,
        if node
            .crypto
            .if_unknown(
                &sender.id,
                || async { InnerKad::key(node.clone(), sender.peer()).is_ok() },
                || false,
            )
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
        if ts - entry.0.timestamp > consts::REPUBLISH_TIME {
            return false;
        }

        // if provider record, check if expiry has not passed
        if let Value::ProviderRecord(ProviderRecord { expiry: e, .. }) = entry.0.value {
            if ts > e {
                return false;
            }
        }

        true
    }

    pub(crate) async fn put(&self, sender: SinglePeer, key: Hash, entry: StoreEntry) -> bool {
        if !self.validate(&sender, &entry).await {
            return false;
        }

        // add to hash table
        let mut lock = self.store.write().await;

        lock.insert(key, entry);

        true
    }

    // get does not re-sign entry, re-signing is for republishing only
    pub(crate) async fn get(&self, key: &Hash) -> Option<StoreEntry> {
        let lock = self.store.read().await;
        lock.get(key).cloned()
    }

    // iterate through store and return all entries that need to be updated
    pub(crate) async fn for_all<F, Fut>(&self, f: F) -> Vec<(Hash, StoreEntry)>
    where
        Fut: Future<Output = Option<(Hash, StoreEntry)>>,
        F: Fn(Hash, StoreEntry) -> Fut,
    {
        let lock = self.store.read().await;
        let mut to_put: Vec<(Hash, StoreEntry)> = vec![];

        for entry in lock.iter() {
            if let Some(e) = f(*entry.0, entry.1.clone()).await {
                to_put.push(e);
            }
        }

        to_put
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;
    use tracing_test::traced_test;

    use crate::{
        node::Kad,
        store::{consts::REPUBLISH_TIME, Data, ProviderRecord, Value},
        util::{hash, timestamp, Hash},
    };

    #[traced_test]
    #[test]
    fn store_valid_data() {
        let kad = Kad::new(16161, false, true).unwrap();
        let entry = kad
            .node
            .store
            .create_new_entry(&Value::Data(Data::Raw("hello".into())));

        assert!(block_on(kad.node.store.put(
            kad.as_single_peer(),
            hash("good morning"),
            entry
        )));
    }

    #[traced_test]
    #[test]
    fn store_invalid_data() {
        // bad signatures
        let kad = Kad::new(16161, false, true).unwrap();
        let mut entry = kad
            .node
            .store
            .create_new_entry(&Value::Data(Data::Raw("hello".into())));

        entry.0.signature = String::from("wlefplwefplwef");
        entry.1 = String::from("wefwefwef");

        assert!(!block_on(kad.node.store.put(
            kad.as_single_peer(),
            hash("good morning"),
            entry
        )));

        // bad timestamp
        let mut entry = kad
            .node
            .store
            .create_new_entry(&Value::Data(Data::Raw("hello".into())));

        entry.0.timestamp += REPUBLISH_TIME + 1;

        assert!(!block_on(kad.node.store.put(
            kad.as_single_peer(),
            hash("good morning"),
            entry
        )));

        // bad
        let entry = kad
            .node
            .store
            .create_new_entry(&Value::ProviderRecord(ProviderRecord {
                provider: Hash::from(1),
                expiry: timestamp() - REPUBLISH_TIME,
            }));

        assert!(!block_on(kad.node.store.put(
            kad.as_single_peer(),
            hash("good morning"),
            entry
        )));
    }
}
