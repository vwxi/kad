# kad

kad is an implementation of a distributed hash table based on the [Kademlia protocol](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf) with features from [S/Kademlia](https://ieeexplore.ieee.org/document/4447808/) 

## usage

```rust
let node = Kad::new(16161, false, true);

if node.join(Addr(IpAddr::from_str("127.0.0.1"), 16162)) {
    if let Ok(missed) = node.put("good morning", "hello", false) {
        assert!(missed.is_empty());
        
        // find value using disjoint lookups
        for values in node.get("good morning", true) {
            debug!("found value {:?}", value);
        }
    }
}

node.stop();
```