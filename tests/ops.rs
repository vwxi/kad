#[cfg(test)]
mod tests {
    use kad::{node::Kad, util::Peer};
    use std::{sync::Arc, time::Duration};
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn serve() {
        let kad = Kad::new(16152, false, true).unwrap();

        std::thread::sleep(Duration::from_secs(1));

        kad.stop();
    }

    #[test]
    #[traced_test]
    fn ping() {
        let (kad1, kad2) = (
            Kad::new(16150, false, true).unwrap(),
            Kad::new(16151, false, true).unwrap(),
        );

        let addr1 = kad1.clone().addr();
        let peer1 = Peer::new(kad1.clone().id(), addr1);

        let addr2 = kad2.clone().addr();
        let peer2 = Peer::new(kad2.clone().id(), addr2);

        {
            let res = kad1.clone().ping(peer2.clone()).unwrap();

            assert_eq!(res.id, peer2.id);
            assert_eq!(res.addr, addr2);
        }

        {
            let res = kad2.clone().ping(peer1.clone()).unwrap();

            assert_eq!(res.id, peer1.id);
            assert_eq!(res.addr, addr1);
        }

        kad1.stop();
        kad2.stop();
    }

    #[test]
    #[traced_test]
    fn join_put_get() {
        let nodes: Vec<Arc<Kad>> = (0..4)
            .map(|i| Kad::new(16010 + i, false, true).unwrap())
            .collect();
        nodes.iter().for_each(|x| x.clone().serve().unwrap());

        for i in &nodes[1..] {
            assert!(i.join(nodes[0].addr()));
        }

        let res = nodes[0].put("good morning", "hello", false).unwrap();

        // make sure all recipients accepted value
        assert!(res.is_empty());

        let res = nodes[3].get("good morning", true);

        assert!(!res.is_empty());
        assert!(res
            .iter()
            .fold(res.first(), |acc, item| {
                acc.and_then(|s| if s == item { Some(s) } else { None })
            })
            .is_some());

        nodes.into_iter().for_each(Kad::stop);
    }
}
