#[cfg(test)]
mod tests {
    use kad::{
        forward::NoFwd,
        node::Kad,
        util::{Kvs, Peer},
    };
    use std::{sync::Arc, time::Duration};
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn serve() {
        let kad = Kad::new::<NoFwd>(16152, false, true).unwrap();
        kad.clone().serve().unwrap();

        std::thread::sleep(Duration::from_secs(1));

        kad.stop::<NoFwd>();
    }

    #[test]
    #[traced_test]
    fn ping() {
        let (kad1, kad2) = (
            Kad::new::<NoFwd>(16150, false, true).unwrap(),
            Kad::new::<NoFwd>(16151, false, true).unwrap(),
        );

        kad1.clone().serve().unwrap();
        kad2.clone().serve().unwrap();

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

        kad1.stop::<NoFwd>();
        kad2.stop::<NoFwd>();
    }

    #[test]
    #[traced_test]
    fn join_put_get() {
        let nodes: Vec<Arc<Kad>> = (0..4)
            .map(|i| Kad::new::<NoFwd>(16000 + i, false, true).unwrap())
            .collect();
        nodes.iter().for_each(|x| x.clone().serve().unwrap());

        for i in &nodes[1..] {
            let a = nodes[0].addr();
            assert!(i.join("127.0.0.1", a.1));
        }

        let res = nodes[0]
            .put("good morning", &String::from("hello"), false)
            .unwrap();

        // make sure all recipients accepted value
        assert!(res.is_empty());

        let res: Kvs<String> = nodes[3].get("good morning", true);
        let val = String::from("hello");

        assert!(!res.is_empty());
        assert!(res
            .iter()
            .fold(res.first(), |acc, item| {
                acc.and_then(|s| {
                    if s == item && item.value == val {
                        Some(s)
                    } else {
                        None
                    }
                })
            })
            .is_some());

        nodes.into_iter().for_each(Kad::stop::<NoFwd>);
    }

    #[test]
    #[traced_test]
    fn put_compressed() {
        let (kad1, kad2) = (
            Kad::new::<NoFwd>(16153, false, true).unwrap(),
            Kad::new::<NoFwd>(16154, false, true).unwrap(),
        );

        kad1.clone().serve().unwrap();
        kad2.clone().serve().unwrap();

        let addr2 = kad2.clone().addr();

        assert!(kad1.join("127.0.0.1", addr2.1));
        assert!(kad1
            .put(
                "hello",
                &String::from("good morning everyone have a nice day"),
                true
            )
            .unwrap()
            .is_empty());

        let res: Kvs<String> = kad1.get("hello", false);

        assert!(!res.is_empty());

        let v = String::from("good morning everyone have a nice day");

        assert_eq!(v, res.first().unwrap().value);

        kad1.stop::<NoFwd>();
        kad2.stop::<NoFwd>();
    }

    #[traced_test]
    #[test]
    fn resolve() {
        let nodes: Vec<Arc<Kad>> = (0..4)
            .map(|i| Kad::new::<NoFwd>(16010 + i, false, true).unwrap())
            .collect();
        nodes.iter().for_each(|x| x.clone().serve().unwrap());

        assert!(nodes[0].join("127.0.0.1", nodes[1].addr().1));
        assert!(nodes[1].join("127.0.0.1", nodes[2].addr().1));
        assert!(nodes[0].join("127.0.0.1", nodes[3].addr().1));

        let res = nodes[1].resolve(nodes[3].id());

        assert!(!res.is_empty());
        assert_eq!(*res.first().unwrap(), nodes[3].addr());

        nodes.into_iter().for_each(Kad::stop::<NoFwd>);
    }
}
