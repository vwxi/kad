#[cfg(test)]
mod tests {
    use kad::{node::Kad, util::Peer};
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn serve() {
        let kad = Kad::new(16161, false, true);
        let handle = kad.serve();

        handle.abort();
    }

    #[test]
    #[traced_test]
    fn ping() {
        let (kad1, kad2) = (Kad::new(16161, false, true), Kad::new(16162, false, true));
        let (handle1, handle2) = (kad1.clone().serve(), kad2.clone().serve());

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

        handle1.abort();
        handle2.abort();
    }
}
