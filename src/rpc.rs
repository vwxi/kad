use crate::{
    node::{InnerKad, Kad, RealPinger},
    util::{Addr, FindValueResult, Peer, RpcArgs, RpcOp, RpcResult, RpcResults, SinglePeer},
};
use async_trait::async_trait;
use futures::{
    future::{AbortHandle, Abortable},
    prelude::*,
};
use serde::{Deserialize, Serialize};
use std::{error::Error, net::SocketAddr, sync::Arc, time::Duration};
use tarpc::{
    client, context,
    server::{BaseChannel, Channel},
    tokio_serde::formats::Json,
    transport::channel::{ChannelError, UnboundedChannel},
};
use tokio::time::timeout;
use tracing::{debug, error};

pub(crate) mod consts {
    pub(super) const TIMEOUT: u64 = 30;
}

#[tarpc::service]
pub(crate) trait RpcService {
    async fn key() -> RpcResults;
    async fn ping() -> RpcResults;
    async fn get_addresses(args: RpcArgs) -> RpcResults;
    async fn store(args: RpcArgs) -> RpcResults;
    async fn find_node(args: RpcArgs) -> RpcResults;
    async fn find_value(args: RpcArgs) -> RpcResults;
}

#[derive(Clone)]
pub(crate) struct Service {
    pub(crate) client: RpcServiceClient,
    pub(crate) node: Arc<InnerKad>,
    pub(crate) addr: SocketAddr,
}

// hacky
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum RpcMessage<Req, Resp> {
    Request(Req),
    Response(Resp),
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum RpcError {
    ChannelError(ChannelError),
    IOError(std::io::Error),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RpcError::ChannelError(e) => write!(f, "{}", e.to_string().as_str()),
            RpcError::IOError(e) => write!(f, "{}", e.to_string().as_str()),
        }
    }
}

impl From<ChannelError> for RpcError {
    fn from(e: ChannelError) -> RpcError {
        RpcError::ChannelError(e)
    }
}

impl From<std::io::Error> for RpcError {
    fn from(e: std::io::Error) -> RpcError {
        RpcError::IOError(e)
    }
}

impl Service {
    // get_addresses, find_node, find_value and store will have a two-step arg validation
    pub(crate) async fn verify(&self, args: &RpcArgs) -> Result<(), RpcResults> {
        if self
            .node
            .crypto
            .verify_args(args, || async {
                if let Ok((RpcResult::Key(key), _)) = self.client.key(context::current()).await {
                    self.node.crypto.entry(args.0.id, key.as_str()).await;
                }
            })
            .await
        {
            Ok(())
        } else {
            Err(self.node.crypto.results(RpcResult::Bad))
        }
    }
}

impl RpcService for Service {
    async fn key(self, _: context::Context) -> RpcResults {
        self.node
            .crypto
            .results(if let Ok(k) = self.node.crypto.public_key_as_string() {
                RpcResult::Key(k)
            } else {
                RpcResult::Bad
            })
    }

    // pings are not identification. we're just seeing if we speak the same language
    async fn ping(self, _: context::Context) -> RpcResults {
        self.node
            .crypto
            .results(RpcResult::Ping(self.node.table.id))
    }

    // get_addresses will NOT verify any args and will NOT return any signature
    async fn get_addresses(self, _: context::Context, args: RpcArgs) -> RpcResults {
        (
            if let RpcOp::GetAddresses(id) = args.0.op {
                RpcResult::GetAddresses(
                    if let Some(peer) = self.node.table.clone().find(id).await {
                        Some(peer.addresses.iter().map(|a| a.0).collect())
                    } else {
                        None
                    },
                )
            } else {
                RpcResult::Bad
            },
            String::new(),
        )
    }

    async fn store(self, _: context::Context, args: RpcArgs) -> RpcResults {
        if let Err(r) = self.verify(&args).await {
            return r;
        }

        let sender = SinglePeer::new(args.0.id, args.0.addr);

        if let RpcOp::Store(k, v) = args.0.op {
            self.node.table.clone().update::<RealPinger>(sender).await;

            self.node
                .crypto
                .results(if self.node.store.put(sender, k, *v).await {
                    RpcResult::Store
                } else {
                    RpcResult::Bad
                })
        } else {
            self.node.crypto.results(RpcResult::Bad)
        }
    }

    async fn find_node(self, _: context::Context, args: RpcArgs) -> RpcResults {
        if let Err(r) = self.verify(&args).await {
            return r;
        }

        let sender = SinglePeer::new(args.0.id, args.0.addr);

        if let RpcOp::FindNode(id) = args.0.op {
            let bkt = self.node.table.clone().find_bucket(id).await;

            self.node.table.clone().update::<RealPinger>(sender).await;

            self.node.crypto.results(RpcResult::FindNode(bkt))
        } else {
            self.node.crypto.results(RpcResult::Bad)
        }
    }

    async fn find_value(self, _: context::Context, args: RpcArgs) -> RpcResults {
        if let Err(r) = self.verify(&args).await {
            return r;
        }

        let sender = SinglePeer::new(args.0.id, args.0.addr);

        if let RpcOp::FindValue(id) = args.0.op {
            self.node.table.clone().update::<RealPinger>(sender).await;

            if let Some(e) = self.node.store.get(&id).await {
                self.node
                    .crypto
                    .results(RpcResult::FindValue(Box::new(FindValueResult::Value(
                        Box::new(e),
                    ))))
            } else {
                let bkt = self.node.table.clone().find_bucket(id).await;
                self.node
                    .crypto
                    .results(RpcResult::FindValue(Box::new(FindValueResult::Nodes(bkt))))
            }
        } else {
            self.node.crypto.results(RpcResult::Bad)
        }
    }
}

type TwoWay<Req1, Resp1, Req2, Resp2> =
    (UnboundedChannel<Req1, Resp1>, UnboundedChannel<Resp2, Req2>);

#[async_trait]
pub(crate) trait Network {
    // the two-way RPC code is derived from https://github.com/google/tarpc/issues/300#issuecomment-617599457
    fn spawn_twoway<Req1, Resp1, Req2, Resp2, T>(transport: T) -> TwoWay<Req1, Resp1, Req2, Resp2>
    where
        T: Stream<Item = std::io::Result<RpcMessage<Req1, Resp2>>>,
        T: Sink<RpcMessage<Req2, Resp1>, Error = std::io::Error>,
        T: Unpin + Send + 'static,
        Req1: Send + 'static,
        Resp1: Send + 'static,
        Req2: Send + 'static,
        Resp2: Send + 'static,
    {
        let (server, server_) = tarpc::transport::channel::unbounded();
        let (client, client_) = tarpc::transport::channel::unbounded();
        let (mut server_sink, server_stream) = server.split();
        let (mut client_sink, client_stream) = client.split();
        let (transport_sink, mut transport_stream) = transport.split();
        let (abort_handle, abort_registration) = AbortHandle::new_pair();

        // receiving task
        tokio::spawn(async move {
            let e: Result<(), RpcError> = async move {
                while let Some(m) = transport_stream.next().await {
                    match m? {
                        RpcMessage::Request(req) => server_sink.send(req).await?,
                        RpcMessage::Response(resp) => client_sink.send(resp).await?,
                    }
                }
                Ok(())
            }
            .await;

            if let Err(e) = e {
                error!("failed to forward messages to server: {}", e);
            }

            abort_handle.abort();
        });

        // sending task
        let channel = Abortable::new(
            futures::stream::select(
                server_stream.map_ok(RpcMessage::Response),
                client_stream.map_ok(RpcMessage::Request),
            )
            .map_err(RpcError::ChannelError),
            abort_registration,
        );

        tokio::spawn(
            channel
                .forward(transport_sink.sink_map_err(RpcError::IOError))
                .inspect_ok(|()| {})
                .inspect_err(|e| error!("outbound message handle error: {}", e)),
        );

        (server_, client_)
    }

    async fn serve(node_: Arc<InnerKad>) -> std::io::Result<tokio::task::AbortHandle> {
        let addr = node_.addr;
        let kad = node_.parent.upgrade().unwrap();

        match tarpc::serde_transport::tcp::listen(&addr.to(), Json::default).await {
            Ok(mut listener) => Ok(kad
                .runtime
                .spawn(async move {
                    listener.config_mut().max_frame_length(usize::MAX);

                    debug!("now listening for calls at {:?}", addr);

                    listener
                        .filter_map(|r| future::ready(r.ok()))
                        .map(|i| {
                            let peer_addr = i.peer_addr().unwrap();
                            let (srv, clt) = Self::spawn_twoway(i);
                            let service = Service {
                                client: RpcServiceClient::new(client::Config::default(), clt)
                                    .spawn(),
                                node: node_.clone(),
                                addr: peer_addr,
                            };

                            BaseChannel::with_defaults(srv)
                                .execute(service.serve())
                                .for_each(|resp| async move {
                                    tokio::spawn(resp);
                                })
                        })
                        .buffer_unordered(10)
                        .for_each(|()| async {})
                        .await;
                })
                .abort_handle()),
            Err(err) => Err(err),
        }
    }

    async fn connect(kad: Arc<Kad>, addr: Addr) -> Result<Service, Box<dyn Error>> {
        let to = addr.to();
        let mut transport = tarpc::serde_transport::tcp::connect(&to, Json::default);
        transport.config_mut().max_frame_length(usize::MAX);

        let i = transport.await?;
        let peer_addr = i.peer_addr().unwrap();
        let (srv, clt) = Self::spawn_twoway(i);
        let service = Service {
            client: RpcServiceClient::new(client::Config::default(), clt).spawn(),
            node: kad.node.clone(),
            addr: peer_addr,
        };

        tokio::spawn(
            BaseChannel::with_defaults(srv)
                .execute(service.clone().serve())
                .for_each(|resp| async move {
                    tokio::spawn(resp);
                }),
        );

        Ok(service)
    }

    async fn connect_peer(kad: Arc<Kad>, peer: Peer) -> Result<(Service, SinglePeer), SinglePeer> {
        let mut addr = peer.addresses.iter().peekable();

        let mut last_addr = addr.peek().unwrap().0;

        let connection: Option<Service> = loop {
            match addr.peek() {
                Some(current) => {
                    last_addr = current.0;

                    if let Ok(Ok(service)) = timeout(
                        Duration::from_secs(consts::TIMEOUT),
                        Self::connect(kad.clone(), current.0),
                    )
                    .await
                    {
                        break Some(service);
                    }

                    addr.next();
                }
                None => break None,
            }
        };

        let single_peer = SinglePeer {
            id: peer.id,
            addr: last_addr,
        };

        if let Some(conn) = connection {
            Ok((conn, single_peer))
        } else {
            Err(single_peer)
        }
    }
}

#[derive(Default)]
pub(crate) struct KadNetwork {}
impl Network for KadNetwork {}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::{
        node::{Kad, ResponsiveMockPinger},
        routing::consts::BUCKET_SIZE,
        store::{Data, Value},
        util::{generate_peer, hash, Addr, FindValueResult, Hash, Peer, SinglePeer},
    };
    use futures::executor::block_on;
    use rsa::pkcs1::EncodeRsaPublicKey;
    use tracing::debug;
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn key() {
        let (first, second) = (
            Kad::new(16161, false, true).unwrap(),
            Kad::new(16162, false, true).unwrap(),
        );

        first.clone().serve().unwrap();
        second.clone().serve().unwrap();

        let second_addr = second.clone().addr();
        let second_peer = Peer::new(second.clone().id(), second_addr);

        let _ = first.node.clone().key(second_peer.clone()).unwrap();

        let binding = first.clone();
        let keyring = binding.node.crypto.keyring.blocking_read();

        let result = keyring
            .get(&second_peer.id)
            .unwrap()
            .0
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .unwrap();

        assert_eq!(result, second.node.crypto.public_key_as_string().unwrap());

        first.stop();
        second.stop();
    }

    #[traced_test]
    #[test]
    fn get_addresses() {
        let (first, second) = (
            Kad::new(16163, false, true).unwrap(),
            Kad::new(16164, false, true).unwrap(),
        );

        first.clone().serve().unwrap();
        second.clone().serve().unwrap();

        let second_addr = second.clone().addr();
        let second_peer = Peer::new(second.clone().id(), second_addr);

        // add addresses
        for i in 0..=3 {
            debug!("adding {}", 8000 + i);
            block_on(
                second
                    .node
                    .table
                    .clone()
                    .update::<ResponsiveMockPinger>(SinglePeer::new(
                        Hash::from(1),
                        Addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 8000 + i),
                    )),
            );
        }

        let reference = block_on(second.node.table.clone().find(Hash::from(1))).unwrap();

        let res = first
            .node
            .clone()
            .get_addresses(second_peer, Hash::from(1))
            .unwrap()
            .0;

        assert_eq!(reference.addresses.len(), 4);
        assert_eq!(res.len(), 4);
        assert!(reference.addresses.iter().zip(res).all(|(x, y)| x.0 == y));

        first.stop();
        second.stop();
    }

    #[traced_test]
    #[test]
    fn store() {
        let (first, second) = (
            Kad::new(16165, false, true).unwrap(),
            Kad::new(16166, false, true).unwrap(),
        );

        first.clone().serve().unwrap();
        second.clone().serve().unwrap();

        let second_addr = second.clone().addr();
        let second_peer = Peer::new(second.clone().id(), second_addr);

        let entry = first
            .node
            .store
            .create_new_entry(&Value::Data(Data::Raw(String::from("hello"))));

        assert!(
            first
                .node
                .clone()
                .store(second_peer.clone(), hash("good morning"), entry)
                .unwrap()
                .0
        );

        assert!(block_on(second.node.store.get(&hash("good morning"))).is_some());

        first.stop();
        second.stop();
    }

    #[traced_test]
    #[test]
    fn find_node() {
        let (first, second) = (
            Kad::new(16167, false, true).unwrap(),
            Kad::new(16168, false, true).unwrap(),
        );

        first.clone().serve().unwrap();
        second.clone().serve().unwrap();

        let to_find = Hash::from(1);

        let second_addr = second.clone().addr();
        let second_peer = Peer::new(second.clone().id(), second_addr);

        for i in 0..(BUCKET_SIZE - 1) {
            block_on(
                second
                    .node
                    .table
                    .clone()
                    .update::<ResponsiveMockPinger>(generate_peer(Some(Hash::from(i)))),
            );
        }

        let reference = block_on(second.node.table.clone().find_bucket(to_find));

        assert!(!reference.is_empty());

        let res = first
            .node
            .clone()
            .find_node(second_peer.clone(), to_find)
            .unwrap()
            .0;

        assert!(!res.is_empty());
        assert!(reference.iter().zip(res.iter()).all(|(x, y)| x.id == y.id));

        first.stop();
        second.stop();
    }

    #[traced_test]
    #[test]
    fn find_value() {
        let (first, second) = (
            Kad::new(16169, false, true).unwrap(),
            Kad::new(16170, false, true).unwrap(),
        );
        first.clone().serve().unwrap();
        second.clone().serve().unwrap();

        let second_addr = second.clone().addr();
        let second_peer = Peer::new(second.clone().id(), second_addr);

        // fill second node with random entries
        for i in 0..(BUCKET_SIZE - 1) {
            block_on(
                second
                    .node
                    .table
                    .clone()
                    .update::<ResponsiveMockPinger>(generate_peer(Some(Hash::from(i)))),
            );
        }

        // store a value in second node
        let entry = first
            .node
            .store
            .create_new_entry(&Value::Data(Data::Raw(String::from("hello"))));

        assert!(
            first
                .node
                .clone()
                .store(second_peer.clone(), hash("good morning"), entry)
                .unwrap()
                .0,
            "check if store was successful"
        );

        // request existing value from node
        assert!(
            if let FindValueResult::Value(v) = *first
                .node
                .clone()
                .find_value(second_peer.clone(), hash("good morning"))
                .unwrap()
                .0
            {
                block_on(first.node.store.validate(&first.as_single_peer(), &v))
            } else {
                false
            },
            "check if value exists in stored node"
        );

        // request nonexisting value from node
        let res = first
            .node
            .clone()
            .find_value(second_peer.clone(), hash("good AFTERNOON"))
            .unwrap()
            .0;

        if let FindValueResult::Nodes(n) = *res {
            let reference = block_on(
                second
                    .node
                    .table
                    .clone()
                    .find_bucket(hash("good AFTERNOON")),
            );

            assert!(!reference.is_empty(), "check if local bucket is not empty");
            assert!(!n.is_empty(), "check if obtained bucket is not empty");
            assert!(
                reference.iter().zip(n.iter()).all(|(x, y)| x.id == y.id),
                "check if obtained bucket matches local bucket"
            );
        } else {
            panic!("not a list of nodes");
        }

        first.stop();
        second.stop();
    }
}
