use crate::{
    node::{Kad, KadNode, RealPinger},
    routing::RoutingTable,
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
use tokio::{task::JoinHandle, time::timeout};
use tracing::{debug, error};

pub(crate) const TIMEOUT: u64 = 30;

#[tarpc::service]
pub(crate) trait RpcService {
    async fn key() -> RpcResults;
    async fn ping() -> RpcResults;
    async fn store(args: RpcArgs) -> RpcResults;
    async fn find_node(args: RpcArgs) -> RpcResults;
    async fn find_value(args: RpcArgs) -> RpcResults;
}

#[derive(Clone)]
pub(crate) struct Service {
    pub(crate) client: RpcServiceClient,
    pub(crate) node: Arc<KadNode>,
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
        self.node.crypto.results(RpcResult::Ping)
    }

    async fn store(self, _: context::Context, args: RpcArgs) -> RpcResults {
        if let Err(r) = self.verify(&args).await {
            return r;
        }

        let sender = SinglePeer::new(args.0.id, args.0.addr);

        if let RpcOp::Store(k, v) = args.0.op {
            RoutingTable::update::<RealPinger>(self.node.table.clone(), sender).await;
            
            self.node.crypto.results(if self.node.store.put(sender, k.as_str(), v).await {
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
            let bkt = RoutingTable::find_bucket(self.node.table.clone(), id).await;

            RoutingTable::update::<RealPinger>(self.node.table.clone(), sender).await;

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
            RoutingTable::update::<RealPinger>(self.node.table.clone(), sender).await;

            if let Some(e) = self.node.store.get(&id).await {
                self.node.crypto.results(RpcResult::FindValue(FindValueResult::Value(e)))
            } else {
                let bkt = RoutingTable::find_bucket(self.node.table.clone(), id).await;
                self.node.crypto.results(RpcResult::FindValue(FindValueResult::Nodes(bkt)))
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
                .inspect_ok(|_| {})
                .inspect_err(|e| error!("outbound message handle error: {}", e)),
        );

        (server_, client_)
    }

    async fn serve(node_: Arc<KadNode>) -> std::io::Result<JoinHandle<()>> {
        let addr = node_.addr;

        match tarpc::serde_transport::tcp::listen(&addr, Json::default).await {
            Ok(mut listener) => Ok(tokio::spawn(async move {
                listener.config_mut().max_frame_length(usize::MAX);

                debug!("now listening for calls at {:?}:{}", addr.0, addr.1);

                listener
                    .filter_map(|r| future::ready(r.ok()))
                    .map(|i| {
                        let peer_addr = i.peer_addr().unwrap();
                        let (srv, clt) = Self::spawn_twoway(i);
                        let service = Service {
                            client: RpcServiceClient::new(client::Config::default(), clt).spawn(),
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
                    .for_each(|_| async {})
                    .await;
            })),
            Err(err) => Err(err)
        }
    }

    async fn connect(kad: Arc<Kad>, addr: Addr) -> Result<Service, Box<dyn Error>> {
        let mut transport = tarpc::serde_transport::tcp::connect(&addr, Json::default);
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
                        Duration::from_secs(TIMEOUT),
                        Self::connect(kad.clone(), current.0),
                    )
                    .await
                    {
                        break Some(service);
                    } else {
                        addr.next();
                    }
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
    use crate::{
        node::{Kad, KadNode, ResponsiveMockPinger}, routing::{RoutingTable, BUCKET_SIZE}, store::Value, util::{generate_peer, hash, Hash, Peer}
    };
    use futures::executor::block_on;
    use rsa::pkcs1::EncodeRsaPublicKey;
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn key() {
        let (first, second) = (Kad::new(16161, false, true), Kad::new(16162, false, true));
        let (handle1, handle2) = (first.clone().serve().unwrap(), second.clone().serve().unwrap());

        let second_addr = second.clone().addr();
        let second_peer = Peer::new(second.clone().id(), second_addr);

        let _ = KadNode::key(first.node.clone(), second_peer.clone()).unwrap();

        let keyring = first.node.crypto.keyring.blocking_read();

        let result = keyring
            .get(&second_peer.id)
            .unwrap()
            .0
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .unwrap();

        assert_eq!(result, second.node.crypto.public_key_as_string().unwrap());

        handle1.abort();
        handle2.abort();
    }

    #[traced_test]
    #[test]
    fn store() {
        let (first, second) = (Kad::new(16163, false, true), Kad::new(16164, false, true));
        let (handle1, handle2) = (first.clone().serve().unwrap(), second.clone().serve().unwrap());

        let second_addr = second.clone().addr();
        let second_peer = Peer::new(second.clone().id(), second_addr);

        let entry = first.node.store.create_new_entry(Value::Data(String::from("hello")));

        assert!(KadNode::store(first.node.clone(), second_peer.clone(), String::from("good morning"), entry).unwrap());
        assert!(block_on(second.node.store.get(&hash("good morning"))).is_some());

        handle1.abort();
        handle2.abort();
    }

    #[traced_test]
    #[test]
    fn find_node() {
        let (first, second) = (Kad::new(16165, false, true), Kad::new(16166, false, true));
        let (handle1, handle2) = (first.clone().serve().unwrap(), second.clone().serve().unwrap());

        let to_find = Hash::from(1);

        let second_addr = second.clone().addr();
        let second_peer = Peer::new(second.clone().id(), second_addr);

        for i in 0..(BUCKET_SIZE - 1) {
            block_on(RoutingTable::update::<ResponsiveMockPinger>(
                second.node.table.clone(),
                generate_peer(Some(Hash::from(i))),
            ));
        }

        let reference = block_on(RoutingTable::find_bucket(
            second.node.table.clone(),
            to_find,
        ));

        assert!(!reference.is_empty());

        let res = KadNode::find_node(first.node.clone(), second_peer.clone(), to_find).unwrap();

        assert!(!res.is_empty());
        assert!(reference.iter().zip(res.iter()).all(|(x, y)| x.id == y.id));

        handle1.abort();
        handle2.abort();
    }
}
