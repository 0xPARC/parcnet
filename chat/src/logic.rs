use std::{
    net::{Ipv4Addr, SocketAddrV4},
    str::FromStr,
    sync::{Arc, RwLock},
};

use bytes::Bytes;
use futures::StreamExt;
use iroh_base::key::SecretKey;
use iroh_gossip::{
    net::{Event, Gossip, GossipEvent, GossipReceiver, GossipSender},
    proto::TopicId,
};
use iroh_net::{discovery::Discovery, key::PublicKey, relay::RelayMode, Endpoint, NodeAddr};
use tokio::sync::{watch, Mutex};
use tracing::warn;

pub struct Logic {
    latest_message: Arc<RwLock<String>>,
    message_watch: (watch::Sender<()>, watch::Receiver<()>),
    message_sender: Arc<Mutex<Option<GossipSender>>>,
}

const GOSSIP_ALPN: &[u8] = b"/iroh-gossip/0";
const TOPIC_ID: &str = "nontdllkgf7b77fvdns3bbrer7qlmqqbqt4jwgwaq6vd3anp3euq";
// Need to know about at least one peer to join the network
const PEER_ID: &str = "fhozrkei6mgiqqfcfpq4xzfk6zdcnv2onp77xhoer7wblpcokgeq";

async fn endpoint_loop(endpoint: Endpoint, gossip: Gossip) {
    while let Some(incoming) = endpoint.accept().await {
        let conn = match incoming.accept() {
            Ok(conn) => conn,
            Err(err) => {
                warn!("incoming connection failed: {err:#}");
                // We can carry on in these cases:
                // This can be caused by retransmitted datagrams
                continue;
            }
        };
        let gossip = gossip.clone();
        tokio::spawn(async move { handle_connection(conn, gossip).await });
    }
}

async fn handle_connection(mut conn: iroh_net::endpoint::Connecting, gossip: Gossip) {
    let alpn = conn.alpn().await.unwrap();
    let conn = conn.await.unwrap();
    let peer_id = iroh_net::endpoint::get_remote_node_id(&conn).unwrap();
    match alpn.as_ref() {
        GOSSIP_ALPN => gossip.handle_connection(conn).await.unwrap(),
        _ => println!("> ignoring connection from {peer_id}: unsupported ALPN protocol"),
    }
}

async fn connect_topic(topic_id: TopicId, peer: NodeAddr) -> (GossipSender, GossipReceiver) {
    let secret_key = SecretKey::generate();
    let relay_mode = RelayMode::Default;
    let builder = iroh_net::discovery::pkarr::dht::DhtDiscovery::builder()
        .dht(true)
        .n0_dns_pkarr_relay();
    let discovery = builder.secret_key(secret_key.clone()).build().unwrap();
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![GOSSIP_ALPN.to_vec()])
        .relay_mode(relay_mode)
        .discovery(Box::new(discovery.clone()))
        // Using a random port
        .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .bind()
        .await
        .unwrap();

    let mut peer_discovery_task = discovery.resolve(endpoint.clone(), peer.node_id).unwrap();
    let peer_addr_info = peer_discovery_task.next().await.unwrap().unwrap().addr_info;
    let peer_addr = NodeAddr::from_parts(
        peer.node_id,
        peer_addr_info.relay_url,
        peer_addr_info.direct_addresses.into_iter().collect(),
    );

    let addr = endpoint.node_addr().await.unwrap();

    let gossip = Gossip::from_endpoint(endpoint.clone(), Default::default(), &addr.info);
    tokio::spawn(endpoint_loop(endpoint.clone(), gossip.clone()));
    let peer_id = peer.node_id.clone();
    endpoint.add_node_addr(peer_addr).unwrap();
    gossip.join(topic_id, vec![peer_id]).await.unwrap().split()
}

impl Logic {
    pub fn new() -> Self {
        let message_watch = watch::channel(());
        let logic = Self {
            latest_message: Arc::new(RwLock::new("".to_string())),
            message_watch,
            message_sender: Arc::new(Mutex::new(None)),
        };
        logic
    }

    pub fn run_test_task(&self) {
        let message_watch_sender = self.message_watch.0.clone();
        let latest_message = self.latest_message.clone();
        let message_sender = self.message_sender.clone();
        tokio::spawn(async move {
            let topic_id = TopicId::from_str(TOPIC_ID).unwrap();
            let peer = NodeAddr::new(PublicKey::from_str(PEER_ID).unwrap());
            let (sender, mut receiver) = connect_topic(topic_id, peer).await;
            message_sender.lock().await.replace(sender);
            while let Some(Ok(event)) = receiver.next().await {
                if let Event::Gossip(GossipEvent::Received(msg)) = event {
                    let decoded = String::from_utf8(msg.content.to_vec()).unwrap();
                    *latest_message.write().unwrap() = decoded.clone();
                    message_watch_sender.send(()).unwrap();
                }
            }
        });
    }

    pub fn send_message(&self, message: &str) {
        let message_sender = self.message_sender.clone();
        let encoded_message = Bytes::from(String::from(message).into_bytes());
        tokio::spawn(async move {
            let message_sender = message_sender.lock().await;
            if let Some(sender) = &*message_sender {
                sender.broadcast(encoded_message.clone()).await.unwrap();
            }
        });
    }

    pub fn get_latest_message(&self) -> String {
        self.latest_message.clone().read().unwrap().clone()
    }

    pub fn get_message_watch(&self) -> watch::Receiver<()> {
        self.message_watch.1.clone()
    }
}
