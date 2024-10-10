use futures::StreamExt;
use iroh_gossip::{
    net::{Gossip, GossipReceiver, GossipSender},
    proto::TopicId,
};
use iroh_net::{
    discovery::{pkarr::dht::DhtDiscovery, Discovery},
    endpoint::Connecting,
    key::{PublicKey, SecretKey},
    relay::RelayMode,
    Endpoint, NodeAddr,
};
use std::net::{Ipv4Addr, SocketAddrV4};
use tracing::warn;

const GOSSIP_ALPN: &[u8] = b"/iroh-gossip/0";

async fn endpoint_loop(endpoint: Endpoint, gossip: Gossip) {
    while let Some(incoming) = endpoint.accept().await {
        let conn = match incoming.accept() {
            Ok(conn) => conn,
            Err(err) => {
                warn!("incoming connection failed: {err:#}");
                continue;
            }
        };
        let gossip = gossip.clone();
        tokio::spawn(async move { handle_connection(conn, gossip).await });
    }
}

async fn handle_connection(mut conn: Connecting, gossip: Gossip) {
    let alpn = conn.alpn().await.unwrap();
    let conn = conn.await.unwrap();
    let peer_id = iroh_net::endpoint::get_remote_node_id(&conn).unwrap();
    match alpn.as_ref() {
        GOSSIP_ALPN => gossip.handle_connection(conn).await.unwrap(),
        _ => warn!("ignoring connection from {peer_id}: unsupported ALPN protocol"),
    }
}

async fn dht_resolve_node_addr(
    id: PublicKey,
    discovery: DhtDiscovery,
    endpoint: Endpoint,
) -> NodeAddr {
    let mut task = discovery.resolve(endpoint, id).unwrap();
    let info = task.next().await.unwrap().unwrap().addr_info;
    NodeAddr::from_parts(
        id,
        info.relay_url,
        info.direct_addresses.into_iter().collect(),
    )
}

pub async fn connect_topic(
    topic_id: TopicId,
    peer_ids: &[PublicKey],
    secret_key: SecretKey,
) -> (GossipSender, GossipReceiver) {
    let relay_mode = RelayMode::Default;
    let builder = DhtDiscovery::builder().dht(true).n0_dns_pkarr_relay();
    let discovery = builder.secret_key(secret_key.clone()).build().unwrap();
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![GOSSIP_ALPN.to_vec()])
        .relay_mode(relay_mode)
        .discovery(Box::new(discovery.clone()))
        // 0 = random port
        .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .bind()
        .await
        .unwrap();

    let peers = peer_ids
        .iter()
        .map(|id| dht_resolve_node_addr(*id, discovery.clone(), endpoint.clone()))
        .collect::<Vec<_>>();

    let addr = endpoint.node_addr().await.unwrap();

    let gossip = Gossip::from_endpoint(endpoint.clone(), Default::default(), &addr.info);
    tokio::spawn(endpoint_loop(endpoint.clone(), gossip.clone()));
    for peer in peers {
        endpoint.add_node_addr(peer.await).unwrap();
    }
    gossip
        .join(topic_id, peer_ids.to_vec())
        .await
        .unwrap()
        .split()
}
