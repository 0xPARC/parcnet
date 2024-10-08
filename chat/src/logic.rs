mod auto_update;
mod gossip;
mod message;

use auto_update::AutoUpdater;
use futures::StreamExt;
use gossip::connect_topic;
use gpui::SemanticVersion;
use iroh_gossip::{
    net::{Event, GossipEvent, GossipSender},
    proto::TopicId,
};
use iroh_net::key::{PublicKey, SecretKey};
use message::Message;
use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};
use tokio::sync::{watch, Mutex};
use tracing::{info, warn};

pub struct Logic {
    messages: Arc<RwLock<Vec<Message>>>,
    message_watch: (watch::Sender<()>, watch::Receiver<()>),
    message_sender: Arc<Mutex<Option<GossipSender>>>,
    _auto_updater: AutoUpdater,
}

const TOPIC_ID: &str = "ka6iqvox3fpbtouurx2n637eiznjmgp47fbbslgdufbyob5lrk2q";
const PEER_ID: &str = "7uarjluqs7mtnuaxohp6z5u7ysls5qglr2j2lqghbhptz5hjmhia";

impl Logic {
    pub fn new() -> Self {
        let message_watch = watch::channel(());
        let auto_updater = AutoUpdater::new();
        let logic = Self {
            messages: Arc::new(RwLock::new(Vec::new())),
            message_watch,
            message_sender: Arc::new(Mutex::new(None)),
            _auto_updater: auto_updater,
        };
        logic.connect();
        logic
    }

    pub async fn send_message(&self, message: &str) {
        let messages = self.messages.clone();
        let message_watch_sender = self.message_watch.0.clone();
        if let Some(sender) = self.message_sender.lock().await.as_ref() {
            let message = Message {
                timestamp: chrono::Utc::now(),
                text: message.to_string(),
            };
            let bytes = message.encode();
            info!("sending message: {}", message.text);
            sender.broadcast(bytes).await.unwrap();
            messages.write().map(|mut msgs| msgs.push(message)).unwrap();
            message_watch_sender.send(()).unwrap();
            return;
        }
        warn!("no sender available");
    }

    pub fn get_messages(&self) -> Vec<Message> {
        self.messages.read().map(|msg| msg.clone()).unwrap()
    }

    pub fn get_message_watch(&self) -> watch::Receiver<()> {
        self.message_watch.1.clone()
    }

    fn connect(&self) {
        let message_watch_sender = self.message_watch.0.clone();
        let message_sender = self.message_sender.clone();
        let messages = self.messages.clone();
        let topic_id = TopicId::from_str(TOPIC_ID).unwrap();
        let peer_id = PublicKey::from_str(PEER_ID).unwrap();
        warn!("generating new secret key");
        let secret_key = SecretKey::generate();
        tokio::spawn(async move {
            let (sender, mut receiver) = connect_topic(topic_id, peer_id, secret_key).await;
            message_sender.lock().await.replace(sender);
            while let Some(Ok(event)) = receiver.next().await {
                if let Event::Gossip(GossipEvent::Received(msg)) = event {
                    if let Some(message) = Message::decode(msg.content) {
                        info!("received message: {}", message.text);
                        messages.write().map(|mut msgs| msgs.push(message)).unwrap();
                        message_watch_sender.send(()).unwrap();
                    } else {
                        warn!("failed to decode message");
                    }
                }
            }
        });
    }
}
