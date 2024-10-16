mod auto_update;
mod message;
mod persistence;

use auto_update::AutoUpdater;
use futures::StreamExt;
use iroh::client::docs::LiveEvent;
use iroh::client::Doc;
use iroh::docs::DocTicket;
use message::Message;
use persistence::get_or_create_secret_key;
use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};
use tokio::sync::watch;
use tracing::info;

pub use auto_update::{get_app_path, get_current_version, is_dev};

type IrohNode = iroh::node::Node<iroh::blobs::store::fs::Store>;

pub struct Logic {
    iroh: Arc<tokio::sync::RwLock<Option<IrohNode>>>,
    doc0: Arc<tokio::sync::RwLock<Option<Doc>>>,
    messages: RwLock<Vec<Message>>,
    message_watch: (watch::Sender<()>, watch::Receiver<()>),
    _auto_updater: AutoUpdater,
}

const DOP0: &str = "j2kblusfmti4mvc662jprvncnkes5qydcqj4bdl54ko6bdyfsx5a";
const DOC0_TICKET: &str = "docaaacak27d7p7ksnzob3gho3y45ocpdpjejbb3fmnsy2h7ot6f7xgg4pzafn7exieodujj72s7cyhw2dzv4to2wdowgvt5rdlvqilfodb4ba7uaaa";

impl Logic {
    pub fn new() -> Self {
        let message_watch = watch::channel(());
        let auto_updater = AutoUpdater::new();

        Self {
            iroh: Arc::new(tokio::sync::RwLock::new(None)),
            doc0: Arc::new(tokio::sync::RwLock::new(None)),
            messages: RwLock::new(Vec::new()),
            message_watch,
            _auto_updater: auto_updater,
        }
    }

    pub async fn initialize(&self) -> anyhow::Result<()> {
        info!("initializing chat logic");
        let secret_key = get_or_create_secret_key();
        let iroh = iroh::node::Builder::default()
            .enable_docs()
            .secret_key(secret_key)
            .persist(persistence::persistence_file_path())
            .await?
            .spawn()
            .await?;
        let ticket = DocTicket::from_str(DOC0_TICKET)?;
        let doc = iroh.docs().import(ticket).await?;
        {
            let mut iroh_lock = self.iroh.write().await;
            *iroh_lock = Some(iroh);
        }
        {
            let mut doc_lock = self.doc0.write().await;
            *doc_lock = Some(doc);
        }

        self.load_initial_messages().await?;
        self.setup_message_subscription().await?;
        Ok(())
    }

    async fn load_initial_messages(&self) -> anyhow::Result<()> {
        info!("loading initial messages");
        let iroh = self.iroh.read().await;
        let doc = self.doc0.read().await;

        if let (Some(iroh), Some(doc)) = (iroh.as_ref(), doc.as_ref()) {
            let mut entries = doc.get_many(iroh::docs::store::Query::all()).await?;
            let mut initial_messages = Vec::new();

            while let Some(Ok(entry)) = entries.next().await {
                if let Ok(content) = iroh.blobs().read_to_bytes(entry.content_hash()).await {
                    if let Some(message) = Message::decode(content) {
                        initial_messages.push(message);
                    }
                }
            }

            initial_messages.sort_by_key(|m| m.timestamp);
            *self.messages.write().unwrap() = initial_messages;
            self.message_watch.0.send(()).unwrap();
        }
        info!("initial messages loaded");
        Ok(())
    }

    async fn setup_message_subscription(&self) -> anyhow::Result<()> {
        info!("setting up message subscription");
        let doc = self.doc0.read().await;
        let iroh = self.iroh.read().await;
        if let (Some(doc), Some(iroh)) = (doc.as_ref(), iroh.as_ref()) {
            let mut events = doc.subscribe().await?;
            let message_watch_sender = self.message_watch.0.clone();
            while let Some(Ok(event)) = events.next().await {
                match event {
                    LiveEvent::InsertRemote { .. } | LiveEvent::InsertLocal { .. } => {
                        let mut new_messages = Vec::new();
                        let mut entries = doc.get_many(iroh::docs::store::Query::all()).await?;
                        while let Some(Ok(entry)) = entries.next().await {
                            if let Ok(content) =
                                iroh.blobs().read_to_bytes(entry.content_hash()).await
                            {
                                if let Some(message) = Message::decode(content) {
                                    new_messages.push(message);
                                }
                            }
                        }
                        new_messages.sort_by_key(|m| m.timestamp);
                        *self.messages.write().unwrap() = new_messages;
                        message_watch_sender.send(()).unwrap();
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    pub async fn send_message(&self, message: &str) -> anyhow::Result<()> {
        info!("sending message: {}", message);
        let iroh = self.iroh.read().await;
        let doc = self.doc0.read().await;

        if let (Some(iroh), Some(doc)) = (iroh.as_ref(), doc.as_ref()) {
            let message = Message {
                timestamp: chrono::Utc::now(),
                text: message.to_string(),
            };
            let content = message.encode();
            let author = iroh.authors().default().await?;
            doc.set_bytes(
                author,
                message.timestamp.timestamp_micros().to_string(),
                content,
            )
            .await?;
            info!("message sent");
            Ok(())
        } else {
            anyhow::bail!("Iroh or Doc not initialized")
        }
    }

    pub fn get_messages(&self) -> Vec<Message> {
        self.messages.read().map(|msg| msg.clone()).unwrap()
    }

    pub fn get_message_watch(&self) -> watch::Receiver<()> {
        self.message_watch.1.clone()
    }

    pub async fn cleanup(&self) -> anyhow::Result<()> {
        self.iroh
            .write()
            .await
            .as_mut()
            .unwrap()
            .clone()
            .shutdown()
            .await?;
        Ok(())
    }
}
