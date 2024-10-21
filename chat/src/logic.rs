mod auto_update;
mod identity;
mod message;
mod persistence;

use auto_update::AutoUpdater;
pub use auto_update::{get_app_path, get_current_version, is_dev};
use futures::StreamExt;
use identity::Identities;
use iroh::client::Doc;
use iroh::docs::DocTicket;
use iroh::net::discovery::pkarr::dht::DhtDiscovery;
use iroh::net::endpoint::{TransportConfig, VarInt};
use iroh::net::key::{PublicKey, SecretKey};
use iroh::{client::docs::LiveEvent, node::DiscoveryConfig};
use message::SignedMessage;

use persistence::{get_or_create_schnorr_secret_key, get_or_create_secret_key};
use pod2::schnorr::SchnorrSecretKey;
use std::sync::Mutex;
use std::time::Duration;
use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};
use tokio::sync::watch;
use tracing::info;

pub use message::Message;

type IrohNode = iroh::node::Node<iroh::blobs::store::fs::Store>;

pub struct Logic {
    iroh: Arc<tokio::sync::RwLock<Option<IrohNode>>>,
    secret_key: SecretKey,
    schnorr_secret_key: SchnorrSecretKey,
    doc0: Arc<tokio::sync::RwLock<Option<Doc>>>,
    messages: RwLock<Vec<(PublicKey, Message)>>,
    identities: Mutex<Identities>,
    message_watch: (watch::Sender<()>, watch::Receiver<()>),
    initial_sync: RwLock<bool>,
    initial_sync_watch: (watch::Sender<()>, watch::Receiver<()>),
    _auto_updater: AutoUpdater,
}

const _DOC0: &str = "6noafdqcxno4xv4ejf5xpma6gcl4gaw4w2gxsyvlp6kfwq3t6i2q";
const DOC0_TICKET: &str = "docaaacaxeh5eddy2cni7cuu5gail5gaxqqy2loiv6cghg5u45akcplu4skahswyqlad2rachperq7aesmyhoxycbsn7djsqwrn4m7yd7pkr3rxwaaa";

mod pods {
    use anyhow::Result;
    use chrono::{DateTime, Utc};
    use iroh::net::key::PublicKey;
    use pod2::pod::POD;
    use rusqlite::{params, Connection, OpenFlags};
    use std::path::Path;
    use tracing::{error, info};

    pub struct PodStore {
        conn: Connection,
    }

    impl PodStore {
        pub fn new(db_path: &Path) -> Result<Self> {
            let conn = Connection::open_with_flags(
                db_path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            )?;

            conn.execute(
                "CREATE TABLE IF NOT EXISTS pods (
                    uid TEXT PRIMARY KEY,
                    public_key BLOB NOT NULL,
                    pod BLOB NOT NULL,
                    timestamp INTEGER NOT NULL
                )",
                [],
            )?;

            Ok(Self { conn })
        }

        pub fn add_pod(&self, uid: &str, public_key: &PublicKey, pod: &POD) -> Result<()> {
            let timestamp = Utc::now();
            let serialized_pod = postcard::to_stdvec(pod)?;

            self.conn.execute(
                "INSERT OR REPLACE INTO pods (uid, public_key, pod, timestamp) VALUES (?1, ?2, ?3, ?4)",
                params![
                    uid,
                    public_key.as_bytes(),
                    serialized_pod,
                    timestamp.timestamp(),
                ],
            )?;

            info!("Added pod with UID: {}", uid);
            Ok(())
        }

        pub fn get_pod(&self, uid: &str) -> Result<Option<(PublicKey, POD, DateTime<Utc>)>> {
            let mut stmt = self
                .conn
                .prepare("SELECT public_key, pod, timestamp FROM pods WHERE uid = ?1")?;

            let result = stmt.query_row(params![uid], |row| {
                let public_key_bytes: Vec<u8> = row.get(0)?;
                let pod_bytes: Vec<u8> = row.get(1)?;
                let timestamp: i64 = row.get(2)?;

                let public_key = PublicKey::try_from_bytes(&public_key_bytes).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })?;

                let pod: POD = postcard::from_bytes(&pod_bytes).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })?;

                let datetime = DateTime::from_timestamp(timestamp, 0).ok_or_else(|| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Integer,
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Invalid timestamp",
                        )),
                    )
                })?;

                Ok((public_key, pod, datetime))
            });

            match result {
                Ok(pod_data) => Ok(Some(pod_data)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => {
                    error!("Error retrieving pod: {:?}", e);
                    Err(e.into())
                }
            }
        }
    }
}

impl Logic {
    pub fn new() -> Self {
        let message_watch = watch::channel(());
        let secret_key = get_or_create_secret_key();
        let schnorr_secret_key = get_or_create_schnorr_secret_key();
        let initial_sync_watch = watch::channel(());
        let auto_updater = AutoUpdater::new();

        Self {
            iroh: Arc::new(tokio::sync::RwLock::new(None)),
            secret_key,
            schnorr_secret_key,
            doc0: Arc::new(tokio::sync::RwLock::new(None)),
            messages: RwLock::new(Vec::new()),
            identities: Mutex::new(Identities::new()),
            message_watch,
            initial_sync: RwLock::new(true),
            initial_sync_watch,
            _auto_updater: auto_updater,
        }
    }

    pub async fn initialize(&self) -> anyhow::Result<()> {
        info!("initializing chat logic");
        let builder = DhtDiscovery::builder().dht(true).n0_dns_pkarr_relay();
        let discovery = builder.secret_key(self.secret_key.clone()).build().unwrap();
        let discovery_config = DiscoveryConfig::Custom(Box::new(discovery));

        let mut transport_config = TransportConfig::default();
        transport_config.keep_alive_interval(Some(Duration::from_millis(250)));
        transport_config.max_idle_timeout(Some(VarInt::from_u32(1_000).into()));

        let iroh = iroh::node::Builder::default()
            .enable_docs()
            .secret_key(self.secret_key.clone())
            .transport_config(transport_config)
            .node_discovery(discovery_config)
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
                    if let Ok(m) = SignedMessage::verify_and_decode(&content) {
                        initial_messages.push(m);
                    }
                }
            }

            for (pubkey, message) in &initial_messages {
                self.add_message(*pubkey, message);
            }
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
            while let Some(Ok(event)) = events.next().await {
                // When getting ContentReady event, it means something we have finished downloading
                // PendingContentReady means we are done with our initial sync
                match event {
                    LiveEvent::ContentReady { hash } => {
                        if let Ok(content) = iroh.blobs().read_to_bytes(hash).await {
                            if let Ok(m) = SignedMessage::verify_and_decode(&content) {
                                info!("inserting message");
                                self.add_message(m.0, &m.1);
                            }
                        }
                    }
                    LiveEvent::PendingContentReady => {
                        info!("sync is done");
                        *self.initial_sync.write().unwrap() = false;
                        self.initial_sync_watch.0.send(()).unwrap();
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    pub async fn send_message(&self, input: &str) -> anyhow::Result<()> {
        let message = parse_message_input(input);

        let content = SignedMessage::sign_and_encode(&self.secret_key, &message)?;
        let timestamp = *message.timestamp();

        let iroh = Arc::clone(&self.iroh);
        let doc0 = Arc::clone(&self.doc0);

        self.add_message(self.secret_key.public(), &message);

        tokio::spawn(async move {
            let iroh = iroh.read().await;
            let doc0 = doc0.read().await;
            if let (Some(iroh), Some(doc0)) = (iroh.as_ref(), doc0.as_ref()) {
                let author = iroh.authors().default().await?;
                doc0.set_bytes(author, timestamp.timestamp_micros().to_string(), content)
                    .await?;
                info!("message sent, storing pod");
                Ok::<_, anyhow::Error>(())
            } else {
                anyhow::bail!("Iroh or Doc not initialized")
            }
        });
        Ok(())
    }

    pub fn get_name(&self, pubkey: &PublicKey) -> String {
        self.identities
            .lock()
            .unwrap()
            .get_name(pubkey)
            .cloned()
            .unwrap_or_else(|| pubkey.to_string().chars().take(6).collect::<String>())
    }

    pub fn get_initial_sync(&self) -> bool {
        *self.initial_sync.read().unwrap()
    }

    pub fn get_messages(&self) -> Vec<(PublicKey, String)> {
        let m: Vec<(PublicKey, String)> = self
            .messages
            .read()
            .map(|msg| msg.clone())
            .unwrap()
            .into_iter()
            .filter_map(|m| match m {
                (public_key, Message::Chat { timestamp: _, text }) => Some((public_key, text)),
                _ => None,
            })
            .collect();
        m
    }

    pub fn get_message_watch(&self) -> watch::Receiver<()> {
        self.message_watch.1.clone()
    }

    pub fn get_initial_sync_watch(&self) -> watch::Receiver<()> {
        self.initial_sync_watch.1.clone()
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

    fn add_message(&self, pubkey: PublicKey, message: &Message) {
        self.messages
            .write()
            .unwrap()
            .push((pubkey, message.clone()));
        self.identities
            .lock()
            .unwrap()
            .apply_message(pubkey, message);
        self.messages
            .write()
            .unwrap()
            .sort_by_key(|m| *m.1.timestamp());
        self.message_watch.0.send(()).unwrap();
    }
}

pub fn parse_message_input(input: &str) -> Message {
    input
        .strip_prefix('/')
        .and_then(|cmd| cmd.strip_prefix("name"))
        .filter(|name| !name.trim().is_empty())
        .map_or_else(
            || Message::new_chat(input.to_string()),
            |name| Message::new_about_me(name.trim().to_string()),
        )
}
