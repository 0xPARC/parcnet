use anyhow::Result;
use async_trait::async_trait;
use futures::StreamExt;
use iroh::client::Doc;
use iroh::docs::DocTicket;
use iroh::net::discovery::pkarr::dht::DhtDiscovery;
use iroh::net::endpoint::{TransportConfig, VarInt};
use iroh::net::key::SecretKey;
use pod2::pod::POD;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot; // Add this import
use tokio::sync::RwLock;

type IrohNode = iroh::node::MemNode;

use crate::{ScriptId, SharedStore, Value};

pub struct IrohStore {
    iroh: Arc<tokio::sync::RwLock<Option<IrohNode>>>,
    doc: Arc<RwLock<Option<Doc>>>,
    values: Arc<Mutex<HashMap<(ScriptId, u64), Value>>>,
    pods: Arc<Mutex<HashMap<String, POD>>>,
    secret_key: SecretKey,
}
const DOC_TICKET: &str = "docaaacb6cej4lpglwuuya5tecmiflfmnkeprhubm6nk7lhdhj4vwnobficahswyqlad2rachperq7aesmyhoxycbsn7djsqwrn4m7yd7pkr3rxwaaa";

#[derive(Clone, Debug, Serialize, Deserialize)]
enum PodOrValue {
    Pod(String, POD),
    Value(String, Value),
}

impl IrohStore {
    pub fn new(secret_key: SecretKey) -> Self {
        Self {
            iroh: Arc::new(RwLock::new(None)),
            doc: Arc::new(RwLock::new(None)),
            values: Arc::new(Mutex::new(HashMap::new())),
            pods: Arc::new(Mutex::new(HashMap::new())),
            secret_key,
        }
    }

    pub async fn initialize(&self, sync_signal: oneshot::Sender<()>) -> Result<()> {
        let builder = DhtDiscovery::builder().dht(true).n0_dns_pkarr_relay();
        let discovery = builder.secret_key(self.secret_key.clone()).build().unwrap();
        let discovery_config = iroh::node::DiscoveryConfig::Custom(Box::new(discovery));

        let mut transport_config = TransportConfig::default();
        transport_config.keep_alive_interval(Some(Duration::from_millis(250)));
        transport_config.max_idle_timeout(Some(VarInt::from_u32(1_000).into()));

        let iroh = iroh::node::Builder::default()
            .enable_docs()
            .secret_key(self.secret_key.clone())
            .transport_config(transport_config)
            .node_discovery(discovery_config)
            .spawn()
            .await?;

        let ticket = DocTicket::from_str(DOC_TICKET)?;
        let doc = iroh.docs().import(ticket).await?;
        let _ = sync_signal.send(());
        {
            let mut iroh_lock = self.iroh.write().await;
            *iroh_lock = Some(iroh);
        }
        {
            let mut doc_lock = self.doc.write().await;
            *doc_lock = Some(doc);
        }

        self.setup_sync().await?;
        Ok(())
    }

    async fn setup_sync(&self) -> Result<()> {
        let doc = self.doc.read().await;
        let iroh = self.iroh.read().await;
        if let (Some(doc), Some(iroh)) = (doc.as_ref(), iroh.as_ref()) {
            dbg!("listening for events");
            let mut events = doc.subscribe().await.unwrap();

            let values = self.values.clone();
            let pods = self.pods.clone();

            while let Some(Ok(event)) = events.next().await {
                match event {
                    iroh::client::docs::LiveEvent::ContentReady { hash } => {
                        if let Ok(content) = iroh.blobs().read_to_bytes(hash).await {
                            if let Ok(pod_or_value) = postcard::from_bytes::<PodOrValue>(&content) {
                                match pod_or_value {
                                    PodOrValue::Pod(_, pod) => {
                                        let id = crate::PodBuilder::pod_id(&pod);
                                        pods.lock().unwrap().insert(id, pod);
                                    }
                                    PodOrValue::Value(key, value) => {
                                        let parts: Vec<&str> = key.split(':').collect();
                                        if parts.len() == 3 && parts[0] == "value" {
                                            if let (Ok(script_id), Ok(value_id)) = (
                                                parts[1].parse::<String>(),
                                                parts[2].parse::<u64>(),
                                            ) {
                                                values
                                                    .lock()
                                                    .unwrap()
                                                    .insert((ScriptId(script_id), value_id), value);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        };
        Ok(())
    }

    pub async fn cleanup(&self) -> Result<()> {
        if let Some(iroh) = self.iroh.write().await.take() {
            iroh.shutdown().await?;
        }
        Ok(())
    }
}

#[async_trait]
impl SharedStore for IrohStore {
    async fn get_value(&self, script_id: &ScriptId, id: u64) -> Option<Value> {
        let mut counter = 0;
        loop {
            if let Some(v) = self
                .values
                .lock()
                .unwrap()
                .get(&(script_id.clone(), id))
                .cloned()
            {
                return Some(v);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            counter += 1;
            if counter > 100 {
                return None;
            }
        }
    }

    fn set_value(&self, script_id: &ScriptId, id: u64, value: Value) {
        self.values
            .lock()
            .unwrap()
            .insert((script_id.clone(), id), value.clone());

        // Sync to iroh network
        let doc = self.doc.clone();
        let iroh = self.iroh.clone();
        let key = format!("value:{}:{}", script_id.0, id);
        let value = PodOrValue::Value(key.clone(), value.clone());

        tokio::spawn(async move {
            if let (Some(doc), Some(iroh)) = (doc.read().await.as_ref(), iroh.read().await.as_ref())
            {
                let author = iroh.authors().default().await?;
                let serialized_value: Vec<u8> = postcard::to_stdvec(&value)?;
                doc.set_bytes(author, key, serialized_value).await?;
                Ok::<(), anyhow::Error>(())
            } else {
                Ok(())
            }
        });
    }

    async fn get_pod(&self, id: &String) -> Option<POD> {
        self.pods.lock().unwrap().get(id).cloned()
    }

    fn store_pod(&self, pod: POD) -> String {
        let id = crate::PodBuilder::pod_id(&pod);
        self.pods.lock().unwrap().insert(id.clone(), pod.clone());

        // Sync to iroh network
        let doc = self.doc.clone();
        let iroh = self.iroh.clone();
        let key = format!("pod:{}", id);
        let pod = PodOrValue::Pod(key.clone(), pod.clone());

        tokio::spawn(async move {
            if let (Some(doc), Some(iroh)) = (doc.read().await.as_ref(), iroh.read().await.as_ref())
            {
                let author = iroh.authors().default().await?;
                let serialized_value: Vec<u8> = postcard::to_stdvec(&pod)?;
                doc.set_bytes(author, key, serialized_value).await?;
                Ok::<(), anyhow::Error>(())
            } else {
                Ok(())
            }
        });

        id
    }
}
