use std::fmt::Display;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use ed25519_dalek::Signature;
use iroh::net::key::{PublicKey, SecretKey};
use pod2::schnorr::SchnorrPublicKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedMessage {
    from: PublicKey,
    data: Bytes,
    signature: Signature,
}

impl SignedMessage {
    pub fn verify_and_decode(bytes: &[u8]) -> anyhow::Result<(PublicKey, Message)> {
        let signed_message: Self = postcard::from_bytes(bytes)?;
        let key: PublicKey = signed_message.from;
        key.verify(&signed_message.data, &signed_message.signature)?;
        let message: Message = postcard::from_bytes(&signed_message.data)?;
        Ok((signed_message.from, message))
    }

    pub fn sign_and_encode(secret_key: &SecretKey, message: &Message) -> anyhow::Result<Bytes> {
        let data: Bytes = postcard::to_stdvec(&message)?.into();
        let signature = secret_key.sign(&data);
        let from: PublicKey = secret_key.public();
        let signed_message = Self {
            from,
            data,
            signature,
        };
        let encoded = postcard::to_stdvec(&signed_message)?;
        Ok(encoded.into())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Message {
    AboutMe {
        name: String,
        timestamp: DateTime<Utc>,
    },
    SchnorrKey {
        schnorr_public_key: SchnorrPublicKey,
        timestamp: DateTime<Utc>,
    },
    Chat {
        text: String,
        timestamp: DateTime<Utc>,
    },
}
impl Message {
    pub fn new_about_me(name: String) -> Self {
        Self::AboutMe {
            name,
            timestamp: Utc::now(),
        }
    }

    pub fn new_chat(text: String) -> Self {
        Self::Chat {
            text,
            timestamp: Utc::now(),
        }
    }

    pub fn timestamp(&self) -> &DateTime<Utc> {
        match self {
            Message::AboutMe { timestamp, .. } => timestamp,
            Message::SchnorrKey { timestamp, .. } => timestamp,
            Message::Chat { timestamp, .. } => timestamp,
        }
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::AboutMe { name, timestamp } => {
                write!(f, "AboutMe: {} at {}", name, timestamp)
            }
            Message::SchnorrKey {
                schnorr_public_key,
                timestamp,
            } => {
                write!(
                    f,
                    "SchnorrKey: {} at {}",
                    schnorr_public_key.pk.0, timestamp
                )
            }
            Message::Chat { text, timestamp } => {
                write!(f, "Chat: {} at {}", text, timestamp)
            }
        }
    }
}
