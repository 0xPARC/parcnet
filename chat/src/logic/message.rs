use bytes::Bytes;
use chrono::{DateTime, Utc};

#[derive(Clone)]
pub struct Message {
    pub timestamp: DateTime<Utc>,
    pub text: String,
}

impl Message {
    pub fn encode(&self) -> Bytes {
        Bytes::from(format!("{},{}", self.timestamp.to_rfc3339(), self.text))
    }

    pub fn decode(bytes: Bytes) -> Option<Self> {
        let s = String::from_utf8(bytes.to_vec()).ok()?;
        let (timestamp, text) = s.split_once(',')?;
        Some(Self {
            timestamp: timestamp.parse().ok()?,
            text: text.to_string(),
        })
    }
}
