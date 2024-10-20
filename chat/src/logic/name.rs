use iroh::net::key::PublicKey;
use std::collections::HashMap;

use super::Message;

pub struct Names {
    names: HashMap<PublicKey, String>,
}

impl Names {
    pub fn new() -> Self {
        Self {
            names: HashMap::new(),
        }
    }

    pub fn apply_about_message(&mut self, pubkey: PublicKey, message: &Message) {
        if let Message::AboutMe { name, timestamp: _ } = message {
            self.names.insert(pubkey, name.clone());
        }
    }

    pub fn get_name(&self, pubkey: &PublicKey) -> Option<&String> {
        self.names.get(pubkey)
    }
}
