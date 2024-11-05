use iroh::net::key::PublicKey;
use pod2::signature::schnorr::{SchnorrPublicKey, SchnorrSigner};
use std::collections::HashMap;
use tracing::warn;

use super::Message;

pub struct Identities {
    names: HashMap<PublicKey, String>,
    keys: HashMap<PublicKey, SchnorrPublicKey>,
}

impl Identities {
    pub fn new() -> Self {
        Self {
            names: HashMap::new(),
            keys: HashMap::new(),
        }
    }

    pub fn apply_message(&mut self, pubkey: PublicKey, message: &Message) {
        match message {
            Message::AboutMe { name, .. } => {
                self.names.insert(pubkey, name.clone());
            }
            Message::SchnorrKey {
                schnorr_public_key,
                signature,
                ..
            } => {
                let signer = SchnorrSigner::new();
                let field_elem = schnorr_public_key.pk;
                if !signer.verify(signature, &vec![field_elem], schnorr_public_key) {
                    warn!("invalid schnorr sig, not storing identity");
                    return;
                }
                self.keys.insert(pubkey, *schnorr_public_key);
            }
            _ => {}
        }
    }

    pub fn get_name(&self, pubkey: &PublicKey) -> Option<&String> {
        self.names.get(pubkey)
    }
}
