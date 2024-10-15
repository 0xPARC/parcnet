use iroh_net::key::SecretKey;
use std::{fs, path::PathBuf};
use tracing::info;

fn key_file_path() -> PathBuf {
    std::env::current_exe()
        .expect("failed to get executable path")
        .parent()
        .expect("failed to get parent directory")
        .join("user_key.bin")
}

pub fn get_or_create_secret_key() -> SecretKey {
    let path = key_file_path();
    match fs::read(&path) {
        Ok(bytes) if bytes.len() == 32 => {
            let bytes: [u8; 32] = bytes.try_into().unwrap();
            info!("loaded existing user key");
            SecretKey::from_bytes(&bytes)
        }
        _ => {
            info!("generating new user key");
            let key = SecretKey::generate();
            if let Err(e) = fs::write(&path, key.to_bytes()) {
                info!("failed to save user key: {}", e);
            }
            key
        }
    }
}
