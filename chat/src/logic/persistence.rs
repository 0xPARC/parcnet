use iroh::net::key::SecretKey;
use pod2::schnorr::SchnorrSecretKey;
use std::{fs, path::PathBuf};
use tracing::info;

trait KeyOperations: Sized {
    const FILENAME: &'static str;
    const EXPECTED_BYTES: usize;

    fn generate_new() -> Self;
    fn from_bytes(bytes: &[u8]) -> Option<Self>;
    fn to_bytes(&self) -> Vec<u8>;
}

impl KeyOperations for SecretKey {
    const FILENAME: &'static str = "user_key.bin";
    const EXPECTED_BYTES: usize = 32;

    fn generate_new() -> Self {
        Self::generate()
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: [u8; 32] = bytes.try_into().ok()?;
        Some(Self::from_bytes(&bytes))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl KeyOperations for SchnorrSecretKey {
    const FILENAME: &'static str = "schnorr_key.bin";
    const EXPECTED_BYTES: usize = 8;

    fn generate_new() -> Self {
        Self { sk: rand::random() }
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: [u8; 8] = bytes.try_into().ok()?;
        Some(Self {
            sk: u64::from_le_bytes(bytes),
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.sk.to_le_bytes().to_vec()
    }
}

fn get_exe_parent_dir() -> PathBuf {
    std::env::current_exe()
        .expect("failed to get executable path")
        .parent()
        .expect("failed to get parent directory")
        .to_path_buf()
}

pub fn persistence_file_path() -> PathBuf {
    get_exe_parent_dir().join("iroh_data")
}

fn get_or_create_key<T: KeyOperations>() -> T {
    let path = get_exe_parent_dir().join(T::FILENAME);

    match fs::read(&path) {
        Ok(bytes) if bytes.len() == T::EXPECTED_BYTES => {
            if let Some(key) = T::from_bytes(&bytes) {
                info!("loaded existing {}", T::FILENAME);
                return key;
            }
            info!("failed to parse existing {}", T::FILENAME);
            let key = T::generate_new();
            if let Err(e) = fs::write(&path, key.to_bytes()) {
                info!("failed to save {}: {}", T::FILENAME, e);
            }
            key
        }
        _ => {
            info!("generating new {}", T::FILENAME);
            let key = T::generate_new();
            if let Err(e) = fs::write(&path, key.to_bytes()) {
                info!("failed to save {}: {}", T::FILENAME, e);
            }
            key
        }
    }
}

pub fn get_or_create_secret_key() -> SecretKey {
    get_or_create_key()
}

pub fn get_or_create_schnorr_secret_key() -> SchnorrSecretKey {
    get_or_create_key()
}
