use anyhow::Result;
use chrono::Utc;
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
use pod2::pod::POD;
use rusqlite::{params, Connection, OpenFlags};
use std::path::PathBuf;
use tracing::info;

use super::persistence::get_exe_parent_dir;

pub struct PodStore {
    conn: Connection,
}

impl PodStore {
    pub fn new() -> Self {
        let conn = Connection::open_with_flags(
            get_default_db_path(),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )
        .unwrap();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS pods (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            pod BLOB NOT NULL,
                            timestamp INTEGER NOT NULL
                        )",
            [],
        )
        .unwrap();

        Self { conn }
    }

    pub fn add_pod(&self, pod: &POD) -> Result<()> {
        let timestamp = Utc::now();
        let serialized_pod = postcard::to_stdvec(pod)?;

        self.conn.execute(
            "INSERT INTO pods (pod, timestamp) VALUES (?1, ?2)",
            params![serialized_pod, timestamp.timestamp(),],
        )?;
        info!("added pod");
        Ok(())
    }

    pub fn get_num_pods(&self) -> Result<u64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM pods", [], |row| row.get(0))?;
        Ok(count as u64)
    }
}

pub fn get_string_field_elem(text: &str) -> GoldilocksField {
    let hash = blake3::hash(text.to_string().as_bytes());
    let hash_bytes = hash.as_bytes();
    let mut n = 0u128;
    for &byte in hash_bytes.iter().take(16) {
        n = (n << 8) | (byte as u128);
    }
    GoldilocksField::from_noncanonical_u128(n)
}

fn get_default_db_path() -> PathBuf {
    get_exe_parent_dir().join("podstore.db")
}
