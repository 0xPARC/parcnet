pub use ark_bn254::Fr as Fq;
use ark_ff::PrimeField;
use babyjubjub_ark::Point;
use poseidon_ark::Poseidon;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{serde::timestamp::milliseconds, OffsetDateTime};

use super::serialisation::*;
use super::PodCreationError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PodValue {
    String(String),
    Int(i64),
    #[serde(serialize_with = "fq_ser", deserialize_with = "fq_de")]
    Cryptographic(Fq),
    #[serde(
        serialize_with = "compressed_pt_ser",
        deserialize_with = "compressed_pt_de",
        rename = "eddsa_pubkey"
    )]
    EdDSAPublicKey(Point),
    Boolean(bool),
    Bytes(Vec<u8>),
    #[serde(
        serialize_with = "milliseconds::serialize",
        deserialize_with = "milliseconds::deserialize"
    )]
    Date(OffsetDateTime),
    #[serde(serialize_with = "null_ser", deserialize_with = "null_de")]
    Null,
}

impl PodValue {
    pub fn hash(&self) -> Result<Fq, PodCreationError> {
        let hasher = |input_type, x| {
            Poseidon::new().hash(x).map_err(|e| {
                PodCreationError::HashError(format!("{} hash failed: {}", input_type, e))
            })
        };
        println!("self: {:?}", self);
        match self {
            PodValue::String(s) => Ok(string_hash(s)),
            PodValue::Int(i) => {
                let fq = Fq::from(*i);
                let h = hasher("Integer", vec![fq]);
                println!("INT: {:?}, HASHED: {:?}", i, h);
                h
            }
            PodValue::Cryptographic(c) => hasher("Cryptographic", vec![*c]),
            PodValue::EdDSAPublicKey(pt) => hasher("EdDSA public key", vec![pt.x, pt.y]),
            PodValue::Boolean(b) => hasher("Boolean", vec![Fq::from(*b)]),
            PodValue::Bytes(b) => Ok(bytes_hash(b)),
            PodValue::Date(t) => {
                hasher("Date", vec![Fq::from(t.unix_timestamp_nanos() / 1_000_000)])
            }
            PodValue::Null => Ok(PrimeField::from_be_bytes_mod_order(
                &[0; 32].iter().map(|_| 0x1d).collect::<Vec<_>>(),
            )),
        }
    }
}

impl From<&str> for PodValue {
    fn from(s: &str) -> Self {
        PodValue::String(s.to_string())
    }
}

impl From<String> for PodValue {
    fn from(s: String) -> Self {
        PodValue::String(s)
    }
}

impl From<i64> for PodValue {
    fn from(i: i64) -> Self {
        PodValue::Int(i)
    }
}

impl From<Fq> for PodValue {
    fn from(b: Fq) -> Self {
        PodValue::Cryptographic(b)
    }
}

impl From<bool> for PodValue {
    fn from(b: bool) -> Self {
        PodValue::Boolean(b)
    }
}

impl From<OffsetDateTime> for PodValue {
    fn from(t: OffsetDateTime) -> Self {
        PodValue::Date(t)
    }
}

impl From<&[u8]> for PodValue {
    fn from(bytes: &[u8]) -> Self {
        PodValue::Bytes(bytes.to_vec())
    }
}

impl From<()> for PodValue {
    fn from(_: ()) -> Self {
        PodValue::Null
    }
}

pub fn string_hash(s: &str) -> Fq {
    bytes_hash(s.as_bytes())
}

pub fn bytes_hash(v: &[u8]) -> Fq {
    let digest = Sha256::digest(v);
    // Right-shift by 8 bits
    PrimeField::from_be_bytes_mod_order(&digest[0..31])
}
