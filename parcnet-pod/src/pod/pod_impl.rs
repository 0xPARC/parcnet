use std::array;

use ark_std::str::FromStr;
use ark_bn254::Fr as Fq;
use ark_ff::PrimeField;
use babyjubjub_ark::{decompress_point, decompress_signature, verify, Point, PrivateKey, Signature};
use base64::{engine::general_purpose, Engine as _};
use indexmap::IndexMap;
use poseidon_ark::Poseidon;
use sha2::{Digest, Sha256};
use thiserror::Error;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use uuid::Uuid;

use crate::crypto::lean_imt::lean_poseidon_imt;

pub(crate) type Error = Box<dyn std::error::Error>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "PodValueHelper", from = "PodValueHelper")]
pub enum PodValue {
    String(String),
    Int(i64),
    Cryptographic(Fq),
}

#[derive(Serialize, Deserialize)]
struct PodValueHelper {
    #[serde(rename = "type")]
    value_type: String,
    value: serde_json::Value,
}

impl From<PodValue> for PodValueHelper {
    fn from(pod_value: PodValue) -> Self {
        match pod_value {
            PodValue::String(s) => PodValueHelper {
                value_type: "string".to_string(),
                value: Value::String(s),
            },
            PodValue::Int(i) => PodValueHelper {
                value_type: "int".to_string(),
                value: Value::Number(i.into()),
            },
            PodValue::Cryptographic(c) => PodValueHelper {
                value_type: "cryptographic".to_string(),
                value: Value::String(c.to_string()),
            },
        }
    }
}

impl From<PodValueHelper> for PodValue {
    fn from(helper: PodValueHelper) -> Self {
        match helper.value_type.as_str() {
            "string" => PodValue::String(helper.value.as_str().unwrap().to_string()),
            "int" => PodValue::Int(helper.value.as_i64().unwrap()),
            "cryptographic" => PodValue::Cryptographic(
                Fq::from_str(helper.value.as_str().unwrap()).unwrap()
            ),
            _ => panic!("Unknown PodValue type"),
        }
    }
}

pub type PodEntries = IndexMap<String, PodValue>;

#[derive(Debug, Serialize, Deserialize)]
pub struct PodClaim {
    entries: PodEntries,
    #[serde(rename = "signerPublicKey")]
    signer_public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PodProof {
    signature: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Pod {
    id: Uuid,
    claim: PodClaim,
    proof: PodProof,
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

impl Pod {
    pub fn entries(&self) -> PodEntries {
        self.claim.entries.clone()
    }
    
    pub fn get(&self, key: &str) -> Option<&PodValue> {
        self.claim.entries.get(key)
    }

    pub fn content_id(&self) -> Result<Fq, PodCreationError> {
        let mut hashes = Vec::new();
        for (k, v) in &self.claim.entries {
            hashes.push(pod_hash(&PodValue::String(k.to_string()))?);
            hashes.push(pod_hash(v)?);
        }
        lean_poseidon_imt(&hashes).map_err(|_| PodCreationError::ImtError)
    }

    pub fn signer_public_key(&self) -> Result<Point, String> {
        let compressed_key = general_purpose::STANDARD.decode(&self.claim.signer_public_key).map_err(|e| format!("{:?}", e))?;
        let compressed_key_arr: [u8; 32] = array::from_fn(|i| compressed_key[i]);
        decompress_point(compressed_key_arr)
    }

    pub fn signature(&self) -> Result<Signature, String> {
        let compressed_signature = general_purpose::STANDARD.decode(&self.proof.signature).map_err(|e| format!("{:?}", e))?;
        let compressed_signature_arr: [u8; 64] = array::from_fn(|i| compressed_signature[i]);
        decompress_signature(
            &compressed_signature_arr
                )
    }
    
pub fn verify(&self) -> Result<bool, Error> {
    // Reconstruct content ID
    let content_id = self.content_id()?;

    // Check proof
    let signer_public_key = self.signer_public_key()?;
    let signature = self.signature()?;

    Ok(verify(signer_public_key, signature, content_id))
}
}

pub fn pod_hash(value: &PodValue) -> Result<Fq, PodCreationError> {
    let poseidon = Poseidon::new();
    match value {
        PodValue::String(s) => {
            Ok(string_hash(s))
        }
        PodValue::Int(i) => 
            poseidon.hash(vec![Fq::from(*i)])
            .map_err(|e| PodCreationError::HashError(format!("Intenger hash failed: {}", e))),
        PodValue::Cryptographic(c) => poseidon.hash(vec![c.clone()]).map_err(|e| {
            PodCreationError::HashError(format!("Cryptographic hash (Big Int) failed: {}", e))
        }),
    }
}

pub fn string_hash(s: &str) -> Fq {
    let digest = Sha256::digest(s.as_bytes());
    // Right-shift by 8 bits
    PrimeField::from_be_bytes_mod_order(&digest[0..31])
}

#[derive(Error, Debug)]
pub enum PodCreationError {
    #[error("IMT computation failed")]
    ImtError,
    #[error("Signature generation failed")]
    SignatureError,
    #[error("Hash computation failed: {0}")]
    HashError(String),
}

pub fn create_pod<K>(private_key: &[u8], data: Vec<(K, PodValue)>) -> Result<Pod, PodCreationError>
where
    K: Into<String>,
{
    let entries: IndexMap<String, PodValue> =
        data.into_iter().map(|(k, v)| (k.into(), v)).collect();

    let hashes: Result<Vec<_>, PodCreationError> = entries
        .iter()
        .flat_map(|(k, v)| vec![pod_hash(&PodValue::String(k.to_string())), pod_hash(v)])
        .collect();
    let hashes = hashes?;

    let message = lean_poseidon_imt(&hashes).map_err(|_| PodCreationError::ImtError)?;
    
    let private_key = PrivateKey { key: array::from_fn(|i| private_key[i]) };
    let public_key = private_key.public();
    let sign =
        private_key.sign(message).map_err(|_| PodCreationError::SignatureError)?;

    Ok(Pod {
        id: Uuid::new_v4(),
        claim: PodClaim {
            entries,
            signer_public_key: general_purpose::STANDARD.encode(&public_key.compress()),
        },
        proof: PodProof {
            signature: general_purpose::STANDARD.encode(&sign.compress()),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    type Error = Box<dyn std::error::Error>;

    fn create_test_pod() -> Result<Pod, PodCreationError> {
        let private_key = vec![0u8; 32]; // Dummy private key for testing
        create_pod(
            &private_key,
            crate::pod_entries![
                "attack" => 7,
                "itemSet" => "celestial",
                "pod_type" => "item.weapon",
                "weaponType" => "sword"
            ],
        )
    }

    #[test]
    fn verify_test_pod() -> Result<(), Error> {
        let pod = create_test_pod()?;
        assert!(pod.verify()?);
        Ok(())
    }

    #[test]
    fn test_pod_creation_match_reference() -> Result<(), PodCreationError> {
        let pod = create_test_pod()?;
        dbg!(pod.content_id().expect("can't hash"));
        dbg!(hex::encode(
            pod.signer_public_key().expect("can't decode signer's public key").compress()
        ));
        dbg!(hex::encode(
            pod.signature().expect("can't decode sig").compress()
        ));

        Ok(())
    }

    #[test]
    fn test_pod_creation() -> Result<(), PodCreationError> {
        let pod = create_test_pod()?;
        assert_eq!(pod.claim.entries.len(), 4);
        assert_eq!(
            pod.get("itemSet"),
            Some(&PodValue::String("celestial".to_string()))
        );
        assert_eq!(pod.get("attack"), Some(&PodValue::Int(7)));

        Ok(())
    }

    #[test]
    fn test_pod_content_id() -> Result<(), PodCreationError> {
        let pod = create_test_pod()?;
        let content_id = pod.content_id().unwrap();
        assert!(content_id > Fq::from(0));
        Ok(())
    }

    #[test]
    fn test_pod_hash_string() {
        let hash = pod_hash(&PodValue::String("test".to_string())).unwrap();
        assert!(hash > Fq::from(0));
    }

    #[test]
    fn test_pod_hash_int() {
        let hash = pod_hash(&PodValue::Int(42)).unwrap();
        assert!(hash > Fq::from(0));
    }

    #[test]
    fn test_pod_hash_cryptographic() {
        let hash = pod_hash(&PodValue::Cryptographic(Fq::from(1234))).unwrap();
        assert!(hash > Fq::from(0));
    }

    #[test]
    fn test_from_impls() {
        assert_eq!(PodValue::from("test"), PodValue::String("test".to_string()));
        assert_eq!(
            PodValue::from(String::from("test")),
            PodValue::String("test".to_string())
        );
        assert_eq!(PodValue::from(42i64), PodValue::Int(42));
        assert_eq!(
            PodValue::from(Fq::from(1234)),
            PodValue::Cryptographic(Fq::from(1234))
        );
    }

    #[test]
    fn test_create_pod_with_different_types() {
        let private_key = vec![1u8; 32]; // Dummy private key for testing
        let pod = create_pod(
            &private_key,
            crate::pod_entries![
                "string" => "test",
                "int" => 42i64,
                "bigint" => Fq::from(1234),
            ],
        )
        .unwrap();

        assert_eq!(
            pod.get("string"),
            Some(&PodValue::String("test".to_string()))
        );
        assert_eq!(pod.get("int"), Some(&PodValue::Int(42)));
        assert_eq!(
            pod.get("bigint"),
            Some(&PodValue::Cryptographic(Fq::from(1234)))
        );
    }
}
