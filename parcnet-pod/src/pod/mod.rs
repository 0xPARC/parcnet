pub mod macros;
pub mod zupass;
mod serialisation;
pub mod value;

use std::array;

use rayon::prelude::*;
pub use ark_bn254::Fr as Fq;

use babyjubjub_ark::{decompress_point, decompress_signature, verify, Point, PrivateKey, Signature};
use base64::{engine::general_purpose, Engine as _};
use indexmap::IndexMap;
use thiserror::Error;
use time::OffsetDateTime;


use serde::{Deserialize, Serialize};

use uuid::Uuid;
use value::PodValue;

use crate::crypto::lean_imt::lean_poseidon_imt;

pub(crate) type Error = Box<dyn std::error::Error>;


pub type PodEntries = IndexMap<String, PodValue>; 

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PodClaim {
    entries: PodEntries,
    signer_public_key: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PodProof {
    signature: String
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
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

impl Pod {
    pub fn sign<K>(data: Vec<(K, PodValue)>, private_key: PrivateKey) -> Result<Self, PodCreationError>
where
    K: Into<String> + Clone,
{
    let mut entry_alist = data;
    entry_alist.sort_by(|(k1, _), (k2, _)| Into::<String>::into(k1.clone()).cmp(&Into::<String>::into(k2.clone())));
    let entries: IndexMap<String, PodValue> =
        entry_alist.into_iter().map(|(k, v)| (k.into(), v)).collect();

    let hashes: Result<Vec<_>, PodCreationError> = entries
        .par_iter()
        .flat_map(|(k, v)| vec![PodValue::String(k.to_string()).hash(), v.hash()])
        .collect();
    let hashes = hashes?;

    let message = lean_poseidon_imt(&hashes).map_err(|_| PodCreationError::ImtError)?;
    
    let public_key = private_key.public();
    let sign =
        private_key.sign(message).map_err(|_| PodCreationError::SignatureError)?;

    Ok(Pod {
        id: Uuid::new_v4(),
        claim: PodClaim {
            entries,
            signer_public_key: general_purpose::STANDARD_NO_PAD.encode(public_key.compress()),
        },
        proof: PodProof {
            signature: general_purpose::STANDARD_NO_PAD.encode(sign.compress()),
        },
    })
    }
    
    pub fn entries(&self) -> PodEntries {
        self.claim.entries.clone()
    }
    
    pub fn get(&self, key: &str) -> Option<&PodValue> {
        self.claim.entries.get(key)
    }

    pub fn content_id(&self) -> Result<Fq, PodCreationError> {
        let hashes =
            self.claim.entries.par_iter().flat_map(
                |(k,v)|
                  [PodValue::String(k.to_string()).hash(), v.hash()]
            ).collect::<Result<Vec<_>, PodCreationError>>()?;
        lean_poseidon_imt(&hashes).map_err(|_| PodCreationError::ImtError)
    }

    pub fn signer_public_key(&self) -> Result<Point, String> {
        let compressed_key = general_purpose::STANDARD_NO_PAD.decode(&self.claim.signer_public_key).map_err(|e| format!("{:?}", e))?;
        let compressed_key_arr: [u8; 32] = array::from_fn(|i| compressed_key[i]);
        decompress_point(compressed_key_arr)
    }

    pub fn signature(&self) -> Result<Signature, String> {
        let compressed_signature = general_purpose::STANDARD_NO_PAD.decode(&self.proof.signature).map_err(|e| format!("{:?}", e))?;
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
    K: Into<String> + Clone,
{
    let mut entry_alist = data;
    entry_alist.sort_by(|(k1, _), (k2, _)| Into::<String>::into(k1.clone()).cmp(&Into::<String>::into(k2.clone())));
    let entries: IndexMap<String, PodValue> =
        entry_alist.into_iter().map(|(k, v)| (k.into(), v)).collect();

    let hashes: Result<Vec<_>, PodCreationError> = entries
        .iter()
        .flat_map(|(k, v)| vec![PodValue::String(k.to_string()).hash(), v.hash()])
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
            signer_public_key: general_purpose::STANDARD_NO_PAD.encode(public_key.compress()),
        },
        proof: PodProof {
            signature: general_purpose::STANDARD_NO_PAD.encode(sign.compress()),
        },
    })
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
    use time::macros::datetime;
    use std::str::FromStr;

    use super::*;

    fn create_test_pod() -> Result<Pod, PodCreationError> {
        // Follows the example given in test/common.ts in the @pcd/pod package.
        let private_key = [0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1];
        create_pod(
            &private_key,
            crate::pod_entries![
                "E" => -123,
                "F" => Fq::from(-1),
                "C" => "hello",
                "D" => "foobar",
                "A" => 123,
                "B" => 321,
                "G" => 7,
                "H" => 8,
                "I" => 9,
                "J" => 10,
                "publicKey" => PodValue::EdDSAPublicKey(Point {
                    x: Fq::from_str("13277427435165878497778222415993513565335242147425444199013288855685581939618").unwrap(),
                    y: Fq::from_str("13622229784656158136036771217484571176836296686641868549125388198837476602820").unwrap()
                }),
                "owner" => Fq::from_str("18711405342588116796533073928767088921854096266145046362753928030796553161041").unwrap(),
            ],
        )
    }

    fn create_test_pod2() -> Result<Pod, PodCreationError> {
        // Follows the second example given in test/common.ts in the @pcd/pod package.
        let private_key = [0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1];
        create_pod(
            &private_key,
            crate::pod_entries![
                "attendee" => Fq::from_str("18711405342588116796533073928767088921854096266145046362753928030796553161041").unwrap(),
                "eventID" => Fq::from(456),
                "ticketID" => Fq::from(999),
                "isConsumed" => true,
                "issueDate" => datetime!(2024-01-01 00:00:00 UTC),
                "image" => [1u8,2,3].as_slice(),
                "vipStatus" => ()
            ],
        )
    }

    // TODO: More roundtrip tests.
    #[test]
    fn test_serde_json() -> Result<(), Error> {
        let pod = create_test_pod()?;
        let serialised_pod = serde_json::to_string(&pod)?;
        let deserialised_pod: Pod = serde_json::from_str(&serialised_pod)?;
        assert!(deserialised_pod == pod);
        Ok(())
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
        assert_eq!(pod.claim.entries.len(), 12);
        assert_eq!(
            pod.get("G"),
            Some(&PodValue::Int(7))
        );
        assert_eq!(pod.get("F"), Some(&PodValue::Cryptographic(Fq::from(-1))));

        Ok(())
    }

    #[test]
    fn test_against_pcd_pod_values() -> Result<(), Error> {
        let pod = create_test_pod()?;
        let pod2 = create_test_pod2()?;
        
        assert!(pod.content_id()? == Fq::from_str("18003549444852780886592139349318927700964545643704389119309344945101355208480").map_err(|e| format!("{:?}", e))?);
        assert!(pod.signature()? == decompress_signature(&{
            let byte_vec = b64.decode("Jp3i2PnnRoLCmVPzgM6Bowchg44jz3fKuMQPzXQqWy4jzPFpZx2KwLuaIYaeYbd7Ah4FusEht2VhsVf3I81AAg")?;
            array::from_fn(|i| byte_vec[i])
        })?);

        
        assert!(pod2.content_id()? == Fq::from_str("14490445713061892907571559700953246722753167030842690801373581812224357192993").map_err(|e| format!("{:?}", e))?);
        assert!(pod2.signature()? == decompress_signature(&{
            let byte_vec = b64.decode("XsPL63NJKkq59CiO8VC3vDFNGPeNfnDsN3ugn68aOQjOvAMLiRqE2ISEBQSJlAxb9eokyyauUuKlGyD98FeSBQ")?;
            array::from_fn(|i| byte_vec[i])
        })?);        

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
        let hash = PodValue::String("test".to_string()).hash().unwrap();
        assert!(hash > Fq::from(0));
    }

    #[test]
    fn test_pod_hash_int() {
        let hash = PodValue::Int(42).hash().unwrap();
        assert!(hash > Fq::from(0));
    }

    #[test]
    fn test_pod_hash_cryptographic() {
        let hash = PodValue::Cryptographic(Fq::from(1234)).hash().unwrap();
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
