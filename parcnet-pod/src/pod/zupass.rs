use crate::pod::Pod;
use crate::pod::serialisation::{compressed_pt_de, compressed_pt_ser, compressed_sig_de, compressed_sig_ser};
use babyjubjub_ark::{Point, Signature};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use super::PodEntries;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PodPcdClaim {
    entries: PodEntries,
    #[serde(
        serialize_with = "compressed_pt_ser",
        deserialize_with = "compressed_pt_de"
    )]
    signer_public_key: Point,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PodPcdProof {
    #[serde(
        serialize_with = "compressed_sig_ser",
        deserialize_with = "compressed_sig_de"
    )]
    signature: Signature,
}

/// PODPCD is the representation of a POD in PCD clients like Zupass.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PodPcd {
    id: Uuid,
    claim: PodPcdClaim,
    proof: PodPcdProof,
}

impl Into<PodPcd> for Pod {
    fn into(self) -> PodPcd {
        let id = Uuid::new_v4();
        let claim = PodPcdClaim {
            entries: self.entries,
            signer_public_key: self.signer_public_key,
        };
        let proof = PodPcdProof {
            signature: self.signature,
        };
        PodPcd { id, claim, proof }
    }
}

impl Into<Pod> for PodPcd {
    fn into(self) -> Pod {
        Pod {
            entries: self.claim.entries,
            signer_public_key: self.claim.signer_public_key,
            signature: self.proof.signature,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ZupassPcdWrapper {
    #[serde(rename = "type")]
    pcd_type: String,
    pcd: String,
}

#[derive(Serialize, Deserialize)]
struct ZupassRequest {
    #[serde(rename = "type")]
    request_type: String,
    #[serde(rename = "returnUrl")]
    return_url: String,
    pcd: ZupassPcdWrapper,
}

impl PodPcd {
    pub fn make_zupass_url(&self, return_url: &str) -> Result<Url, Box<dyn std::error::Error>> {
        let pcd_json = serde_json::to_string(self)?;

        let request = ZupassRequest {
            request_type: "Add".to_string(),
            return_url: return_url.to_string(),
            pcd: ZupassPcdWrapper {
                pcd_type: "pod-pcd".to_string(),
                pcd: pcd_json,
            },
        };

        let request_json = serde_json::to_string(&request)?;
        let encoded_request = urlencoding::encode(&request_json);

        let zupass_url = format!("https://zupass.org/#/add?request={}", encoded_request);
        Ok(Url::parse(&zupass_url)?)
    }
    pub fn make_zupass_url_default_return_url(&self) -> Result<Url, Box<dyn std::error::Error>> {
        self.make_zupass_url("https://zupass.org/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pod::{create_pod, PodValue};

    #[test]
    fn test_make_zupass_url_two_value_failing_zupass_verification() {
        let private_key = vec![0u8; 32]; // Dummy private key for testing
        let pod = create_pod(
            &private_key,
            crate::pod_entries![
                "name" => "John Doe",
                "age" => 30
            ],
        )
        .unwrap();

        let pod_pcd: PodPcd = pod.into();

        let url_str = pod_pcd
            .make_zupass_url_default_return_url()
            .unwrap()
            .to_string();

        dbg!(url_str);
    }

    #[test]
    fn test_make_zupass_url() {
        let private_key = vec![0u8; 32]; // Dummy private key for testing
        let pod = create_pod(
            &private_key,
            crate::pod_entries![
                "attack" => 7,
                "itemSet" => "celestial",
                "pod_type" => "item.weapon",
                "weaponType" => "sword"
            ],
        )
        .unwrap();

        let pod_pcd: PodPcd = pod.into();

        let url_str = pod_pcd
            .make_zupass_url_default_return_url()
            .unwrap()
            .to_string();

        // Extract everything after "add?request="
        let request_param = url_str.split("add?request=").nth(1).unwrap();

        // URL decode the extracted parameter
        let decoded_request = urlencoding::decode(request_param).unwrap();

        // Parse the JSON request
        let request: ZupassRequest = serde_json::from_str(&decoded_request).unwrap();

        // Verify the request properties
        assert_eq!(request.request_type, "Add");
        assert_eq!(request.return_url, "https://zupass.org/");
        assert_eq!(request.pcd.pcd_type, "pod-pcd");

        // Parse the PCD (which should be our POD)
        let parsed_pod_pcd: PodPcd = serde_json::from_str(&request.pcd.pcd).unwrap();

        // Verify the POD contents
        assert_eq!(
            parsed_pod_pcd.claim.entries.get("itemSet"),
            Some(&PodValue::String("celestial".to_string()))
        );
        assert_eq!(
            parsed_pod_pcd.claim.entries.get("attack"),
            Some(&PodValue::Int(7))
        );
    }
    
    #[test]
    fn test_pod_pcd_conversion() {
        let private_key = vec![0u8; 32]; // Dummy private key for testing
        let pod = create_pod(
            &private_key,
            crate::pod_entries![
                "attack" => 7,
                "itemSet" => "celestial",
                "pod_type" => "item.weapon",
                "weaponType" => "sword"
            ],
        )
        .unwrap();
        let pod_pcd: PodPcd = pod.clone().into();
        let pod2: Pod = pod_pcd.into();
        
        // Both PODs should match up.
        assert_eq!(pod, pod2);
    }
}