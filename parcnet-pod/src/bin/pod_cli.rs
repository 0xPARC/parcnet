use std::io::{self, Read};

use parcnet_pod::pod::{create_pod_from_map, Pod, PodCreationError, PodEntries};
use serde::{Deserialize, Serialize};

pub(crate) type Error = Box<dyn std::error::Error>;

#[derive(Deserialize)]
#[serde(tag = "cmd")]
enum PodCommand {
    #[serde(rename = "create")]
    Create {
        private_key: String,
        entries: PodEntries,
    },
    #[serde(rename = "verify")]
    Verify {
        pod_json: String,
    },
}

fn main() -> Result<(), Error> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;

    let command: PodCommand = serde_json::from_str(&buffer)?;

    let result = match command {
        PodCommand::Create { private_key, entries } => handle_create(&private_key, &entries),
        PodCommand::Verify { pod_json } => handle_verify(&pod_json),
    };

    match result {
        Ok(json_output) => {
            println!("{}", json_output);
        }
        Err(e) => {
            eprintln!("Pod creation failed: {:?}", e);
            std::process::exit(1);
        }
    }
    Ok(())
}

fn handle_create(private_key: &str, entries: &PodEntries) -> Result<String, Error> {
    let pk_bytes = parse_private_key(&private_key)?;
    let pod = create_pod_from_map(&pk_bytes, entries.clone())?;
    let out = serde_json::to_string(&pod)?;
    Ok(out)
}

#[derive(Serialize)]
struct VerifyResponse {
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn handle_verify(pod_json: &str) -> Result<String, Error> {
    let pod: Pod = serde_json::from_str(&pod_json)
        .map_err(|e| PodCreationError::HashError(format!("verify parse error: {}", e)))?;

    match pod.verify() {
        Ok(is_verified) => {
            let resp = VerifyResponse {
                verified: is_verified,
                error: None,
            };
            Ok(serde_json::to_string(&resp)?)
        }
        Err(e) => {
            let resp = VerifyResponse {
                verified: false,
                error: Some(format!("verify error: {}", e)),
            };
            Ok(serde_json::to_string(&resp)?)
        }
    }
}

fn parse_private_key(pk_hex: &str) -> Result<[u8; 32], PodCreationError> {
    let decoded = hex::decode(pk_hex).map_err(|_| PodCreationError::SignatureError)?;
    if decoded.len() != 32 {
        return Err(PodCreationError::SignatureError);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&decoded);
    Ok(arr)
}
