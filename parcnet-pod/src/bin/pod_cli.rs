use std::io::{self, Read};
use std::collections::HashMap;

use babyjubjub_ark::PrivateKey;
use parcnet_pod::pod::{create_pod, Pod, PodCreationError, PodValue};
use serde::{Deserialize, Serialize};

pub(crate) type Error = Box<dyn std::error::Error>;

#[derive(Deserialize)]
#[serde(tag = "cmd")]
struct PodCommand {
    cmd: String,

    #[serde(default)]
    private_key: String,

    #[serde(default)]
    entries: HashMap<String, serde_json::Value>,

    #[serde(default)]
    pod_json: String,
}

fn main() -> Result<(), Error> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;

    let command: PodCommand = serde_json::from_str(&buffer)?;

    let result = match command.cmd.as_str() {
        "create" => handle_create(&command),
        "sign"   => handle_sign(&command),
        "verify" => handle_verify(&command),
        other => Err(format!("unknown cmd: {}", other).into())
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

fn handle_create(command: &PodCommand) -> Result<String, Error> {
    let pk_bytes = parse_private_key(&command.private_key)?;
    let data_pairs = convert_entries(&command.entries)?;
    let pod = create_pod(&pk_bytes, data_pairs)?;

    // Return the entire Pod as JSON
    let out = serde_json::to_string(&pod)?;
    Ok(out)
}

fn handle_sign(command: &PodCommand) -> Result<String, Error> {
    let pk_bytes = parse_private_key(&command.private_key)?;
    let data_pairs = convert_entries(&command.entries)?;

    let private_key = PrivateKey { key: pk_bytes };
    let pod = Pod::sign(data_pairs, private_key)?;
    let out = serde_json::to_string(&pod)?;
    Ok(out)
}

#[derive(Serialize)]
struct VerifyResponse {
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn handle_verify(command: &PodCommand) -> Result<String, Error> {
    let pod: Pod = serde_json::from_str(&command.pod_json)
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
    let decoded = hex::decode(pk_hex)
        .map_err(|_| PodCreationError::SignatureError)?;
    if decoded.len() != 32 {
        return Err(PodCreationError::SignatureError);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&decoded);
    Ok(arr)
}

fn convert_entries(
    map: &HashMap<String, serde_json::Value>
) -> Result<Vec<(String, PodValue)>, PodCreationError> {
    let mut out = Vec::new();
    for (k, v) in map {
        out.push((k.clone(), json_to_pod_value(v)?));
    }
    Ok(out)
}

fn json_to_pod_value(val: &serde_json::Value) -> Result<PodValue, PodCreationError> {
    if let Some(s) = val.as_str() {
        Ok(PodValue::String(s.to_string()))
    } else if let Some(i) = val.as_i64() {
        Ok(PodValue::Int(i))
    } else if let Some(b) = val.as_bool() {
        Ok(PodValue::Boolean(b))
    } else if val.is_null() {
        Ok(PodValue::Null)
    } else {
        Err(PodCreationError::HashError("unhandled type".to_string()))
    }
}