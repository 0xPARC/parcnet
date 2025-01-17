use std::io::{self, Read};
use babyjubjub_ark::PrivateKey;
use parcnet_pod::pod::{create_pod, Pod, PodCreationError};
use parcnet_pod::pod::PodValue;
use serde::Deserialize;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read all JSON from stdin
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    let command: PodCommand = serde_json::from_str(&buffer)?;

    // Dispatch based on cmd
    let pod_result = match command.cmd.as_str() {
        "create" => handle_create(&command),
        "sign" => handle_sign(&command),
        other => Err(PodCreationError::HashError(format!("unknown cmd: {}", other))),
    };

    // Print the resulting Pod or an error
    match pod_result {
        Ok(pod) => {
            let out = serde_json::to_string(&pod)?;
            println!("{}", out);
        }
        Err(e) => {
            // You could print a structured error if you like
            eprintln!("Pod creation failed: {:?}", e);
            // Or output JSON error structure
            // For simplicity, we'll just exit with error code
            std::process::exit(1);
        }
    }

    Ok(())
}

#[derive(Deserialize)]
struct PodCommand {
    // e.g. "create" or "sign"
    cmd: String,

    // Common fields for both commands
    private_key: String,
    entries: std::collections::HashMap<String, serde_json::Value>,
}

fn handle_create(command: &PodCommand) -> Result<Pod, PodCreationError> {
    let pk_bytes = parse_private_key(&command.private_key)?;
    let data_pairs = convert_entries(&command.entries)?;
    create_pod(&pk_bytes, data_pairs)
}

fn handle_sign(command: &PodCommand) -> Result<Pod, PodCreationError> {
    let pk_bytes = parse_private_key(&command.private_key)?;
    let data_pairs = convert_entries(&command.entries)?;

    // Construct the PrivateKey
    let private_key = PrivateKey { key: pk_bytes };

    // Convert Vec<(String, PodValue)> for the Pod::sign call
    let pod = Pod::sign(data_pairs, private_key)?;
    Ok(pod)
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

fn convert_entries(
    entries: &std::collections::HashMap<String, serde_json::Value>,
) -> Result<Vec<(String, PodValue)>, PodCreationError> {
    let mut converted = Vec::new();
    for (k, v) in entries.iter() {
        converted.push((k.clone(), json_to_pod_value(v)?));
    }
    Ok(converted)
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
        Err(PodCreationError::HashError("Unhandled type".to_string()))
    }
}