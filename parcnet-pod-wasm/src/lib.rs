mod utils;

use wasm_bindgen::prelude::*;
use parcnet_pod::pod::Pod;
use parcnet_pod::pod::PodEntries;
use babyjubjub_ark::PrivateKey;

#[wasm_bindgen]
pub fn sign_pod(entries: String, private_key: &[u8]) -> Result<String, JsValue> {
    let entries: PodEntries = serde_json::from_str(&entries)
        .map_err(|e| JsValue::from(e.to_string()))?;
    let private_key = PrivateKey::import(private_key.to_vec())?;
    let pod = Pod::sign(entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect(), private_key);
    match pod {
        Ok(pod) => Ok(serde_json::to_string(&pod).unwrap()),
        Err(e) => Err(e.to_string().into())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_sign_pod() {
        // Create a sample private key (32 bytes)
        let private_key = vec![1u8; 32];
        
        // Create a sample pod entries
        let mut entries = HashMap::new();
        entries.insert("name".to_string(), "Alice".to_string());
        entries.insert("age".to_string(), "30".to_string());
        
        // Convert entries to JSON string
        let entries_json = serde_json::to_string(&entries).unwrap();
        
        // Sign the pod
        let result = sign_pod(entries_json, &private_key);
        
        // Assert the result is Ok and contains a valid JSON string
        assert!(result.is_ok());
        
        // Parse the result back to verify it's valid JSON
        let pod_json = result.unwrap();
        let pod: Pod = serde_json::from_str(&pod_json).unwrap();
        
        // Verify the pod contains our entries
        assert_eq!(pod.entries().get("name").unwrap(), &"Alice".into());
        assert_eq!(pod.entries().get("age").unwrap(), &"30".into());
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_sign_pod() {
        // Skip test on non-wasm targets
        println!("Skipping test on non-wasm target");
    }
}

