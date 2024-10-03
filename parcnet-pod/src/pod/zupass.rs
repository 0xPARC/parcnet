use crate::pod::pod_impl::Pod;
use serde::{Deserialize, Serialize};
use url::Url;

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

impl Pod {
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
    use crate::pod::pod_impl::{create_pod, PodValue};

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

        let url_str = pod
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

        let url_str = pod
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
        let parsed_pod: Pod = serde_json::from_str(&request.pcd.pcd).unwrap();

        // Verify the POD contents
        assert_eq!(
            parsed_pod.get("itemSet"),
            Some(&PodValue::String("celestial".to_string()))
        );
        assert_eq!(parsed_pod.get("attack"), Some(&PodValue::Int(7)));
    }
}
