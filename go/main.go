package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
)

// Unpadded Base64 for decoding (matching Rust base64::STANDARD_NO_PAD)
var noPadB64 = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/").WithPadding(base64.NoPadding)

type Pod struct {
	ID    string `json:"id"`
	Claim struct {
		Entries         map[string]interface{} `json:"entries"`
		SignerPublicKey string                 `json:"signerPublicKey"`
	} `json:"claim"`
	Proof struct {
		Signature string `json:"signature"`
	} `json:"proof"`
}

type JSONPOD struct {
	Entries         map[string]interface{} `json:"entries"`
	Signature       string                 `json:"signature"`
	SignerPublicKey string                 `json:"signerPublicKey"`
}

// Request sent to Rust binary
type createPodRequest struct {
	PrivateKey string                 `json:"private_key"`
	Entries    map[string]interface{} `json:"entries"`
}

func toJSONPOD(p *Pod) JSONPOD {
	return JSONPOD{
		Entries:         p.Claim.Entries,
		Signature:       p.Proof.Signature,
		SignerPublicKey: p.Claim.SignerPublicKey,
	}
}

func hexEncodeField(raw map[string]interface{}, parentKey string, fieldKey string, expectedLen int) error {
	parent, ok := raw[parentKey].(map[string]interface{})
	if !ok {
		return nil
	}
	fieldVal, ok := parent[fieldKey].(string)
	if !ok {
		return nil
	}
	decoded, err := noPadB64.DecodeString(fieldVal)
	if err != nil {
		return fmt.Errorf("%s not valid no-pad base64: %v", fieldKey, err)
	}
	if len(decoded) != expectedLen {
		return fmt.Errorf("%s is %d bytes, expected %d", fieldKey, len(decoded), expectedLen)
	}
	hexVal := hex.EncodeToString(decoded)
	parent[fieldKey] = hexVal
	return nil
}

func validatePrivateKeyHex(pk string) error {
    if len(pk) != 64 {
        return fmt.Errorf("private key must be 64 hex characters (32 bytes), got length %d", len(pk))
    }
    decoded, err := hex.DecodeString(pk)
    if err != nil {
        return fmt.Errorf("private key '%s' isn't valid hex: %v", pk, err)
    }
    if len(decoded) != 32 {
        return fmt.Errorf("decoded private key is %d bytes, expected 32", len(decoded))
    }
    return nil
}

// privateKey is the 32-byte hex-encoded private key that will sign the POD
// entries is the map of key-value pairs to be included in the POD
func NewPod(privateKey string, entries map[string]interface{}) (*Pod, string, error) {
	if err := validatePrivateKeyHex(privateKey); err != nil {
		return nil, "", fmt.Errorf("invalid private key: %w", err)
	}

	req := createPodRequest{
		PrivateKey: privateKey,
		Entries:    entries,
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Spawn Rust binary
	cmd := exec.Command("./pod_creator")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, "", fmt.Errorf("failed to start process: %w", err)
	}

	// Write JSON to Rust
	if _, err := stdin.Write(reqBytes); err != nil {
		return nil, "", fmt.Errorf("failed writing to stdin: %w", err)
	}
	stdin.Close()

	// Read JSON from Rust
	outBytes, err := io.ReadAll(stdout)
	if err != nil {
		return nil, "", fmt.Errorf("failed reading stdout: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return nil, "", fmt.Errorf("process error: %w", err)
	}

	// We first unmarshal into a generic map to do the hex conversions
	var raw map[string]interface{}
	if err := json.Unmarshal(outBytes, &raw); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal raw Pod: %w", err)
	}

	// Convert base64 -> hex for publicKey and signature
	if err := hexEncodeField(raw, "claim", "signerPublicKey", 32); err != nil {
		return nil, "", err
	}
	if err := hexEncodeField(raw, "proof", "signature", 64); err != nil {
		return nil, "", err
	}

	// Now re-marshal the map and unmarshal into our Pod struct
	remarshaled, err := json.Marshal(raw)
	if err != nil {
		return nil, "", fmt.Errorf("failed to re-marshal after hex conversion: %w", err)
	}
	var pod Pod
	if err := json.Unmarshal(remarshaled, &pod); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal Pod: %w", err)
	}

	jsonPod := toJSONPOD(&pod)
	jsonPodBytes, err := json.Marshal(jsonPod)
	if err != nil {
		return &pod, "", fmt.Errorf("failed to marshal JSONPOD: %w", err)
	}
	return &pod, string(jsonPodBytes), nil
}

func main() {
	podObj, jsonPodString, err := NewPod(
		"0001020304050607080900010203040506070809000102030405060708090001",
		map[string]interface{}{
			"created_by": "Golang",
			"year":       2025,
		},
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("=== Pod Struct ===")
	fmt.Printf("%+v\n", podObj)

	fmt.Println("\n=== JSONPOD Output ===")
	fmt.Println(jsonPodString)
}