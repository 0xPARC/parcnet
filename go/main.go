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

func hexEncodeSignerPublicKey(raw map[string]interface{}) error {
	claim, ok := raw["claim"].(map[string]interface{})
	if !ok {
		return nil
	}
	spkVal, ok := claim["signerPublicKey"].(string)
	if !ok {
		return nil
	}
	decoded, err := noPadB64.DecodeString(spkVal)
	if err != nil {
		return fmt.Errorf("publicKey not valid no-pad base64: %v", err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("publicKey is %d bytes, expected 32", len(decoded))
	}
	hexVal := hex.EncodeToString(decoded)
	claim["signerPublicKey"] = hexVal
	return nil
}

func hexEncodeSignature(raw map[string]interface{}) error {
	proof, ok := raw["proof"].(map[string]interface{})
	if !ok {
		return nil
	}
	sigVal, ok := proof["signature"].(string)
	if !ok {
		return nil
	}
	decoded, err := noPadB64.DecodeString(sigVal)
	if err != nil {
		return fmt.Errorf("signature not valid no-pad base64: %v", err)
	}
	if len(decoded) != 64 {
		return fmt.Errorf("signature is %d bytes, expected 64", len(decoded))
	}
	hexVal := hex.EncodeToString(decoded)
	proof["signature"] = hexVal
	return nil
}

func NewPod(privateKey string, entries map[string]interface{}) (*Pod, string, error) {

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
	if err := hexEncodeSignerPublicKey(raw); err != nil {
		return nil, "", err
	}
	if err := hexEncodeSignature(raw); err != nil {
		return nil, "", err
	}

	// 6) Now re-marshal the map and unmarshal into our Pod struct
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