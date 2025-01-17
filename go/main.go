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

type podCommandRequest struct {
	Cmd        string                 `json:"cmd"`         // "create" or "sign"
	PrivateKey string                 `json:"private_key"` // 64 hex chars
	Entries    map[string]interface{} `json:"entries"`     // for create/sign
}

func toJSONPOD(p *Pod) JSONPOD {
	return JSONPOD{
		Entries:         p.Claim.Entries,
		Signature:       p.Proof.Signature,
		SignerPublicKey: p.Claim.SignerPublicKey,
	}
}

func hexEncodeField(raw map[string]interface{}, parentKey, fieldKey string, expectedLen int) error {
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

func CreatePod(privateKey string, entries map[string]interface{}) (*Pod, string, error) {
	if err := validatePrivateKeyHex(privateKey); err != nil {
		return nil, "", fmt.Errorf("invalid private key: %w", err)
	}

	req := podCommandRequest{
		Cmd:        "create",
		PrivateKey: privateKey,
		Entries:    entries,
	}
	return dispatchRustCommand(req)
}

func SignPod(privateKey string, entries map[string]interface{}) (*Pod, string, error) {
	if err := validatePrivateKeyHex(privateKey); err != nil {
		return nil, "", fmt.Errorf("invalid private key: %w", err)
	}

	req := podCommandRequest{
		Cmd:        "sign",
		PrivateKey: privateKey,
		Entries:    entries,
	}
	return dispatchRustCommand(req)
}

func dispatchRustCommand(req podCommandRequest) (*Pod, string, error) {
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Spawn Rust CLI
	cmd := exec.Command("./pod_cli")
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

	// Write JSON request
	if _, err := stdin.Write(reqBytes); err != nil {
		return nil, "", fmt.Errorf("failed writing to stdin: %w", err)
	}
	stdin.Close()

	// Read JSON response
	outBytes, err := io.ReadAll(stdout)
	if err := cmd.Wait(); err != nil {
		return nil, "", fmt.Errorf("process error: %w", err)
	}
	if err != nil {
		return nil, "", fmt.Errorf("failed reading stdout: %w", err)
	}

	// Unmarshal into generic map => fix up fields => re-unmarshal
	var raw map[string]interface{}
	if err := json.Unmarshal(outBytes, &raw); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal raw Pod: %w", err)
	}

	// Convert base64 => hex for publicKey, signature
	if err := hexEncodeField(raw, "claim", "signerPublicKey", 32); err != nil {
		return nil, "", err
	}
	if err := hexEncodeField(raw, "proof", "signature", 64); err != nil {
		return nil, "", err
	}

	remarshaled, err := json.Marshal(raw)
	if err != nil {
		return nil, "", fmt.Errorf("failed to re-marshal after hex conversion: %w", err)
	}
	var pod Pod
	if err := json.Unmarshal(remarshaled, &pod); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal Pod: %w", err)
	}

	// Produce final JSONPOD string
	jsonPodStruct := toJSONPOD(&pod)
	jsonPodBytes, err := json.Marshal(jsonPodStruct)
	if err != nil {
		return &pod, "", fmt.Errorf("failed to marshal JSONPOD: %w", err)
	}

	return &pod, string(jsonPodBytes), nil
}

func main() {
	fmt.Println("=== CREATE POD  ===")
	podObj, jsonPodString, err := CreatePod(
		"0001020304050607080900010203040506070809000102030405060708090001",
		map[string]interface{}{
			"created_by": "Golang",
			"year":       2025,
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Pod:")
	fmt.Println(podObj)
	fmt.Println()
	fmt.Println("JSONPOD:")
	fmt.Println(jsonPodString)

	fmt.Println("\n=== SIGN POD  ===")
	podObj2, jsonPodString2, err := SignPod(
		"0001020304050607080900010203040506070809000102030405060708090001",
		map[string]interface{}{
			"some_data": "some_value",
			"count":     42,
			"ffi":       false,
			"ipc":       true,
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Signed Pod:")
	fmt.Println(podObj2)
	fmt.Println()
	fmt.Println("JSONPOD:")
	fmt.Println(jsonPodString2)
}
