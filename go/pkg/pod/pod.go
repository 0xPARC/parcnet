package pod

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
)

// noPadB64 matches Rust's base64::STANDARD_NO_PAD
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
	Cmd        string                 `json:"cmd"`
	PrivateKey string                 `json:"private_key"`
	Entries    map[string]interface{} `json:"entries"`
}

// JSON from Rust for a verification response
type verifyResponse struct {
	Verified bool   `json:"verified"`
	Error    string `json:"error,omitempty"`
}

func toJSONPOD(p *Pod) JSONPOD {
	return JSONPOD{
		Entries:         p.Claim.Entries,
		Signature:       p.Proof.Signature,
		SignerPublicKey: p.Claim.SignerPublicKey,
	}
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

func dispatchRustCommand(req podCommandRequest) (*Pod, string, error) {
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal request: %w", err)
	}

	cmd := exec.Command("./pod_cli") // Ensure ./pod_cli is in your path or same folder
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

	if _, err := stdin.Write(reqBytes); err != nil {
		return nil, "", fmt.Errorf("failed writing to stdin: %w", err)
	}
	stdin.Close()

	outBytes, err := io.ReadAll(stdout)
	if werr := cmd.Wait(); werr != nil {
		return nil, "", fmt.Errorf("rust process error: %w", werr)
	}
	if err != nil {
		return nil, "", fmt.Errorf("failed reading stdout: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(outBytes, &raw); err != nil {
		return nil, "", fmt.Errorf("failed unmarshal raw: %w\nOutput: %s", err, string(outBytes))
	}

	if err := hexEncodeField(raw, "claim", "signerPublicKey", 32); err != nil {
		return nil, "", err
	}
	if err := hexEncodeField(raw, "proof", "signature", 64); err != nil {
		return nil, "", err
	}

	remarshaled, err := json.Marshal(raw)
	if err != nil {
		return nil, "", fmt.Errorf("failed re-marshal: %w", err)
	}
	var pod Pod
	if err := json.Unmarshal(remarshaled, &pod); err != nil {
		return nil, "", fmt.Errorf("failed final unmarshal Pod: %w", err)
	}

	jsonPod := toJSONPOD(&pod)
	jsonPodBytes, err := json.Marshal(jsonPod)
	if err != nil {
		return &pod, "", fmt.Errorf("failed to marshal JSONPOD: %w", err)
	}

	return &pod, string(jsonPodBytes), nil
}