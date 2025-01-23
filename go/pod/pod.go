package pod

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
)

type Pod struct {
	Entries         map[string]interface{} `json:"entries"`
	Signature       string                 `json:"signature"`
	SignerPublicKey string                 `json:"signerPublicKey"`
}

type podCommandRequest struct {
	Cmd        string                 `json:"cmd"`
	PrivateKey string                 `json:"private_key"`
	Entries    map[string]interface{} `json:"entries"`
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

func dispatchRustCommand(req podCommandRequest) (*Pod, string, error) {
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal request: %w", err)
	}

	cmd := exec.Command("./pod_worker")
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

	remarshaled, err := json.Marshal(raw)
	if err != nil {
		return nil, "", fmt.Errorf("failed re-marshal: %w", err)
	}
	var pod Pod
	if err := json.Unmarshal(remarshaled, &pod); err != nil {
		return nil, "", fmt.Errorf("failed final unmarshal Pod: %w", err)
	}

	jsonPodBytes, err := json.Marshal(pod)
	if err != nil {
		return &pod, "", fmt.Errorf("failed to marshal JSONPOD: %w", err)
	}

	return &pod, string(jsonPodBytes), nil
}
