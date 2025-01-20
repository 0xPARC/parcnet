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

func (p *Pod) Verify() (bool, error) {
	podCopy := *p

	if len(podCopy.SignerPublicKey) == 64 {
		rawSPK, err := hex.DecodeString(podCopy.SignerPublicKey)
		if err != nil {
			return false, fmt.Errorf("failed decode signerPublicKey: %w", err)
		}
		podCopy.SignerPublicKey = noPadB64.EncodeToString(rawSPK)
	}
	if len(podCopy.Signature) == 128 {
		rawSig, err := hex.DecodeString(podCopy.Signature)
		if err != nil {
			return false, fmt.Errorf("failed decode signature hex: %w", err)
		}
		podCopy.Signature = noPadB64.EncodeToString(rawSig)
	}

	podBytes, err := json.Marshal(podCopy)
	if err != nil {
		return false, fmt.Errorf("marshal Pod for verify: %w", err)
	}

	reqMap := map[string]interface{}{
		"cmd":      "verify",
		"pod_json": string(podBytes),
	}
	reqBytes, err := json.Marshal(reqMap)
	if err != nil {
		return false, fmt.Errorf("marshal verify request: %w", err)
	}

	c := exec.Command("./pod_cli")
	stdin, _ := c.StdinPipe()
	stdout, _ := c.StdoutPipe()

	if err := c.Start(); err != nil {
		return false, fmt.Errorf("start Rust process: %w", err)
	}
	if _, err := stdin.Write(reqBytes); err != nil {
		return false, fmt.Errorf("writing verify req: %w", err)
	}
	stdin.Close()

	outBytes, err := io.ReadAll(stdout)
	if werr := c.Wait(); werr != nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading verify stdout: %w", err)
	}

	var vr struct {
		Verified bool   `json:"verified"`
		Error    string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(outBytes, &vr); err != nil {
		return false, fmt.Errorf("unmarshal verify resp: %w\nOutput: %s", err, string(outBytes))
	}
	if vr.Error != "" {
		fmt.Println("[WARN] verify error:", vr.Error)
		return false, nil
	}
	return vr.Verified, nil
}
