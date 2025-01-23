package pod

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// noPadB64 matches Rust's base64::STANDARD_NO_PAD
var noPadB64 = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/").WithPadding(base64.NoPadding)

// Verify uses dispatchRustCommand to check the Pod's signature.
func (p *Pod) Verify() (bool, error) {
	podCopy := *p

	if len(podCopy.SignerPublicKey) == 64 {
		rawSPK, err := hex.DecodeString(podCopy.SignerPublicKey)
		if err != nil {
			return false, fmt.Errorf("failed to decode signerPublicKey: %w", err)
		}
		podCopy.SignerPublicKey = noPadB64.EncodeToString(rawSPK)
	}

	if len(podCopy.Signature) == 128 {
		rawSig, err := hex.DecodeString(podCopy.Signature)
		if err != nil {
			return false, fmt.Errorf("failed to decode signature hex: %w", err)
		}
		podCopy.Signature = noPadB64.EncodeToString(rawSig)
	}

	podBytes, err := json.Marshal(podCopy)
	if err != nil {
		return false, fmt.Errorf("marshal Pod for verify: %w", err)
	}

	req := podCommandRequest{
		Cmd: "verify",
		Entries: map[string]interface{}{
			// The Rust side presumably expects a "pod_json" key containing the Pod in JSON form
			"pod_json": string(podBytes),
		},
		// No PrivateKey needed for verify, so we can leave it empty
	}

	_, outJSON, err := dispatchRustCommand(req)
	if err != nil {
		return false, fmt.Errorf("failed to dispatch verify command: %w", err)
	}

	var vr struct {
		Verified bool   `json:"verified"`
		Error    string `json:"error,omitempty"`
	}
	if err := json.Unmarshal([]byte(outJSON), &vr); err != nil {
		return false, fmt.Errorf("unmarshal verify response: %w\nOutput: %s", err, outJSON)
	}

	if vr.Error != "" {
		return false, fmt.Errorf("verify failed: %s", vr.Error)
	}

	return vr.Verified, nil
}
