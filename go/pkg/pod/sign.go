package pod

import "fmt"

// SignPod calls "sign" subcommand in Rust
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