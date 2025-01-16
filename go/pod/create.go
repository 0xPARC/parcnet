package pod

import "fmt"

// CreatePod calls "create" subcommand in Rust
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
