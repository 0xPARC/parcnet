package pod

import (
	"encoding/hex"
	"fmt"

	"github.com/iden3/go-iden3-crypto/v2/babyjub"
)

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

func CreateGoPodHex(privateKeyHex string, entries PodEntries) (*Pod, error) {
	var privateKey babyjub.PrivateKey
	hex.Decode(privateKey[:], []byte(privateKeyHex))	
	return CreateGoPod(privateKey, entries)
}

func CreateGoPod(privateKey babyjub.PrivateKey, entries PodEntries) (*Pod, error) {
	contentID, err := computeContentID(entries)
	if err != nil {
		return nil, fmt.Errorf("failed computing content ID: %w", err)
	}
	sig, err := privateKey.SignPoseidon(contentID)
	if err != nil {
		return nil, fmt.Errorf("failed signing content ID: %w", err)
	}
	pubKey := privateKey.Public()
	pod := &Pod{
		Entries:         entries,
		Signature:       sig.Compress().String(),
		SignerPublicKey: pubKey.Compress().String(),
	}

	return pod, nil

}

// func createPodFromMap(privateKey []byte, data map[string]interface{}) (*Pod, error) {
// 	// 1) Sort map keys
// 	keys := make([]string, 0, len(data))
// 	for k := range data {
// 		keys = append(keys, k)
// 	}
// 	sort.Strings(keys)

// 	// 2) Collect hashes of key & value
// 	var allHashes []string
// 	for _, k := range keys {
// 		// Hash of the key
// 		keyHash := hashString(k)
// 		allHashes = append(allHashes, keyHash)

// 		// Hash of the value
// 		valHash, err := hashValue(data[k])
// 		if err != nil {
// 			return nil, fmt.Errorf("failed hashing value for key %q: %w", k, err)
// 		}
// 		allHashes = append(allHashes, valHash)
// 	}

// 	// 3) Poseidon IMT on the collected hashes
// 	root, err := leanPoseidonIMT(allHashes)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed computing IMT: %w", err)
// 	}

// 	// 4) Derive the public key from the private key
// 	pubKey, err := derivePublicKey(privateKey)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed deriving public key: %w", err)
// 	}

// 	// 5) Sign the root
// 	sig, err := signMessage(privateKey, root)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed signing IMT root: %w", err)
// 	}

// 	// 6) Construct the final Pod
// 	pod := &Pod{
// 		Entries:         data,
// 		Signature:       sig,
// 		SignerPublicKey: pubKey,
// 	}
// 	return pod, nil
// }
