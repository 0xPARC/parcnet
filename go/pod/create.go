package pod

import (
	"encoding/hex"
	"fmt"

	"github.com/iden3/go-iden3-crypto/v2/babyjub"
)

func CreatePod(privateKeyHex string, entries PodEntries) (*Pod, error) {
	var privateKey babyjub.PrivateKey
	// Ensure privateKeyHex is in hexadecimal format
	if len(privateKeyHex) != 64 {
		privateKeyBytes, err := noPadB64.DecodeString(privateKeyHex)
		if err != nil {
			return nil, fmt.Errorf("private key must be 32-byte hex or base64 string: %w", err)
		}
		privateKeyHex = hex.EncodeToString(privateKeyBytes)
	}
	hex.Decode(privateKey[:], []byte(privateKeyHex))
	return signPod(privateKey, entries)
}

func signPod(privateKey babyjub.PrivateKey, entries PodEntries) (*Pod, error) {
	contentID, err := computeContentID(entries)
	if err != nil {
		return nil, fmt.Errorf("failed computing content ID: %w", err)
	}
	sig, err := privateKey.SignPoseidon(contentID)
	if err != nil {
		return nil, fmt.Errorf("failed signing content ID: %w", err)
	}
	sigBytes := sig.Compress()
	sigBase64 := noPadB64.EncodeToString(sigBytes[:])

	pubKeyBytes := privateKey.Public().Compress()

	// Encode directly to base64 without intermediate hex
	pubKeyBase64 := noPadB64.EncodeToString(pubKeyBytes[:])

	pod := &Pod{
		Entries:         entries,
		Signature:       sigBase64,
		SignerPublicKey: pubKeyBase64,
	}

	return pod, nil
}
