package pod

import (
	"fmt"

	"github.com/iden3/go-iden3-crypto/v2/babyjub"
)

// A reusable POD signer which can create multiple PODs with the same key.
type Signer struct {
	privateKey babyjub.PrivateKey
}

// Create a new Signer with the given private key.
func NewSigner(privateKeyHex string) (*Signer, error) {
	privateKey, err := parsePrivateKey(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &Signer{privateKey: privateKey}, nil
}

// Create and sign a new POD.  This involves hashing all the given entries
// to generate a Content ID, then signing that content ID with the given
// private key.
func (s *Signer) Sign(entries PodEntries) (*Pod, error) {
	return signPod(s.privateKey, entries)
}

// Create and sign a new POD.  This involves hashing all the given entries
// to generate a Content ID, then signing that content ID with the given
// private key.
func CreatePod(privateKeyHex string, entries PodEntries) (*Pod, error) {
	privateKey, err := parsePrivateKey(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return signPod(privateKey, entries)
}

func parsePrivateKey(encodedPrivateKey string) (babyjub.PrivateKey, error) {
	var privateKey babyjub.PrivateKey

	privateKeyBytes, err := DecodeBytes(encodedPrivateKey, 32)
	if err != nil || len(privateKeyBytes) != 32 {
		return privateKey, fmt.Errorf("failed to parse private key: must be 32-byte hex or base64 string: %w", err)
	}

	privateKey = babyjub.PrivateKey(privateKeyBytes)

	return privateKey, nil
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
