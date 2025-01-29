package pod

import (
	"encoding/hex"
	"fmt"

	"github.com/iden3/go-iden3-crypto/v2/babyjub"
)

func (p *Pod) Verify() (bool, error) {
	// Ensure Signature is in hexadecimal format
	signatureHex := p.Signature
	if len(p.Signature) != 128 {
		signatureBytes, err := noPadB64.DecodeString(p.Signature)
		if err != nil {
			return false, fmt.Errorf("failed to decode signature from base64: %w", err)
		}
		signatureHex = hex.EncodeToString(signatureBytes)
	}

	// Ensure SignerPublicKey is in hexadecimal format
	publicKeyHex := p.SignerPublicKey
	if len(p.SignerPublicKey) != 64 {
		publicKeyBytes, err := noPadB64.DecodeString(p.SignerPublicKey)
		if err != nil {
			return false, fmt.Errorf("failed to decode signer public key from base64: %w", err)
		}
		publicKeyHex = hex.EncodeToString(publicKeyBytes)
	}

	contentID, err := computeContentID(p.Entries)
	if err != nil {
		return false, fmt.Errorf("failed computing content ID: %w", err)
	}

	var sigComp babyjub.SignatureComp
	if err := sigComp.UnmarshalText([]byte(signatureHex)); err != nil {
		return false, fmt.Errorf("failed to decode signature hex: %w", err)
	}
	signature, err := sigComp.Decompress()
	if err != nil {
		return false, fmt.Errorf("failed to decompress signature: %w", err)
	}

	var publicKey babyjub.PublicKey
	if err := publicKey.UnmarshalText([]byte(publicKeyHex)); err != nil {
		return false, fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	err = publicKey.VerifyPoseidon(contentID, signature)
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %w", err)
	}

	return true, nil
}
