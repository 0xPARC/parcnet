package pod

import (
	"errors"
	"fmt"

	"github.com/iden3/go-iden3-crypto/v2/babyjub"
)

func (p *Pod) Verify() (bool, error) {
	// Validate and decode signature format
	signatureBytes, err := DecodeBytes(p.Signature, 64)
	if err != nil || len(signatureBytes) != 64 {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Validate and decode public key format
	publicKeyBytes, err := DecodeBytes(p.SignerPublicKey, 32)
	if err != nil || len(publicKeyBytes) != 32 {
		return false, fmt.Errorf("failed to decode signer public key: %w", err)
	}

	contentID, err := computeContentID(p.Entries)
	if err != nil {
		return false, fmt.Errorf("failed computing content ID: %w", err)
	}

	sigComp := babyjub.SignatureComp(signatureBytes)
	signature, err := sigComp.Decompress()
	if err != nil {
		return false, fmt.Errorf("failed to decompress signature: %w", err)
	}

	publicKeyComp := babyjub.PublicKeyComp(publicKeyBytes)
	publicKey, err := publicKeyComp.Decompress()
	if err != nil {
		return false, fmt.Errorf("failed to decompress public key: %w", err)
	}

	err = publicKey.VerifyPoseidon(contentID, signature)
	if err != nil {
		if !errors.Is(err, babyjub.ErrVerifyPoseidonFailed) {
			return false, fmt.Errorf("failed to verify signature: %w", err)
		}
		return false, nil
	}

	return true, nil
}
