package pod

import (
	"fmt"

	"github.com/iden3/go-iden3-crypto/v2/babyjub"
)

func (p *Pod) Verify() (bool, error) {
	contentID, err := computeContentID(p.Entries)
	if err != nil {
		return false, fmt.Errorf("failed computing content ID: %w", err)
	}

	var sigComp babyjub.SignatureComp
	if err := sigComp.UnmarshalText([]byte(p.Signature)); err != nil {
		return false, fmt.Errorf("failed to decode signature hex: %w", err)
	}
	signature, err := sigComp.Decompress()
	if err != nil {
		return false, fmt.Errorf("failed to decompress signature: %w", err)
	}

	var publicKey babyjub.PublicKey
	if err := publicKey.UnmarshalText([]byte(p.SignerPublicKey)); err != nil {
		return false, fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	err = publicKey.VerifyPoseidon(contentID, signature)
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %w", err)
	}

	return true, nil
}
