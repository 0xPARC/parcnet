package pod

import (
	"fmt"

	"github.com/iden3/go-iden3-crypto/v2/babyjub"
)

// Verify uses dispatchRustCommand to check the Pod's signature.
func (p *Pod) Verify() (bool, error) {
	// For decoding from unpadded base64
	// podCopy := *p

	// if len(podCopy.SignerPublicKey) == 64 {
	// 	rawSPK, err := hex.DecodeString(podCopy.SignerPublicKey)
	// 	if err != nil {
	// 		return false, fmt.Errorf("failed to decode signerPublicKey: %w", err)
	// 	}
	// 	podCopy.SignerPublicKey = noPadB64.EncodeToString(rawSPK)
	// }

	// if len(podCopy.Signature) == 128 {
	// 	rawSig, err := hex.DecodeString(podCopy.Signature)
	// 	if err != nil {
	// 		return false, fmt.Errorf("failed to decode signature hex: %w", err)
	// 	}
	// 	podCopy.Signature = noPadB64.EncodeToString(rawSig)
	// }

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
