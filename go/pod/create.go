package pod

import (
	"encoding/hex"
	"fmt"

	"github.com/iden3/go-iden3-crypto/v2/babyjub"
)

func CreatePod(privateKeyHex string, entries PodEntries) (*Pod, error) {
	var privateKey babyjub.PrivateKey
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
	pubKey := privateKey.Public()
	pod := &Pod{
		Entries:         entries,
		Signature:       sig.Compress().String(),
		SignerPublicKey: pubKey.Compress().String(),
	}

	return pod, nil

}
