package pod

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/iden3/go-iden3-crypto/v2/constants"
	"github.com/iden3/go-iden3-crypto/v2/poseidon"
)

func hashString(s string) *big.Int {
	return hashBytes([]byte(s))
}

// hashBytes hashes the byte slice with SHA-256, then interprets
// the first 31 bytes of that digest as a big-endian integer.
func hashBytes(data []byte) *big.Int {
	hash := sha256.Sum256(data)

	// Take only the first 31 bytes. This discards the last byte,
	// effectively a right-shift by 8 bits compared to the full 32-byte digest.
	first31 := hash[:31]

	// Convert big-endian bytes to a *big.Int
	x := new(big.Int).SetBytes(first31)

	// If you need to reduce this mod a particular prime:
	// x.Mod(x, <your-prime>)

	return x
}

func fieldSafeInt64(val int64) *big.Int {
	// Convert the int64 into a big.Int, then reduce modulo BN254
	// so that negative numbers, or numbers larger than the prime,
	// become a valid field element.
	x := big.NewInt(val)
	x.Mod(x, constants.Q)
	return x
}

// FIXME: terrible right now, doing type inferencing
func hashPodValue(v interface{}) (*big.Int, error) {
	switch vv := v.(type) {
	case string:
		return hashString(vv), nil
	case int:
		return poseidon.Hash([]*big.Int{fieldSafeInt64(int64(vv))})
	case int64:
		return poseidon.Hash([]*big.Int{fieldSafeInt64(vv)})
	case bool:
		if vv {
			return poseidon.Hash([]*big.Int{big.NewInt(1)})
		}
		return poseidon.Hash([]*big.Int{big.NewInt(0)})
	// case map[string]interface{}:
	// Do the version based on the key of the JSON object
	default:
		// Fall back to some simple encoding
		return hashString(fmt.Sprintf("%v", vv)), nil
	}
}

func computeContentID(data PodEntries) (*big.Int, error) {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var allHashes []*big.Int
	for _, k := range keys {
		kh := hashString(k)
		allHashes = append(allHashes, kh)

		vh, err := data[k].Hash()
		if err != nil {
			return nil, err
		}
		allHashes = append(allHashes, vh)
	}

	root, err := leanPoseidonIMT(allHashes)
	if err != nil {
		return nil, err
	}
	return root, nil
}

func leanPoseidonIMT(inputs []*big.Int) (*big.Int, error) {
	if len(inputs) == 0 {
		return nil, errors.New("at least one input is required")
	}

	items := make([]*big.Int, len(inputs))
	copy(items, inputs)

	for len(items) > 1 {
		var newItems []*big.Int
		for i := 0; i < len(items); i += 2 {
			if i+1 < len(items) {
				h, err := poseidon.Hash([]*big.Int{items[i], items[i+1]})
				if err != nil {
					return nil, fmt.Errorf("error hashing chunk: %w", err)
				}
				newItems = append(newItems, h)
			} else {
				newItems = append(newItems, items[i])
			}
		}
		items = newItems
	}
	return items[0], nil
}
