package pod

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

var noPadB64 = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/").WithPadding(base64.NoPadding)

// Decode a fixed number of bytes which may be encoded as hex, or Base64 with
// or without padding. This will fail on any other encoding, or an unexpected
// number of bytes.
func DecodeBytes(encodedBytes string, expectedBytes int) ([]byte, error) {
	var decodedBytes []byte
	var err error

	if len(encodedBytes) == expectedBytes*2 {
		decodedBytes, err = hex.DecodeString(encodedBytes)
		if err != nil {
			return nil, fmt.Errorf("malformed private key: %w", err)
		}
	} else {
		decodedBytes, err = DecodeBase64Bytes(encodedBytes)
		if err != nil {
			return nil, fmt.Errorf("must be %d-byte hex or base64 string: %w", expectedBytes, err)
		}
	}

	if len(decodedBytes) != expectedBytes {
		return nil, fmt.Errorf("must be %d-byte hex or base64 string, got %d bytes", expectedBytes, len(decodedBytes))
	}

	return decodedBytes, nil
}

// Decode a variable number of bytes in Base64 encoding, with or without padding.
func DecodeBase64Bytes(encodedBytes string) ([]byte, error) {
	decodedBytes, err := noPadB64.DecodeString(encodedBytes)
	if err != nil {
		decodedBytes, err = base64.StdEncoding.DecodeString(encodedBytes)
		if err != nil {
			return nil, err
		}
	}
	return decodedBytes, nil
}
