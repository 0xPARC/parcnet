package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -L./lib -lparcnet_pod -lm -ldl
#include <stdlib.h>

// Must match the Rust signatures
extern char* create_pod_ffi(
    const unsigned char* private_key_ptr,
    unsigned long long private_key_len,
    const char* data_json_ptr,
    int* out_error_code
);

extern void free_string(char* ptr);
*/
import "C"
import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"unsafe"
)

// This matches Rust's `STANDARD_NO_PAD` from the base64 crate.
var noPadB64 = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/").WithPadding(base64.NoPadding)


// ========== Data Structures for bridging ==========

// Minimal shape of PodValue
type PodValue struct {
	String  *string `json:"string,omitempty"`
	Int     *int64  `json:"int,omitempty"`
	Cryptographic *bool   `json:"cryptographic,omitempty"`
}

// KVPair
type KVPair struct {
	Key   string
	Value PodValue
}
// ========== FFI Wrapper ==========

func CreatePod(privateKey []byte, data []KVPair) (string, error) {
	// Build the JSON array-of-arrays that Rust expects: Vec<(String, PodValue)>
	arr := make([][2]interface{}, len(data))
	for i, kv := range data {
		arr[i][0] = kv.Key
		arr[i][1] = kv.Value
	}

	dataJSON, err := json.Marshal(arr)
	if err != nil {
		return "", fmt.Errorf("failed to encode data to JSON: %w", err)
	}

	privateKeyPtr := (*C.uchar)(unsafe.Pointer(&privateKey[0]))
	privateKeyLen := C.ulonglong(len(privateKey))

	dataJSONPtr := C.CString(string(dataJSON))
	defer C.free(unsafe.Pointer(dataJSONPtr))

	var cErr C.int

	resultPtr := C.create_pod_ffi(
		privateKeyPtr,
		privateKeyLen,
		dataJSONPtr,
		&cErr,
	)
	defer func() {
		if resultPtr != nil {
			C.free_string(resultPtr)
		}
	}()

	if cErr != 0 || resultPtr == nil {
		return "", fmt.Errorf("create_pod_ffi failed, code %d", cErr)
	}

	rustPodJSON := C.GoString(resultPtr)

	// Post-process the JSON into:
	// 1. type/value shape for PodValue variants
	// 2. Hex-encode signerPublicKey (32 bytes => 64 hex)
	// 3. Hex-encode signature (64 bytes => 128 hex)
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(rustPodJSON), &raw); err != nil {
		return "", fmt.Errorf("failed to unmarshal rustPodJSON: %w", err)
	}

	if err := transformEntries(raw); err != nil {
		return "", fmt.Errorf("transformEntries: %w", err)
	}
	if err := hexEncodeSignerPublicKey(raw); err != nil {
		return "", fmt.Errorf("hexEncodeSignerPublicKey: %w", err)
	}
	if err := hexEncodeSignature(raw); err != nil {
		return "", fmt.Errorf("hexEncodeSignature: %w", err)
	}

	finalBytes, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("failed to marshal final JSON: %w", err)
	}

	return string(finalBytes), nil
}

// Transform the entries from FFI output type/value shape to our type/value shape.
func transformEntries(raw map[string]interface{}) error {
	claim, ok := raw["claim"].(map[string]interface{})
	if !ok {
		return nil
	}
	entries, ok := claim["entries"].(map[string]interface{})
	if !ok {
		return nil
	}

	for key, val := range entries {
		if subObj, ok := val.(map[string]interface{}); ok {
			converted := convertVariant(subObj)
			entries[key] = converted
		}
	}
	return nil
}

// Convert the entries from FFI output type/value shape to our type/value shape.
func convertVariant(obj map[string]interface{}) map[string]interface{} {
	for k, v := range obj {
		switch k {
		case "string":
			return map[string]interface{}{"type": "string", "value": v}
		case "int":
			return map[string]interface{}{"type": "int", "value": v}
		case "cryptographic":
			return map[string]interface{}{"type": "cryptographic", "value": v}
		default:
			// fallback if we don't recognize the key
			return map[string]interface{}{"type": k, "value": v}
		}
	}
	return obj
}

func hexEncodeSignerPublicKey(raw map[string]interface{}) error {
	claim, ok := raw["claim"].(map[string]interface{})
	if !ok {
		return nil
	}

	spkVal, ok := claim["signerPublicKey"].(string)
	if !ok {
		return nil
	}

	// This string is from Rust's compressed_pt_ser, which uses
	// base64::STANDARD_NO_PAD. So let's decode with noPadB64.
	decoded, err := noPadB64.DecodeString(spkVal)
	if err != nil {
		return fmt.Errorf("publicKey not valid no-pad base64: %v", err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("publicKey is %d bytes, expected 32", len(decoded))
	}

	hexVal := hex.EncodeToString(decoded)
	claim["signerPublicKey"] = hexVal
	return nil
}

func hexEncodeSignature(raw map[string]interface{}) error {
	proof, ok := raw["proof"].(map[string]interface{})
	if !ok {
		return nil
	}

	sigVal, ok := proof["signature"].(string)
	if !ok {
		return nil
	}

	decoded, err := noPadB64.DecodeString(sigVal)
	if err != nil {
		return fmt.Errorf("signature not valid no-pad base64: %v", err)
	}
	if len(decoded) != 64 {
		return fmt.Errorf("signature is %d bytes, expected 64", len(decoded))
	}

	hexVal := hex.EncodeToString(decoded)
	proof["signature"] = hexVal
	return nil
}


func main() {
	// Example private key
	priv := make([]byte, 32)
	for i := 0; i < 32; i++ {
		priv[i] = byte(i)
	}

	data := []KVPair{
		{
			Key: "created_by",
			Value: PodValue{
				String: ptrString("Golang"),
			},
		},
		{
			Key: "year",
			Value: PodValue{
				Int: ptrInt64(2025),
			},
		},
	}
	result, err := CreatePod(priv, data)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println(result)
}

func ptrString(s string) *string { return &s }
func ptrInt64(i int64) *int64    { return &i }