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
	"encoding/json"
	"fmt"
	"unsafe"
)

// ========== Data Structures for bridging ==========

// Minimal shape of PodValue
type PodValue struct {
	String  *string `json:"string,omitempty"`
	Int     *int64  `json:"int,omitempty"`
}

// KVPair
type KVPair struct {
	Key   string
	Value PodValue
}

// ========== FFI Wrapper ==========

func CreatePod(privateKey []byte, data []KVPair) (string, error) {
	// arr := make([][2]interface{}, len(data))
	// for i, kv := range data {
	// 	arr[i][0] = kv.Key
	// 	arr[i][1] = kv.Value
	// }
	arr := make([][2]interface{}, len(data))
	for i, kv := range data {
		arr[i][0] = kv.Key
		arr[i][1] = kv.Value
	}

	dataJSON, err := json.Marshal(arr)
	if err != nil {
		return "", fmt.Errorf("failed to encode data to JSON: %w", err)
	}

	fmt.Printf("Outgoing JSON: %s\n", string(dataJSON))

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

	podJSON := C.GoString(resultPtr)
	return podJSON, nil
}

// ========== MAIN PROGRAM ==========

func main() {
	// Example private key
	priv := make([]byte, 32)
	for i := 0; i < 32; i++ {
		priv[i] = byte(i)
	}

	data := []KVPair{
		{
			Key: "hello",
			Value: PodValue{
				String: ptrString("world"),
			},
		},
		{
			Key: "count",
			Value: PodValue{
				Int: ptrInt64(42),
			},
		},
	}
	result, err := CreatePod(priv, data)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Created POD JSON:", result)
}

func ptrString(s string) *string { return &s }
func ptrInt64(i int64) *int64    { return &i }