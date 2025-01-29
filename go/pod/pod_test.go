package pod

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/v2/babyjub"
)

func TestCreateGoPod(t *testing.T) {
	privKey := babyjub.PrivateKey{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8,
		9, 0, 1,
	}
	pod, err := signPod(privKey, PodEntries{
		"A": PodValue{ValueType: PodIntValue, BigVal: big.NewInt(123)},
		"B": PodValue{ValueType: PodIntValue, BigVal: big.NewInt(321)},
		"G": PodValue{ValueType: PodIntValue, BigVal: big.NewInt(-7)},
		"D": PodValue{ValueType: PodStringValue, StringVal: "foobar"},
		"C": PodValue{ValueType: PodBooleanValue, BoolVal: false},
	})
	if err != nil {
		t.Fatalf("CreateGoPod failed: %v", err)
	}
	jsonPod, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod to JSON: %v", err)
	}
	expectedPod := `{"entries":{"A":123,"B":321,"C":false,"D":"foobar","G":-7},"signature":"fd75dc76f55eeb27e518ed5ebaca78a2b269e27d70cc0106b9f1e823380995ad8a2216351493ba3f50704ef3daae86b5163d6055d0c6644c4a1e64f03adc2704","signerPublicKey":"c433f7a696b7aa3a5224efb3993baf0ccd9e92eecee0c29a3f6c8208a9e81d9e"}`
	if string(jsonPod) != expectedPod {
		t.Fatalf("CreateGoPod returned invalid pod: %v", string(jsonPod))
	}

	jsonPodEntries := `{"count":42,"ffi":false,"ipc":true,"nulled":null,"some_bytes":{"bytes":"AQID"},"some_cryptographic":{"cryptographic":1234567890},"some_data":"some_value","some_date":{"date":"2025-01-01T00:00:00.000Z"}}`
	entries := PodEntries{}
	err = json.Unmarshal([]byte(jsonPodEntries), &entries)
	if err != nil {
		t.Fatalf("Failed to unmarshal pod entries from JSON: %v", err)
	}
	pod, err = signPod(privKey, entries)
	if err != nil {
		t.Fatalf("Failed to sign pod: %v", err)
	}
	jsonPod, err = json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod to JSON: %v", err)
	}
	expectedPod = `{"entries":{"count":42,"ffi":false,"ipc":true,"nulled":null,"some_bytes":{"bytes":"AQID"},"some_cryptographic":{"cryptographic":1234567890},"some_data":"some_value","some_date":{"date":"2025-01-01T00:00:00.000Z"}},"signature":"d7805b5e8d4a876a6f2ce8f575d744aae01bfc1a6d7f4f982e5ca2dbb0ee52a6147c4a9464dae6d41beaba9337d1513beda2cf73fc8e748fad2df235a7a52a00","signerPublicKey":"c433f7a696b7aa3a5224efb3993baf0ccd9e92eecee0c29a3f6c8208a9e81d9e"}`
	if string(jsonPod) != expectedPod {
		t.Fatalf("CreateGoPod returned invalid pod: %v", string(jsonPod))
	}
}

func TestPodMarshal(t *testing.T) {
	jsonPod := `{"entries":{"count":42,"ffi":false,"ipc":true,"nulled":null,"some_bytes":{"bytes":"AQID"},"some_cryptographic":{"cryptographic":1234567890},"some_data":"some_value","some_date":{"date":"2025-01-01T00:00:00.000Z"}},"signature":"p2HfR2I76RySPV7WM+rhdBjV+VVipIyQe2WilgwZGJ817gFkossK6KqVR2C8JNvhUoGHxb4XvDrRRJQnoo87Ag","signerPublicKey":"kfEJWsAZtQYQtctW5ds4iRd/7otkIvyj2sBO4ZMkMak"}`
	pod := &Pod{}
	err := json.Unmarshal([]byte(jsonPod), pod)
	if err != nil {
		t.Fatalf("Failed to unmarshal pod from JSON: %v", err)
	}
	serializedPod, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod to JSON: %v", err)
	}
	if string(serializedPod) != jsonPod {
		t.Fatalf("UnmarshalPod returned invalid pod: %v", string(serializedPod))
	}
}

func TestVerifyGoPod(t *testing.T) {
	// Verify a pod that we created
	privKey := babyjub.PrivateKey{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8,
		9, 0, 1,
	}
	pod, err := signPod(privKey, PodEntries{
		"A": PodValue{ValueType: PodIntValue, BigVal: big.NewInt(123)},
		"B": PodValue{ValueType: PodIntValue, BigVal: big.NewInt(321)},
		"G": PodValue{ValueType: PodIntValue, BigVal: big.NewInt(-7)},
		"D": PodValue{ValueType: PodStringValue, StringVal: "foobar"},
		"C": PodValue{ValueType: PodBooleanValue, BoolVal: false},
	})
	if err != nil {
		t.Fatalf("CreateGoPod failed: %v", err)
	}
	ok, err := pod.Verify()
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatalf("Verify for valid pod returned false")
	}
	// Tamper the signature with another 64-byte hex string
	pod.Signature = "703a5776185903375e19021c45cc34ca1f4c8b5baa049d8c65bf65768db0fb12a1cabe35695310a0299c22947ceb08db1307fa929e9627b4ddbcf90b61c01302"
	ok, _ = pod.Verify()
	if ok {
		t.Fatalf("Verify for invalid pod returned true")
	}

	// Verify a pod that we need to deserialize
	// Base64 original
	// jsonPod := `{"entries":{"count":42,"ffi":false,"ipc":true,"nulled":null,"some_bytes":{"bytes":"AQID"},"some_cryptographic":{"cryptographic":1234567890},"some_data":"some_value","some_date":{"date":"2025-01-01T00:00:00.000Z"}},"signature":"p2HfR2I76RySPV7WM+rhdBjV+VVipIyQe2WilgwZGJ817gFkossK6KqVR2C8JNvhUoGHxb4XvDrRRJQnoo87Ag","signerPublicKey":"kfEJWsAZtQYQtctW5ds4iRd/7otkIvyj2sBO4ZMkMak"}`
	// Hex replacement
	jsonPod := `{"entries":{"count":42,"ffi":false,"ipc":true,"nulled":null,"some_bytes":{"bytes":"AQID"},"some_cryptographic":{"cryptographic":1234567890},"some_data":"some_value","some_date":{"date":"2025-01-01T00:00:00.000Z"}},"signature":"d7805b5e8d4a876a6f2ce8f575d744aae01bfc1a6d7f4f982e5ca2dbb0ee52a6147c4a9464dae6d41beaba9337d1513beda2cf73fc8e748fad2df235a7a52a00","signerPublicKey":"c433f7a696b7aa3a5224efb3993baf0ccd9e92eecee0c29a3f6c8208a9e81d9e"}`
	pod = &Pod{}
	err = json.Unmarshal([]byte(jsonPod), pod)
	if err != nil {
		t.Fatalf("Failed to unmarshal pod from JSON: %v", err)
	}
	ok, err = pod.Verify()
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatalf("Verify for valid pod returned false")
	}
}
