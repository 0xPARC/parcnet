package pod

import (
	"encoding/json"
	"math/big"
	"testing"
	"time"

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
		"S": PodValue{ValueType: PodStringValue, StringVal: "foobar"},
		"C": PodValue{ValueType: PodBooleanValue, BoolVal: false},
		"N": PodValue{ValueType: PodNullValue},
		"J": PodValue{ValueType: PodBytesValue, BytesVal: []byte{0x01, 0x02, 0x03}},
		"K": PodValue{ValueType: PodCryptographicValue, BigVal: big.NewInt(1234567890)},
		"D": PodValue{ValueType: PodDateValue, TimeVal: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
	})
	if err != nil {
		t.Fatalf("CreateGoPod failed: %v", err)
	}
	jsonPod, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod to JSON: %v", err)
	}
	expectedPod := `{"entries":{"A":123,"B":321,"C":false,"D":{"date":"2025-01-01T00:00:00.000Z"},"G":-7,"J":{"bytes":"AQID"},"K":{"cryptographic":1234567890},"N":null,"S":"foobar"},"signature":"vHJjksebJ56lnKH5Lh5A8ZG5VXV4rycqTcH9wFYg95omVVdy7FMzIgagM8q0cDUG7+QmeUppVZsg7HZralmRAg","signerPublicKey":"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4"}`
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

	expectedPod = `{"entries":{"count":42,"ffi":false,"ipc":true,"nulled":null,"some_bytes":{"bytes":"AQID"},"some_cryptographic":{"cryptographic":1234567890},"some_data":"some_value","some_date":{"date":"2025-01-01T00:00:00.000Z"}},"signature":"uqedfDb+lmjfcgXnm1Zk6AP75fjptmJmiR5QhxkGYZdI5Y2/CWiZIEE9d7r/FHAd/ebT+S1sAysHYEgnnQIGAA","signerPublicKey":"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4"}`
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

	// Legacy format #1: JSON-bigint with typed JSON
	typedJSONPod := `{"entries":{"created_by":{"type":"string","value":"Golang"},"year":{"type":"int","value":2025}},"signature":"d9731fa454723273ab8e03bd26af925beb387321336827903af2df0b67d7d29bfa20cb5fee4d466fa718428b49f4cb4ba5e065b8409e5df2266f85aedf072d05","signerPublicKey":"56ca90f80d7c374ae7485e9bcc47d4ac399460948da6aeeb899311097925a72c"}`
	pod = &Pod{}
	err = json.Unmarshal([]byte(typedJSONPod), pod)
	if err != nil {
		t.Fatalf("Failed to unmarshal legacy pod from JSON: %v", err)
	}
	serializedPod, err = json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod to JSON: %v", err)
	}
	// We expect the serialized pod to be in the newest format, not the legacy format
	expectedPod := `{"entries":{"created_by":"Golang","year":2025},"signature":"d9731fa454723273ab8e03bd26af925beb387321336827903af2df0b67d7d29bfa20cb5fee4d466fa718428b49f4cb4ba5e065b8409e5df2266f85aedf072d05","signerPublicKey":"56ca90f80d7c374ae7485e9bcc47d4ac399460948da6aeeb899311097925a72c"}`
	if string(serializedPod) != expectedPod {
		t.Fatalf("UnmarshalPod returned invalid pod: %v", string(serializedPod))
	}

	// Legacy format #2: Explicit POD value types
	explicitPodValueJSON := `{"entries":{"A":{"int":123},"B":{"int":321},"C":{"string":"hello"},"D":{"string":"foobar"},"E":{"int":-123},"F":{"cryptographic":"21888242871839275222246405745257275088548364400416034343698204186575808495616"},"G":{"int":7},"H":{"int":8},"I":{"int":9},"J":{"int":10},"owner":{"cryptographic":"18711405342588116796533073928767088921854096266145046362753928030796553161041"},"publicKey":{"eddsa_pubkey":"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4"}},"signature":"Jp3i2PnnRoLCmVPzgM6Bowchg44jz3fKuMQPzXQqWy4jzPFpZx2KwLuaIYaeYbd7Ah4FusEht2VhsVf3I81AAg","signerPublicKey":"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4"}`
	pod = &Pod{}
	err = json.Unmarshal([]byte(explicitPodValueJSON), pod)
	if err != nil {
		t.Fatalf("Failed to unmarshal legacy pod from JSON: %v", err)
	}
	serializedPod, err = json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod to JSON: %v", err)
	}
	// We expect the serialized pod to be in the newest format, not the legacy format
	expectedPod = `{"entries":{"A":123,"B":321,"C":"hello","D":"foobar","E":-123,"F":{"cryptographic":"0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"},"G":7,"H":8,"I":9,"J":10,"owner":{"cryptographic":"0x295e47b5d8ead41bbb4b9fe30ba1da0f1eaf8d5146cf0d7153d1878cb2908951"},"publicKey":{"eddsa_pubkey":"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4"}},"signature":"Jp3i2PnnRoLCmVPzgM6Bowchg44jz3fKuMQPzXQqWy4jzPFpZx2KwLuaIYaeYbd7Ah4FusEht2VhsVf3I81AAg","signerPublicKey":"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4"}`
	if string(serializedPod) != expectedPod {
		t.Fatalf("UnmarshalPod returned invalid pod: %v", string(serializedPod))
	}

	// Legacy format #3: Hex string signatures with explicit POD value types
	hexPodJSON := `{"entries":{"A":{"int":123},"B":{"int":321},"C":{"boolean":false},"D":{"string":"foobar"},"G":{"int":-7}},"signature":"fd75dc76f55eeb27e518ed5ebaca78a2b269e27d70cc0106b9f1e823380995ad8a2216351493ba3f50704ef3daae86b5163d6055d0c6644c4a1e64f03adc2704","signerPublicKey":"c433f7a696b7aa3a5224efb3993baf0ccd9e92eecee0c29a3f6c8208a9e81d9e"}`
	pod = &Pod{}
	err = json.Unmarshal([]byte(hexPodJSON), pod)
	if err != nil {
		t.Fatalf("Failed to unmarshal legacy pod from JSON: %v", err)
	}
	serializedPod, err = json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod to JSON: %v", err)
	}
	// We expect the serialized pod to be in the newest format, not the legacy format
	expectedPod = `{"entries":{"A":123,"B":321,"C":false,"D":"foobar","G":-7},"signature":"fd75dc76f55eeb27e518ed5ebaca78a2b269e27d70cc0106b9f1e823380995ad8a2216351493ba3f50704ef3daae86b5163d6055d0c6644c4a1e64f03adc2704","signerPublicKey":"c433f7a696b7aa3a5224efb3993baf0ccd9e92eecee0c29a3f6c8208a9e81d9e"}`
	if string(serializedPod) != expectedPod {
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
		"S": PodValue{ValueType: PodStringValue, StringVal: "foobar"},
		"C": PodValue{ValueType: PodBooleanValue, BoolVal: false},
		"N": PodValue{ValueType: PodNullValue},
		"J": PodValue{ValueType: PodBytesValue, BytesVal: []byte{0x01, 0x02, 0x03}},
		"K": PodValue{ValueType: PodCryptographicValue, BigVal: big.NewInt(1234567890)},
		"D": PodValue{ValueType: PodDateValue, TimeVal: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
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
	// eddsaPod := `{"entries":{"count":42,"ffi":false,"ipc":true,"nulled":null,"some_bytes":{"bytes":"AQID"},"some_cryptographic":{"cryptographic":1234567890},"some_data":"some_value","some_date":{"date":"2025-01-01T00:00:00.000Z"},"some_eddsa_pubkey":{"eddsa_pubkey":"1000000000000000000000000000000000000000000000000000000000000000"}},"signature":"4iagF4IyXAf2itQk1Fp/bQBjGFK5Pvo7JVgqPM9F6Jh6hddc3IvBR+3MppwalvGtA6OEEbDkeQh8yTa/2d8kAA","signerPublicKey":"kfEJWsAZtQYQtctW5ds4iRd/7otkIvyj2sBO4ZMkMak"}`
	jsonPod := `{"entries":{"count":42,"ffi":false,"ipc":true,"nulled":null,"some_bytes":{"bytes":"AQID"},"some_cryptographic":{"cryptographic":1234567890},"some_data":"some_value","some_date":{"date":"2025-01-01T00:00:00.000Z"}},"signature":"p2HfR2I76RySPV7WM+rhdBjV+VVipIyQe2WilgwZGJ817gFkossK6KqVR2C8JNvhUoGHxb4XvDrRRJQnoo87Ag","signerPublicKey":"kfEJWsAZtQYQtctW5ds4iRd/7otkIvyj2sBO4ZMkMak"}`
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
