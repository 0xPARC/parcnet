package pod

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/iden3/go-iden3-crypto/v2/babyjub"
)

func TestCreateGoPod(t *testing.T) {
	privKeyHex := "0001020304050607080900010203040506070809000102030405060708090001"
	pod, err := CreatePod(privKeyHex, PodEntries{
		"A": PodValue{ValueType: PodIntValue, BigVal: big.NewInt(9007199254740992)},
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
	expectedPod := `{"entries":{"A":{"int":"0x20000000000000"},"B":321,"C":false,"D":{"date":"2025-01-01T00:00:00.000Z"},"G":-7,"J":{"bytes":"AQID"},"K":{"cryptographic":1234567890},"N":null,"S":"foobar"},"signature":"B8vS1LrnzK7s0E5w/O8qu8YcNxOm+sQBis/aTDDachgTS3dqLcPofbvqISJtpfwb1ov86MIMZZlrIAwv5/xIAw","signerPublicKey":"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4"}`
	if string(jsonPod) != expectedPod {
		t.Fatalf("CreateGoPod returned invalid pod: %v", string(jsonPod))
	}

	jsonPodEntries := `{"count":42,"ffi":false,"ipc":true,"nulled":null,"some_bytes":{"bytes":"AQID"},"some_cryptographic":{"cryptographic":1234567890},"some_data":"some_value","some_date":{"date":"2025-01-01T00:00:00.000Z"}}`
	entries := PodEntries{}
	err = json.Unmarshal([]byte(jsonPodEntries), &entries)
	if err != nil {
		t.Fatalf("Failed to unmarshal pod entries from JSON: %v", err)
	}
	pod, err = CreatePod(privKeyHex, entries)
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

	// Try with base64 private key
	privKeyBase64 := "AAECAwQFBgcICQABAgMEBQYHCAkAAQIDBAUGBwgJAAE"
	pod, err = CreatePod(privKeyBase64, entries)
	if err != nil {
		t.Fatalf("Failed to sign pod: %v", err)
	}
	jsonPod, err = json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod to JSON: %v", err)
	}
	if string(jsonPod) != expectedPod {
		t.Fatalf("CreateGoPod returned invalid pod with base64 private key: %v", string(jsonPod))
	}

	// Try with padded base64 private key
	privKeyBase64 = "AAECAwQFBgcICQABAgMEBQYHCAkAAQIDBAUGBwgJAAE="
	pod, err = CreatePod(privKeyBase64, entries)
	if err != nil {
		t.Fatalf("Failed to sign pod: %v", err)
	}
	jsonPod, err = json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod to JSON: %v", err)
	}
	if string(jsonPod) != expectedPod {
		t.Fatalf("CreateGoPod returned invalid pod with base64 private key: %v", string(jsonPod))
	}

	// Try with invalid private key hex
	wrongPrivateKey := "000102030405060708090001003040506070809000102030405060708090001"

	_, err = CreatePod(wrongPrivateKey, entries)
	if err == nil || !strings.HasPrefix(err.Error(), "failed to parse private key") {
		t.Fatalf("CreatePod should have failed")
	}

	// Try with invalid private key base64
	wrongPrivateKey = "AAECAwQFBgcICQABAgMEBQYHCAkAAQIDBAUGBwgJAA"

	_, err = CreatePod(wrongPrivateKey, entries)
	if err == nil || !strings.HasPrefix(err.Error(), "failed to parse private key") {
		t.Fatalf("CreatePod should have failed")
	}
}

func TestPodMarshal(t *testing.T) {
	// Preferred format where values are encoded without types where possible
	jsonPod := `{"entries":{"count":42,"ffi":false,"ipc":true,"nulled":null,"some_bytes":{"bytes":"AQID"},"some_cryptographic":{"cryptographic":1234567890},"some_data":"some_value","some_date":{"date":"2025-01-01T00:00:00.000Z"}},"signature":"p2HfR2I76RySPV7WM+rhdBjV+VVipIyQe2WilgwZGJ817gFkossK6KqVR2C8JNvhUoGHxb4XvDrRRJQnoo87Ag","signerPublicKey":"kfEJWsAZtQYQtctW5ds4iRd/7otkIvyj2sBO4ZMkMak"}`
	pod := &Pod{}

	// Extra step to insert some data and make sure it doesn't survive unmarshalling.
	pod.Entries = PodEntries{"shouldBeOverwritten": NewPodNullValue()}

	err := json.Unmarshal([]byte(jsonPod), pod)
	if err != nil {
		t.Fatalf("Failed to unmarshal pod from JSON: %v", err)
	}
	ok, err := pod.Verify()
	if err != nil {
		t.Fatalf("Failed to verify JSON POD: %v", err)
	}
	if !ok {
		t.Fatalf("JSON POD is not valid")
	}
	serializedPod, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod to JSON: %v", err)
	}
	if string(serializedPod) != jsonPod {
		t.Fatalf("UnmarshalPod returned invalid pod: %v", string(serializedPod))
	}

	// Legacy format #1: separate type/value like { "type": "string", "value": "hello"}
	// This isn't intended to support the pre-release json-bigint format, since have
	// no guarantee that unmarshalling will handle huge numbers in JSON
	typedJSONPod := `{"entries":{"created_by":{"type":"string","value":"Golang"},"year":{"type":"int","value":2025}},"signature":"d9731fa454723273ab8e03bd26af925beb387321336827903af2df0b67d7d29bfa20cb5fee4d466fa718428b49f4cb4ba5e065b8409e5df2266f85aedf072d05","signerPublicKey":"56ca90f80d7c374ae7485e9bcc47d4ac399460948da6aeeb899311097925a72c"}`
	pod = &Pod{}
	err = json.Unmarshal([]byte(typedJSONPod), pod)
	if err != nil {
		t.Fatalf("Failed to unmarshal legacy pod from JSON: %v", err)
	}
	ok, err = pod.Verify()
	if err != nil {
		t.Fatalf("Failed to verify JSON POD: %v", err)
	}
	if !ok {
		t.Fatalf("JSON POD is not valid")
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

	// Legacy format #2: Explicit but terse POD value types like { "string": "hello" }
	explicitPodValueJSON := `{"entries":{"A":{"int":123},"B":{"int":321},"C":{"string":"hello"},"D":{"string":"foobar"},"E":{"int":-123},"F":{"cryptographic":"21888242871839275222246405745257275088548364400416034343698204186575808495616"},"G":{"int":7},"H":{"int":8},"I":{"int":9},"J":{"int":10},"owner":{"cryptographic":"18711405342588116796533073928767088921854096266145046362753928030796553161041"},"publicKey":{"eddsa_pubkey":"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4"}},"signature":"Jp3i2PnnRoLCmVPzgM6Bowchg44jz3fKuMQPzXQqWy4jzPFpZx2KwLuaIYaeYbd7Ah4FusEht2VhsVf3I81AAg","signerPublicKey":"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4"}`
	pod = &Pod{}
	err = json.Unmarshal([]byte(explicitPodValueJSON), pod)
	if err != nil {
		t.Fatalf("Failed to unmarshal legacy pod from JSON: %v", err)
	}
	ok, err = pod.Verify()
	if err != nil {
		t.Fatalf("Failed to verify JSON POD: %v", err)
	}
	if !ok {
		t.Fatalf("JSON POD is not valid")
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

	// Legacy format #3: Hex strings for signatures with explicit POD value types
	hexPodJSON := `{"entries":{"A":{"int":123},"B":{"int":321},"C":{"boolean":false},"D":{"string":"foobar"},"G":{"int":-7}},"signature":"fd75dc76f55eeb27e518ed5ebaca78a2b269e27d70cc0106b9f1e823380995ad8a2216351493ba3f50704ef3daae86b5163d6055d0c6644c4a1e64f03adc2704","signerPublicKey":"c433f7a696b7aa3a5224efb3993baf0ccd9e92eecee0c29a3f6c8208a9e81d9e"}`
	pod = &Pod{}
	err = json.Unmarshal([]byte(hexPodJSON), pod)
	if err != nil {
		t.Fatalf("Failed to unmarshal legacy pod from JSON: %v", err)
	}
	ok, err = pod.Verify()
	if err != nil {
		t.Fatalf("Failed to verify JSON POD: %v", err)
	}
	if !ok {
		t.Fatalf("JSON POD is not valid")
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

	// Signature should still verify with padded Base64
	modifiedPOD := Pod(*pod)
	modifiedPOD.Signature = pod.Signature + "=="
	modifiedPOD.SignerPublicKey = pod.SignerPublicKey + "="
	ok, err = modifiedPOD.Verify()
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatalf("Verify for valid pod returned false")
	}

	// Signature should still verify with hex instead of Base64
	modifiedPOD = Pod(*pod)
	sigBytes, err := DecodeBytes(pod.Signature, 64)
	if err != nil {
		t.Fatalf("Signature decode failed.")
	}
	modifiedPOD.Signature = hex.EncodeToString(sigBytes)
	pubKeyBytes, err := DecodeBytes(pod.SignerPublicKey, 32)
	if err != nil {
		t.Fatalf("Pub key decode failed.")
	}
	modifiedPOD.SignerPublicKey = hex.EncodeToString(pubKeyBytes)
	ok, err = modifiedPOD.Verify()
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatalf("Verify for valid pod returned false")
	}

	// Tamper the signature with another 64-byte hex string
	pod.Signature = "703a5776185903375e19021c45cc34ca1f4c8b5baa049d8c65bf65768db0fb12a1cabe35695310a0299c22947ceb08db1307fa929e9627b4ddbcf90b61c01302"
	ok, err = pod.Verify()
	if err != nil {
		t.Fatalf("Verify for invalid signature should not be an error")
	}
	if ok {
		t.Fatalf("Verify for invalid pod returned true")
	}

	// Verify a pod that we need to deserialize
	jsonPod := `{"entries":{"count":42,"ffi":false,"ipc":true,"nulled":null,"some_bytes":{"bytes":"AQID"},"some_cryptographic":{"cryptographic":1234567890},"some_data":"some_value","some_date":{"date":"2025-01-01T00:00:00.000Z"},"some_eddsa_pubkey":{"eddsa_pubkey":"1000000000000000000000000000000000000000000000000000000000000000"}},"signature":"4iagF4IyXAf2itQk1Fp/bQBjGFK5Pvo7JVgqPM9F6Jh6hddc3IvBR+3MppwalvGtA6OEEbDkeQh8yTa/2d8kAA","signerPublicKey":"kfEJWsAZtQYQtctW5ds4iRd/7otkIvyj2sBO4ZMkMak"}`
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

func TestSigner(t *testing.T) {
	privKeyHex := "0001020304050607080900010203040506070809000102030405060708090001"

	signer, err := NewSigner(privKeyHex)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	pod, err := signer.Sign(PodEntries{
		"A": PodValue{ValueType: PodIntValue, BigVal: big.NewInt(9007199254740992)},
	})
	if err != nil {
		t.Fatalf("CreateGoPod failed: %v", err)
	}
	jsonPod, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod to JSON: %v", err)
	}
	expectedPod := `{"entries":{"A":{"int":"0x20000000000000"}},"signature":"mw+dxBmrZ9KkSR9qzVKUuZLCZiPztGsn5ujQvlvR1yGMkvvtSS/+eCOndA8abxlm4Iza+A7jvTUr4kHREDT+BA","signerPublicKey":"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4"}`
	if string(jsonPod) != expectedPod {
		t.Fatalf("CreateGoPod returned invalid pod: %v", string(jsonPod))
	}

	jsonPodEntries := `{"count":42,"ffi":false,"ipc":true,"nulled":null,"some_bytes":{"bytes":"AQID"},"some_cryptographic":{"cryptographic":1234567890},"some_data":"some_value","some_date":{"date":"2025-01-01T00:00:00.000Z"}}`
	entries := PodEntries{}
	err = json.Unmarshal([]byte(jsonPodEntries), &entries)
	if err != nil {
		t.Fatalf("Failed to unmarshal pod entries from JSON: %v", err)
	}
	pod, err = signer.Sign(entries)
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

	// Try with base64 private key
	privKeyBase64 := "AAECAwQFBgcICQABAgMEBQYHCAkAAQIDBAUGBwgJAAE"
	signer, err = NewSigner(privKeyBase64)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	pod, err = signer.Sign(entries)
	if err != nil {
		t.Fatalf("Failed to sign pod: %v", err)
	}
	jsonPod, err = json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod to JSON: %v", err)
	}
	if string(jsonPod) != expectedPod {
		t.Fatalf("CreateGoPod returned invalid pod with base64 private key: %v", string(jsonPod))
	}

	// Try with padded base64 private key
	privKeyPaddedBase64 := "AAECAwQFBgcICQABAgMEBQYHCAkAAQIDBAUGBwgJAAE="
	signer, err = NewSigner(privKeyPaddedBase64)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	pod, err = signer.Sign(entries)
	if err != nil {
		t.Fatalf("Failed to sign pod: %v", err)
	}
	jsonPod, err = json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod to JSON: %v", err)
	}
	if string(jsonPod) != expectedPod {
		t.Fatalf("CreateGoPod returned invalid pod with base64 private key: %v", string(jsonPod))
	}

	// Try with invalid private key hex
	wrongPrivateKey := "000102030405060708090001003040506070809000102030405060708090001"

	_, err = NewSigner(wrongPrivateKey)
	if err == nil || !strings.HasPrefix(err.Error(), "failed to parse private key") {
		t.Fatalf("NewSigner should have failed")
	}

	// Try with invalid private key base64
	wrongPrivateKey = "AAECAwQFBgcICQABAgMEBQYHCAkAAQIDBAUGBwgJAA"

	_, err = NewSigner(wrongPrivateKey)
	if err == nil || !strings.HasPrefix(err.Error(), "failed to parse private key") {
		t.Fatalf("NewSigner should have failed")
	}
}

func TestJSONPodCompatibility(t *testing.T) {
	// Backward-compatibility test ensures Go can parse a POD from TypeScript, and
	// that future Go changes don't stop supporting the current JSON format.
	// This is the same string as used in Zupass PODPCD compatibility test for JSON format.
	const jsonFromTypeScript = `{"entries":{"I1":1,"_2I":-123,"_s2":"!@#$%%%^&","bigI1":9007199254740991,"bigI2":-9007199254740991,"c1":{"cryptographic":123},"c2":{"cryptographic":"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},"pk1":{"eddsa_pubkey":"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4"},"s1":"hello there"},"signature":"XeD51Okc6YfUH8P/zmbUQJRN16PqF41scbKOsMFyFC7oVclWQV+kd29iU6gmRhLAIg0xYf/iKsb5GE4YaPWzBA","signerPublicKey":"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4"}`
	var pod Pod
	if err := json.Unmarshal([]byte(jsonFromTypeScript), &pod); err != nil {
		t.Fatalf("Failed to parse POD from TS: %v", err)
	}
	ok, err := pod.Verify()
	if err != nil {
		t.Fatalf("Failed to verify POD from TS: %v", err)
	}
	if !ok {
		t.Fatalf("POD from TS has invalid signature")
	}
}

func TestBadJSONPod(t *testing.T) {
	// This utest grew out of an actual bug. The input string is a PODPCD of the
	// POD used in the compatibility test.  The result is that none of the JSON
	// names match when deserializing.  Before it was manually overridden, Go's
	// default behavior was to leave all the fields uninitialized, which didn't
	// originally cause any failures until signature verification.  This test
	// ensures that a clear failure happens at unmarshalling time.
	const jsonPCD = `{"id":"8209fd10-667d-4524-a855-acc51ce795f3","jsonPOD":{"entries":{"I1":1,"_2I":-123,"_s2":"!@#$%%%^&","bigI1":9007199254740991,"bigI2":-9007199254740991,"c1":{"cryptographic":123},"c2":{"cryptographic":"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},"pk1":{"eddsa_pubkey":"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4"},"s1":"hello there"},"signature":"XeD51Okc6YfUH8P/zmbUQJRN16PqF41scbKOsMFyFC7oVclWQV+kd29iU6gmRhLAIg0xYf/iKsb5GE4YaPWzBA","signerPublicKey":"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4"}}`
	var pod Pod
	if err := json.Unmarshal([]byte(jsonPCD), &pod); err == nil {
		t.Fatalf("Expected to fail to parse non-POD JSON %v", pod)
	}

	// Simplified version of the original test would just be to unmarshal some
	// empty JSON, or incompatible JSON types.
	if err := json.Unmarshal([]byte("{}"), &pod); err == nil {
		t.Fatalf("Expected to fail to parse non-POD JSON")
	}
	if err := json.Unmarshal([]byte("[]"), &pod); err == nil {
		t.Fatalf("Expected to fail to parse non-POD JSON")
	}
	if err := json.Unmarshal([]byte(""), &pod); err == nil {
		t.Fatalf("Expected to fail to parse non-POD JSON")
	}
	if err := json.Unmarshal([]byte("123"), &pod); err == nil {
		t.Fatalf("Expected to fail to parse non-POD JSON")
	}
}
