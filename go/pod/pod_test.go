package pod

import (
	"encoding/json"
	"testing"

	"github.com/iden3/go-iden3-crypto/v2/babyjub"
)

func TestCreateGoPod(t *testing.T) {
	privKey := babyjub.PrivateKey{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8,
		9, 0, 1,
	}
	pod, err := signPod(privKey, PodEntries{
		"A": PodValue{kind: "int", intVal: 123},
		"B": PodValue{kind: "int", intVal: 321},
		"G": PodValue{kind: "int", intVal: -7},
		"D": PodValue{kind: "string", strVal: "foobar"},
		"C": PodValue{kind: "boolean", boolVal: false},
	})
	if err != nil {
		t.Fatalf("CreateGoPod failed: %v", err)
	}
	jsonPod, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod to JSON: %v", err)
	}
	expectedPod := `{"entries":{"A":{"int":123},"B":{"int":321},"C":{"boolean":false},"D":{"string":"foobar"},"G":{"int":-7}},"signature":"fd75dc76f55eeb27e518ed5ebaca78a2b269e27d70cc0106b9f1e823380995ad8a2216351493ba3f50704ef3daae86b5163d6055d0c6644c4a1e64f03adc2704","signerPublicKey":"c433f7a696b7aa3a5224efb3993baf0ccd9e92eecee0c29a3f6c8208a9e81d9e"}`
	if string(jsonPod) != expectedPod {
		t.Fatalf("CreateGoPod returned invalid pod: %v", string(jsonPod))
	}
}

func TestVerifyGoPod(t *testing.T) {
	privKey := babyjub.PrivateKey{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8,
		9, 0, 1,
	}
	pod, err := signPod(privKey, PodEntries{
		"A": PodValue{kind: "int", intVal: 123},
		"B": PodValue{kind: "int", intVal: 321},
		"G": PodValue{kind: "int", intVal: -7},
		"D": PodValue{kind: "string", strVal: "foobar"},
		"C": PodValue{kind: "boolean", boolVal: false},
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
	ok, err = pod.Verify()
	if ok {
		t.Fatalf("Verify for invalid pod returned true")
	}
}
