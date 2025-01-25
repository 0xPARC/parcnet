package pod

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/iden3/go-iden3-crypto/v2/babyjub"
	"github.com/iden3/go-iden3-crypto/v2/poseidon"
)

// func TestVerify(t *testing.T) {
// 	p, _, err := CreatePod(
// 		"0001020304050607080900010203040506070809000102030405060708090001",
// 		map[string]interface{}{"hello": map[string]interface{}{"string": "world"}},
// 	)
// 	if err != nil {
// 		t.Fatalf("CreatePod failed: %v", err)
// 	}

// 	ok, err := p.Verify()
// 	if err != nil {
// 		t.Fatalf("Verify failed: %v", err)
// 	}
// 	if !ok {
// 		t.Fatalf("Verify for valid pod returned false")
// 	}

// 	p.Signature = "0001020304050607080900010203040506070809000102030405060708090001"
// 	ok, err = p.Verify()
// 	if err != nil {
// 		t.Fatalf("Verify failed: %v", err)
// 	}
// 	if ok {
// 		t.Fatalf("Verify for invalid pod returned true")
// 	}
// }

func TestCryptography(t *testing.T) {
	startTime := time.Now()
	poseidon, err := poseidon.Hash([]*big.Int{big.NewInt(1), big.NewInt(2)})
	elapsed := time.Since(startTime)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}
	fmt.Println("TIME", elapsed)
	fmt.Println("POSEIDON", poseidon)

	var privKey babyjub.PrivateKey

	privKHex := "21a5e7321d0e2f3ca1cc6504396e6594a2211544b08c206847cdee96f832421a"

	hex.Decode(privKey[:], []byte(privKHex))

	pubKey := privKey.Public()
	fmt.Println("PUBKEY", pubKey)

	startTime = time.Now()
	signature, err := privKey.SignPoseidon(big.NewInt(1))
	elapsed = time.Since(startTime)
	fmt.Println("TIME", elapsed)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	fmt.Println("SIGNATURE", signature)
}

func TestUtils(t *testing.T) {
	str := hashString("test")
	value, err := hashPodValue(42)
	if err != nil {
		t.Fatalf("hashValue failed: %v", err)
	}
	fmt.Println("STRING", str)
	fmt.Println("VALUE", value)
}

func TestContentID(t *testing.T) {
	contentID, err := computeContentID(PodEntries{
		"A": PodValue{kind: "int", intVal: 123},
		"B": PodValue{kind: "int", intVal: 321},
		"G": PodValue{kind: "int", intVal: -7},
		"D": PodValue{kind: "string", strVal: "foobar"},
		"C": PodValue{kind: "boolean", boolVal: false},
	})
	if err != nil {
		t.Fatalf("computeContentID failed: %v", err)
	}
	fmt.Println("CONTENTID", contentID)
}

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
	fmt.Println("POD", pod)
	fmt.Println("POD.SIGNATURE", pod.Signature)
	fmt.Println("POD.SIGNERPUBLICKEY", pod.SignerPublicKey)
	jsonPod, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod to JSON: %v", err)
	}
	fmt.Println("POD JSON:", string(jsonPod))
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
