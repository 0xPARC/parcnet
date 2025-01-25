package pod

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/iden3/go-iden3-crypto/v2/babyjub"
	"github.com/iden3/go-iden3-crypto/v2/poseidon"
)

// func TestCreatePod(t *testing.T) {
// 	p, j, err := CreatePod(
// 		"0001020304050607080900010203040506070809000102030405060708090001",
// 		map[string]interface{}{
// 			"hello":           map[string]interface{}{"string": "world"},
// 			"year":            map[string]interface{}{"int": 2000},
// 			"created_by":      map[string]interface{}{"string": "Golang"},
// 			"is_valid":        map[string]interface{}{"boolean": true},
// 			"explicit_string": map[string]interface{}{"string": "explicit"},
// 		},
// 	)
// 	if err != nil {
// 		t.Fatalf("CreatePod failed: %v", err)
// 	}
// 	if p == nil {
// 		t.Fatalf("Pod is nil")
// 	}
// 	if len(j) == 0 {
// 		t.Fatalf("JSONPOD is empty")
// 	}
// 	fmt.Println("JSONPOD", j)

// 	expectedJSON := "{\"entries\":{\"created_by\":{\"string\":\"Golang\"},\"explicit_string\":{\"string\":\"explicit\"},\"hello\":{\"string\":\"world\"},\"is_valid\":{\"boolean\":true},\"year\":{\"int\":2000}},\"signature\":\"t7+VVUbi7qqSc0bzNemuD8MzLPPlSt+k29H/qVbYYBRXg8bJk4SAWMLFeA2UlcRJWH4N34Ovxs3oLp0OmzVTAg\",\"signerPublicKey\":\"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4\"}"
// 	if j != expectedJSON {
// 		t.Fatalf("JSONPOD does not match expected.\nExpected: %s\nGot: %s", expectedJSON, j)
// 	}
// }

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
	startTime := time.Now()
	Init()
	elapsed := time.Since(startTime)
	fmt.Println()
	fmt.Println("================================================")
	fmt.Println()
	fmt.Println("INIT TIME", elapsed)

	startTime = time.Now()
	_, _, err := CreatePod("0001020304050607080900010203040506070809000102030405060708090001", map[string]interface{}{"A": map[string]interface{}{"int": 123}, "B": map[string]interface{}{"int": 321}, "G": map[string]interface{}{"int": 7}, "D": map[string]interface{}{"string": "foobar"}, "C": map[string]interface{}{"boolean": false}})
	elapsed = time.Since(startTime)
	fmt.Println("RUST GO CREATE TIME", elapsed)
	if err != nil {
		t.Fatalf("CreatePod failed: %v", err)
	}

	startTime = time.Now()
	pod, err := CreateGoPod(privKey, PodEntries{
		"A": PodValue{kind: "int", intVal: 123},
		"B": PodValue{kind: "int", intVal: 321},
		"G": PodValue{kind: "int", intVal: -7},
		"D": PodValue{kind: "string", strVal: "foobar"},
		"C": PodValue{kind: "boolean", boolVal: false},
	})
	elapsed = time.Since(startTime)
	fmt.Println("NATIVE GO CREATE TIME", elapsed)
	if err != nil {
		t.Fatalf("CreateGoPod failed: %v", err)
	}
	fmt.Println("POD", pod)
	fmt.Println("POD.SIGNATURE", pod.Signature)
	fmt.Println("POD.SIGNERPUBLICKEY", pod.SignerPublicKey)
}
