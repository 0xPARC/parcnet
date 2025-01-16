package pod

import (
	"fmt"
	"testing"
)

func TestCreatePod(t *testing.T) {
	p, j, err := CreatePod(
		"0001020304050607080900010203040506070809000102030405060708090001",
		map[string]interface{}{
			"hello":           map[string]interface{}{"string": "world"},
			"year":            map[string]interface{}{"int": 2000},
			"created_by":      map[string]interface{}{"string": "Golang"},
			"is_valid":        map[string]interface{}{"boolean": true},
			"explicit_string": map[string]interface{}{"string": "explicit"},
		},
	)
	if err != nil {
		t.Fatalf("CreatePod failed: %v", err)
	}
	if p == nil {
		t.Fatalf("Pod is nil")
	}
	if len(j) == 0 {
		t.Fatalf("JSONPOD is empty")
	}
	fmt.Println("JSONPOD", j)

	expectedJSON := "{\"entries\":{\"created_by\":{\"string\":\"Golang\"},\"explicit_string\":{\"string\":\"explicit\"},\"hello\":{\"string\":\"world\"},\"is_valid\":{\"boolean\":true},\"year\":{\"int\":2000}},\"signature\":\"t7+VVUbi7qqSc0bzNemuD8MzLPPlSt+k29H/qVbYYBRXg8bJk4SAWMLFeA2UlcRJWH4N34Ovxs3oLp0OmzVTAg\",\"signerPublicKey\":\"xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4\"}"
	if j != expectedJSON {
		t.Fatalf("JSONPOD does not match expected.\nExpected: %s\nGot: %s", expectedJSON, j)
	}
}

func TestVerify(t *testing.T) {
	p, _, err := CreatePod(
		"0001020304050607080900010203040506070809000102030405060708090001",
		map[string]interface{}{"hello": map[string]interface{}{"string": "world"}},
	)
	if err != nil {
		t.Fatalf("CreatePod failed: %v", err)
	}

	ok, err := p.Verify()
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatalf("Verify for valid pod returned false")
	}

	p.Signature = "0001020304050607080900010203040506070809000102030405060708090001"
	ok, err = p.Verify()
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if ok {
		t.Fatalf("Verify for invalid pod returned true")
	}
}
