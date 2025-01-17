package pod

import (
	"testing"
)

func TestCreatePod(t *testing.T) {
	p, j, err := CreatePod(
		"0001020304050607080900010203040506070809000102030405060708090001",
		map[string]interface{}{"hello": "world"},
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
}

func TestVerify(t *testing.T) {
	p, _, err := CreatePod(
		"0001020304050607080900010203040506070809000102030405060708090001",
		map[string]interface{}{"hello": "world"},
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

	p.Proof.Signature = "0001020304050607080900010203040506070809000102030405060708090001"
	ok, err = p.Verify()
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if ok {
		t.Fatalf("Verify for invalid pod returned true")
	}
}
