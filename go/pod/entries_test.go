package pod

import (
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/go-test/deep"
)

func TestCheckLegalPodNames(t *testing.T) {
	if CheckPodName("a") != nil {
		t.Fatalf("expected good name")
	}
	if CheckPodName("_") != nil {
		t.Fatalf("expected good name")
	}
	if CheckPodName("abc123_xyz") != nil {
		t.Fatalf("expected good name")
	}
	if CheckPodName("__init") != nil {
		t.Fatalf("expected good name")
	}
	if CheckPodName("pod_type") != nil {
		t.Fatalf("expected good name")
	}
}

func TestCheckIllegalPodNames(t *testing.T) {
	if CheckPodName("") == nil {
		t.Fatalf("expected bad name")
	}
	if CheckPodName("2") == nil {
		t.Fatalf("expected bad name")
	}
	if CheckPodName("abc 123") == nil {
		t.Fatalf("expected bad name")
	}
	if CheckPodName("_!@#$%^&") == nil {
		t.Fatalf("expected bad name")
	}
	if CheckPodName("\U0001F4A9") == nil {
		t.Fatalf("expected bad name")
	}
}

func TestLegalPodEntries(t *testing.T) {
	nullValue := NewPodNullValue()
	stringValue := NewPodStringValue("abc")
	bytesValue, err := NewPodBytesValue([]byte{1, 2, 3})
	if err != nil {
		t.Fatalf("failed to create value: %v", err)
	}
	cryptValue, err := NewPodCryptographicValue(new(big.Int).Add(PodCryptographicMax(), big.NewInt(-123)))
	if err != nil {
		t.Fatalf("failed to create value: %v", err)
	}
	intValue, err := NewPodIntValue(big.NewInt(12345))
	if err != nil {
		t.Fatalf("failed to create value: %v", err)
	}
	boolValue := NewPodBooleanValue(true)
	pubKeyValue, err := NewPodEdDSAPubkeyValue("xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4")
	if err != nil {
		t.Fatalf("failed to create value: %v", err)
	}
	dateValue, err := NewPodDateValue(time.Unix(123, 456))

	entries := PodEntries{
		"_":            nullValue,
		"a":            stringValue,
		"abc123_xyz":   bytesValue,
		"__foo":        cryptValue,
		"hello":        intValue,
		"true":         boolValue,
		"owner":        pubKeyValue,
		"theTimeIsNow": dateValue,
	}

	// Entries should validate as-is.
	err = entries.Check()
	if err != nil {
		t.Fatalf("check failed on legal entries: %v", err)
	}

	// Entries should serialize and deserialize.
	serialized, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("Failed to marshal entries to JSON: %v", err)
	}
	var deserializedEntries PodEntries
	err = json.Unmarshal([]byte(serialized), &deserializedEntries)
	if err != nil {
		t.Fatalf("Failed to unmarshal entries from JSON: %v", err)
	}

	// Deserialized entries should be valid, and the same as original.
	err = deserializedEntries.Check()
	if err != nil {
		t.Fatalf("check failed on deserialized entries: %v", err)
	}
	if diff := deep.Equal(entries, deserializedEntries); diff != nil {
		t.Fatalf("Original and deserialized entries differ: %v", diff)
	}
}

func TestIllegalPodEntries(t *testing.T) {
	// Bad name
	entries := PodEntries{"bad name": NewPodNullValue()}
	if entries.Check() == nil {
		t.Fatalf("expected bad entries during check")
	}
	if _, err := computeContentID(entries); err == nil {
		t.Fatalf("expected bad entries during compute contentID")
	}
	jsonEntries := `{"bad name": null}`
	if json.Unmarshal([]byte(jsonEntries), &entries) == nil {
		t.Fatalf("expected bad entries during unmarshal")
	}

	// Bad value
	badValue := PodValue{ValueType: PodCryptographicValue, BigVal: big.NewInt(-1)}
	entries = PodEntries{"goodName": badValue}
	if entries.Check() == nil {
		t.Fatalf("expected bad entries during check")
	}
	if _, err := computeContentID(entries); err == nil {
		t.Fatalf("expected bad entries during compute contentID")
	}
	jsonEntries = `{"goodName": {"cryptographic": -1 } }`
	if json.Unmarshal([]byte(jsonEntries), &entries) == nil {
		t.Fatalf("expected bad entries during unmarshal")
	}

}
