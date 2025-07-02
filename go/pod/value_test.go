package pod

import (
	"fmt"
	"math"
	"math/big"
	"testing"
	"time"
)

func TestNewValues(t *testing.T) {
	var value PodValue
	var err error
	var bigInt big.Int

	value = NewPodNullValue()
	if value.ValueType != PodNullValue {
		t.Fatalf("wrong type")
	}

	value = NewPodStringValue("")
	if value.ValueType != PodStringValue {
		t.Fatalf("wrong type")
	}
	if value.StringVal != "" {
		t.Fatalf("wrong value")
	}

	value = NewPodStringValue("abc123")
	if value.ValueType != PodStringValue {
		t.Fatalf("wrong type")
	}
	if value.StringVal != "abc123" {
		t.Fatalf("wrong value")
	}

	value, err = NewPodBytesValue([]byte{})
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodBytesValue {
		t.Fatalf("wrong type")
	}
	if len(value.BytesVal) != 0 {
		t.Fatalf("wrong value")
	}

	value, err = NewPodBytesValue([]byte{1, 2, 3})
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodBytesValue {
		t.Fatalf("wrong type")
	}
	if len(value.BytesVal) != 3 {
		t.Fatalf("wrong value")
	}

	value, err = NewPodCryptographicValue(big.NewInt(123))
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodCryptographicValue {
		t.Fatalf("wrong type")
	}
	if value.BigVal.Cmp(big.NewInt(123)) != 0 {
		t.Fatalf("wrong value")
	}

	value, err = NewPodCryptographicValue(big.NewInt(0))
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodCryptographicValue {
		t.Fatalf("wrong type")
	}
	if value.BigVal.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("wrong value")
	}

	_, success := bigInt.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495616", 10)
	if !success {
		t.Fatalf("bad literal")
	}
	value, err = NewPodCryptographicValue(&bigInt)
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodCryptographicValue {
		t.Fatalf("wrong type")
	}
	if value.BigVal.Cmp(&bigInt) != 0 {
		t.Fatalf("wrong value")
	}

	value, err = NewPodCryptographicValue(PodCryptographicMin())
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodCryptographicValue {
		t.Fatalf("wrong type")
	}
	if value.BigVal.Cmp(PodCryptographicMin()) != 0 {
		t.Fatalf("wrong value")
	}

	value, err = NewPodCryptographicValue(PodCryptographicMax())
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodCryptographicValue {
		t.Fatalf("wrong type")
	}
	if value.BigVal.Cmp(PodCryptographicMax()) != 0 {
		t.Fatalf("wrong value")
	}

	value, err = NewPodIntValue(big.NewInt(0))
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodIntValue {
		t.Fatalf("wrong type")
	}
	if value.BigVal.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("wrong value")
	}

	value, err = NewPodIntValue(big.NewInt(math.MinInt64))
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodIntValue {
		t.Fatalf("wrong type")
	}
	if value.BigVal.Cmp(PodIntMin()) != 0 {
		t.Fatalf("wrong value")
	}

	value, err = NewPodIntValue(big.NewInt(math.MaxInt64))
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodIntValue {
		t.Fatalf("wrong type")
	}
	if value.BigVal.Cmp(PodIntMax()) != 0 {
		t.Fatalf("wrong value")
	}

	value, err = NewPodIntValue(PodIntMin())
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodIntValue {
		t.Fatalf("wrong type")
	}
	if value.BigVal.Cmp(PodIntMin()) != 0 {
		t.Fatalf("wrong value")
	}

	value, err = NewPodIntValue(PodIntMax())
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodIntValue {
		t.Fatalf("wrong type")
	}
	if value.BigVal.Cmp(PodIntMax()) != 0 {
		t.Fatalf("wrong value")
	}

	value = NewPodBooleanValue(false)
	if value.ValueType != PodBooleanValue {
		t.Fatalf("wrong type")
	}
	if value.BoolVal {
		t.Fatalf("wrong value")
	}

	value = NewPodBooleanValue(true)
	if value.ValueType != PodBooleanValue {
		t.Fatalf("wrong type")
	}
	if !value.BoolVal {
		t.Fatalf("wrong value")
	}

	value, err = NewPodEdDSAPubkeyValue("xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4")
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodEdDSAPubkeyValue {
		t.Fatalf("wrong type")
	}
	if value.StringVal != "xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4" {
		t.Fatalf("wrong value")
	}

	value, err = NewPodEdDSAPubkeyValue("c433f7a696b7aa3a5224efb3993baf0ccd9e92eecee0c29a3f6c8208a9e81d9e")
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodEdDSAPubkeyValue {
		t.Fatalf("wrong type")
	}
	if value.StringVal != "c433f7a696b7aa3a5224efb3993baf0ccd9e92eecee0c29a3f6c8208a9e81d9e" {
		t.Fatalf("wrong value")
	}

	value, err = NewPodDateValue(time.Unix(0, 0))
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodDateValue {
		t.Fatalf("wrong type")
	}
	if value.TimeVal.Compare(time.Unix(0, 0)) != 0 {
		t.Fatalf("wrong value")
	}

	value, err = NewPodDateValue(PodDateMin())
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodDateValue {
		t.Fatalf("wrong type")
	}
	if value.TimeVal.Compare(PodDateMin()) != 0 {
		t.Fatalf("wrong value")
	}

	value, err = NewPodDateValue(PodDateMax())
	if err != nil {
		t.Fatalf("error constructing value: %s", err)
	}
	if value.ValueType != PodDateValue {
		t.Fatalf("wrong type")
	}
	if value.TimeVal.Compare(PodDateMax()) != 0 {
		t.Fatalf("wrong value")
	}

}

func TestCheckValues(t *testing.T) {
	var value PodValue
	var err error
	var bigInt big.Int
	var timeVal time.Time

	if value.Check() == nil {
		fmt.Printf("type '%v'\n", value.ValueType)
		t.Fatalf("expected error %v", value.ValueType)
	}

	if value, err = NewPodBytesValue(nil); err == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}
	value.ValueType = PodBytesValue
	value.BytesVal = nil
	if value.Check() == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}

	if value, err = NewPodCryptographicValue(nil); err == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}
	value.ValueType = PodCryptographicValue
	value.BigVal = nil
	if value.Check() == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}

	if value, err = NewPodCryptographicValue(big.NewInt(-1)); err == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}
	value.ValueType = PodCryptographicValue
	value.BigVal = big.NewInt(-1)
	if value.Check() == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}

	bigInt.Add(PodCryptographicMax(), big.NewInt(1))
	if value, err = NewPodCryptographicValue(&bigInt); err == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}
	value.ValueType = PodCryptographicValue
	value.BigVal = &bigInt
	if value.Check() == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}

	if value, err = NewPodIntValue(nil); err == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}
	value.ValueType = PodIntValue
	value.BigVal = nil
	if value.Check() == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}

	bigInt.Add(PodIntMin(), big.NewInt(-1))
	if value, err = NewPodIntValue(&bigInt); err == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}
	value.ValueType = PodIntValue
	value.BigVal = &bigInt
	if value.Check() == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}

	bigInt.Add(PodIntMax(), big.NewInt(1))
	if value, err = NewPodIntValue(&bigInt); err == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}
	value.ValueType = PodIntValue
	value.BigVal = &bigInt
	if value.Check() == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}

	if value, err = NewPodEdDSAPubkeyValue("xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ" /* truncated "4" */); err == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}
	value.ValueType = PodEdDSAPubkeyValue
	value.StringVal = "xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ" /* truncated "4" */
	if value.Check() == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}

	if value, err = NewPodEdDSAPubkeyValue("z433f7a696b7aa3a5224efb3993baf0ccd9e92eecee0c29a3f6c8208a9e81d9e" /* bad digit "z" */); err == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}
	value.ValueType = PodEdDSAPubkeyValue
	value.StringVal = "z433f7a696b7aa3a5224efb3993baf0ccd9e92eecee0c29a3f6c8208a9e81d9e" /* bad digit "z" */
	if value.Check() == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}

	timeVal = PodDateMin().Add(-1 * time.Nanosecond)
	if value, err = NewPodDateValue(timeVal); err == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}
	value.ValueType = PodDateValue
	value.TimeVal = timeVal
	if value.Check() == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}

	timeVal = PodDateMax().Add(1 * time.Nanosecond)
	if value, err = NewPodDateValue(timeVal); err == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}
	value.ValueType = PodDateValue
	value.TimeVal = timeVal
	if value.Check() == nil {
		t.Fatalf("expected error %v", value.ValueType)
	}
}

func TestDateUTCMilis(t *testing.T) {
	// Test #1 has a timezone, but no nanos.  Should convert to UTC without loss.
	testTime1, err := time.Parse(time.RFC3339Nano, "2025-06-30T23:44:58.123-08:00")
	if err != nil {
		t.Fatalf("Unable to parse test time: %v", err)
	}
	timeValue1, err := NewPodDateValue(testTime1)
	if err != nil {
		t.Fatalf("Unable to import test time: %v", err)
	}
	podTime1 := timeValue1.TimeVal
	if !testTime1.Equal(podTime1) {
		t.Fatalf("POD time not the same as input: %v %v", testTime1, podTime1)
	}

	// Test #2 has a timezone and nanos, which are truncated, such that time #2
	// becomes equal to time #1 after conversion.
	testTime2, err := time.Parse(time.RFC3339Nano, "2025-06-30T23:44:58.123456789-08:00")
	if err != nil {
		t.Fatalf("Unable to parse test time: %v", err)
	}
	timeValue2, err := NewPodDateValue(testTime2)
	if err != nil {
		t.Fatalf("Unable to import test time: %v", err)
	}
	podTime2 := timeValue2.TimeVal
	if testTime2.Equal(podTime2) {
		t.Fatalf("POD time expected to change: %v %v", testTime2, podTime2)
	}
	if !testTime1.Equal(podTime2) {
		t.Fatalf("POD time not the same as input: %v %v", testTime1, podTime2)
	}
}
