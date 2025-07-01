package pod

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"

	"strconv"
	"strings"
	"time"

	"github.com/iden3/go-iden3-crypto/v2/babyjub"
	"github.com/iden3/go-iden3-crypto/v2/poseidon"
)

type PodValueType string

const (
	PodNullValue          PodValueType = "null"
	PodStringValue        PodValueType = "string"
	PodBytesValue         PodValueType = "bytes"
	PodCryptographicValue PodValueType = "cryptographic"
	PodIntValue           PodValueType = "int"
	PodBooleanValue       PodValueType = "boolean"
	PodEdDSAPubkeyValue   PodValueType = "eddsa_pubkey"
	PodDateValue          PodValueType = "date"
)

type PodValue struct {
	ValueType PodValueType
	StringVal string
	BytesVal  []byte
	BigVal    *big.Int
	BoolVal   bool
	TimeVal   time.Time
}

func newBigIntFromDecimalLiteral(decimalValue string) *big.Int {
	v := &big.Int{}
	v, success := v.SetString(decimalValue, 10)
	if !success {
		panic(fmt.Sprintf("invalid decimal bigint literal %s", decimalValue))
	}
	return v
}

// Minimum legal POD cryptographic value is 0
func PodCryptographicMin() *big.Int {
	return big.NewInt(0)
}

// Maximum legal POD cryptographic value is 1 less than the Baby Jubjub prime,
// i.e. 21888242871839275222246405745257275088548364400416034343698204186575808495616
func PodCryptographicMax() *big.Int {
	return newBigIntFromDecimalLiteral("21888242871839275222246405745257275088548364400416034343698204186575808495616")
}

// Minimum legal POD int value is -2^63
func PodIntMin() *big.Int {
	return big.NewInt(math.MinInt64)
}

// Maximum legal POD int value is 2^63-1
func PodIntMax() *big.Int {
	return big.NewInt(math.MaxInt64)
}

// Minimum legal POD int value is -8,640,000,000,000,000ms since epoch
func PodDateMin() time.Time {
	return time.UnixMilli(-8_640_000_000_000_000)
}

// Maximum legal POD date value is 8,640,000,000,000,000ms since epoch
func PodDateMax() time.Time {
	return time.UnixMilli(8_640_000_000_000_000)
}

// Constructor for null POD values
func NewPodNullValue() PodValue {
	return PodValue{ValueType: PodNullValue}
}

// Constructor for string POD values
func NewPodStringValue(val string) PodValue {
	return PodValue{ValueType: PodStringValue, StringVal: val}
}

// Constructor for bytes POD values.  Error if input is nil.
func NewPodBytesValue(val []byte) (PodValue, error) {
	value := PodValue{ValueType: PodBytesValue, BytesVal: val}
	return value, value.Check()
}

// Constructor for cryptographic POD values.  Error if input is nil or out of range.
func NewPodCryptographicValue(val *big.Int) (PodValue, error) {
	if val == nil {
		return PodValue{}, fmt.Errorf("%s val should not be nil", PodCryptographicValue)
	}
	value := PodValue{ValueType: PodCryptographicValue, BigVal: &big.Int{}}
	value.BigVal.Set(val)
	return value, value.Check()
}

// Constructor for int POD values.  Error if input is nil or out of range.
func NewPodIntValue(val *big.Int) (PodValue, error) {
	if val == nil {
		return PodValue{}, fmt.Errorf("%s val should not be nil", PodIntValue)
	}
	value := PodValue{ValueType: PodIntValue, BigVal: &big.Int{}}
	value.BigVal.Set(val)
	return value, value.Check()
}

// Constructor for int POD values.  Error if input is nil or out of range.
func NewPodBooleanValue(val bool) PodValue {
	value := PodValue{ValueType: PodBooleanValue, BoolVal: val}
	return value
}

// Constructor for int POD values.  Error if input is not 32 bytes encoded in
// Base64 (with or without padding).
func NewPodEdDSAPubkeyValue(val string) (PodValue, error) {
	value := PodValue{ValueType: PodEdDSAPubkeyValue, StringVal: val}
	return value, value.Check()
}

// Constructor for int POD values.  Error if input is nil or out of range.
func NewPodDateValue(val time.Time) (PodValue, error) {
	if err := checkTimeBounds("", PodDateValue, val, PodDateMin(), PodDateMax()); err != nil {
		return PodValue{}, err
	}
	// Explicitly truncate to millis, and force to UTC
	millisTime := val.Truncate(time.Millisecond).UTC()
	value := PodValue{ValueType: PodDateValue, TimeVal: millisTime}
	return value, value.Check()
}

// Constructor for cryptographic POD values.
// BigInt must be non-nil and in the range [PodCryptographicMin, PodCryptographicMax]

// Checks that the value is well-formed and in the legal bounds for its type.
// Returns nil if it is, otherwise an error explaining what's wrong.
func (p *PodValue) Check() error {
	return p.checkWithNamePrefix("")
}

func (p *PodValue) checkWithNamePrefix(namePrefix string) error {
	if p == nil {
		return fmt.Errorf("%svalue must not be nil", namePrefix)
	}

	switch p.ValueType {
	case PodNullValue:
		return nil
	case PodStringValue:
		return nil
	case PodBytesValue:
		if p.BytesVal == nil {
			return fmt.Errorf("%s%s should not be nil", namePrefix, p.ValueType)
		}
		return nil
	case PodCryptographicValue:
		return checkNumericBounds(
			namePrefix,
			PodCryptographicValue,
			p.BigVal,
			PodCryptographicMin(),
			PodCryptographicMax(),
		)
	case PodIntValue:
		return checkNumericBounds(
			namePrefix,
			PodIntValue,
			p.BigVal,
			PodIntMin(),
			PodIntMax(),
		)
	case PodBooleanValue:
		return nil
	case PodEdDSAPubkeyValue:
		pubKeyBytes, err := DecodeBytes(p.StringVal, 32)
		if err != nil || len(pubKeyBytes) != 32 {
			return fmt.Errorf("%sfailed to decode public key '%s': %w", namePrefix, p.StringVal, err)
		}
		// We don't try to decompress the bytes into a point until verifying,
		// which is consistent with the TypeScript library.
		return nil
	case PodDateValue:
		return checkTimeBounds(
			namePrefix,
			PodDateValue,
			p.TimeVal,
			PodDateMin(),
			PodDateMax(),
		)
	default:
		return fmt.Errorf("%sunknown PodValueType %s", namePrefix, p.ValueType)
	}
}

func checkNumericBounds(
	namePrefix string,
	valueType PodValueType,
	val *big.Int,
	minValue *big.Int,
	maxValue *big.Int,
) error {
	if val == nil {
		return fmt.Errorf("%s%s should not be nil", namePrefix, valueType)
	}
	if minValue == nil || maxValue == nil {
		return fmt.Errorf("%s%s requires a lower and upper bound (%v,%v)", namePrefix, valueType, minValue, maxValue)
	}
	if val.Cmp(minValue) < 0 {
		return fmt.Errorf("%s%s %v less than minimum %v", namePrefix, valueType, val, minValue)
	}
	if val.Cmp(maxValue) > 0 {
		return fmt.Errorf("%s%s %v less than minimum %v", namePrefix, valueType, val, maxValue)
	}
	return nil
}

func checkTimeBounds(
	namePrefix string,
	valueType PodValueType,
	val time.Time,
	minValue time.Time,
	maxValue time.Time,
) error {
	if val.Before(minValue) {
		return fmt.Errorf("%s%s %v less than minimum %v", namePrefix, valueType, val, minValue)
	}
	if val.After(maxValue) {
		return fmt.Errorf("%s%s %v less than minimum %v", namePrefix, valueType, val, maxValue)
	}
	return nil
}

func (p *PodValue) UnmarshalJSON(data []byte) error {
	var raw interface{}
	var err error

	if err = json.Unmarshal(data, &raw); err != nil {
		return err
	}

	switch val := raw.(type) {
	case nil:
		p.ValueType = PodNullValue

	case bool:
		p.ValueType = PodBooleanValue
		p.BoolVal = val

	case float64:
		// Bare number => treat as "int" by TS rules,
		// but we store it in p.BigVal. Then we also check if it fits the standard 64-bit
		// or do range checks as needed. We'll consider it an "int" type in Go.
		p.ValueType = PodIntValue
		p.BigVal = big.NewInt(int64(val))
		// Check if fractional part was lost by int64 cast:
		if float64(p.BigVal.Int64()) != val {
			return fmt.Errorf("got a floating (non-integer) JSON number, which is invalid for 'int'")
		}

	case string:
		p.ValueType = PodStringValue
		p.StringVal = val

	// Check for TypedJSON
	case map[string]interface{}:
		var jsonType string
		var jsonValue interface{}

		if len(val) == 1 {
			for k, v := range val {
				jsonType = k
				jsonValue = v
			}
		} else {
			var typeIsString bool
			var valueExists bool

			rawJsonType, typeExists := val["type"]
			jsonValue, valueExists = val["value"]
			jsonType, typeIsString = rawJsonType.(string)
			if !typeExists || !valueExists || !typeIsString {
				return fmt.Errorf("invalid PodValue: %v", val)
			}
		}

		switch jsonType {
		case "string":
			p.ValueType = PodStringValue
			str, ok := jsonValue.(string)
			if !ok {
				return fmt.Errorf("invalid 'string' encoding (must be a JSON string), got %T", jsonValue)
			}
			p.StringVal = str

		case "boolean":
			p.ValueType = PodBooleanValue
			b, ok := jsonValue.(bool)
			if !ok {
				return fmt.Errorf("invalid 'boolean' encoding, got %T", jsonValue)
			}
			p.BoolVal = b

		case "int":
			p.ValueType = PodIntValue
			if err = p.parseBigIntFromJSON(jsonValue); err != nil {
				return err
			}

		case "cryptographic":
			p.ValueType = PodCryptographicValue
			if err = p.parseBigIntFromJSON(jsonValue); err != nil {
				return err
			}

		case "bytes":
			p.ValueType = PodBytesValue
			s, ok := jsonValue.(string)
			if !ok {
				return fmt.Errorf("invalid 'bytes' encoding, got %T", jsonValue)
			}
			decoded, err := DecodeBase64Bytes(s)
			if err != nil {
				return fmt.Errorf("invalid base64 for 'bytes': %w", err)
			}
			p.BytesVal = decoded

		case "eddsa_pubkey":
			p.ValueType = PodEdDSAPubkeyValue
			s, ok := jsonValue.(string)
			if !ok {
				return fmt.Errorf("invalid 'eddsa_pubkey' encoding, got %T", jsonValue)
			}
			p.StringVal = s

		case "date":
			p.ValueType = PodDateValue
			s, ok := jsonValue.(string)
			if !ok {
				return fmt.Errorf("invalid 'date' encoding, got %T", jsonValue)
			}
			if !strings.HasSuffix(s, "Z") {
				return fmt.Errorf("date must be encoded in UTC: %q", s)
			}
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return fmt.Errorf("invalid date: %w", err)
			}
			p.TimeVal = t

		case "null":
			if jsonValue != nil {
				return fmt.Errorf("invalid 'null' encoding, must be {\"null\":null}")
			}
			p.ValueType = PodNullValue

		default:
			return fmt.Errorf("unknown key %q in object PodValue", jsonType)
		}

	default:
		return fmt.Errorf("invalid PodValue, got %T", val)
	}

	return p.Check()
}

func (p *PodValue) parseBigIntFromJSON(v interface{}) error {
	switch vv := v.(type) {
	case float64:
		tmp := big.NewInt(int64(vv))
		if float64(tmp.Int64()) != vv {
			return fmt.Errorf("non-integer float cannot be parsed to bigint': %g", vv)
		}
		p.BigVal = tmp
		return nil
	case string:
		return p.parseBigIntFromString(vv)
	default:
		return fmt.Errorf("invalid numeric encoding in 'int'/'cryptographic', got %T", v)
	}
}

const nullHashHex = "1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d"

func (p PodValue) Hash() (*big.Int, error) {
	switch p.ValueType {
	case PodStringValue:
		return hashString(p.StringVal), nil
	case PodBooleanValue:
		if p.BoolVal {
			return poseidon.Hash([]*big.Int{big.NewInt(1)})
		}
		return poseidon.Hash([]*big.Int{big.NewInt(0)})
	case PodIntValue:
		return poseidon.Hash([]*big.Int{fieldSafeInt64(p.BigVal.Int64())})
	case PodDateValue:
		return poseidon.Hash([]*big.Int{big.NewInt(p.TimeVal.UnixMilli())})
	case PodBytesValue:
		return hashBytes(p.BytesVal), nil
	case PodCryptographicValue:
		return poseidon.Hash([]*big.Int{p.BigVal})
	case PodEdDSAPubkeyValue:
		publicKeyBytes, err := DecodeBytes(p.StringVal, 32)
		if err != nil || len(publicKeyBytes) != 32 {
			return nil, fmt.Errorf("failed to decode public key '%s': %w", p.StringVal, err)
		}

		publicKeyComp := babyjub.PublicKeyComp(publicKeyBytes)
		publicKey, err := publicKeyComp.Decompress()
		if err != nil {
			return nil, fmt.Errorf("failed to decompress public key: %w", err)
		}

		return poseidon.Hash([]*big.Int{publicKey.X, publicKey.Y})
	case PodNullValue:
		nullHash, ok := new(big.Int).SetString(
			nullHashHex,
			16,
		)
		if !ok {
			return nil, fmt.Errorf("failed to create nullHash")
		}
		return nullHash, nil
	default:
		return nil, fmt.Errorf("unknown PodValue type %q", p.ValueType)
	}
}

// parseBigIntFromString handles decimal or hex string
func (p *PodValue) parseBigIntFromString(s string) error {
	var z big.Int
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		_, ok := z.SetString(s[2:], 16)
		if !ok {
			return fmt.Errorf("invalid hex in BigInt string %q", s)
		}
	} else {
		_, ok := z.SetString(s, 10)
		if !ok {
			return fmt.Errorf("invalid decimal in BigInt string %q", s)
		}
	}
	p.BigVal = &z
	return nil
}

func (p PodValue) MarshalJSON() ([]byte, error) {
	switch p.ValueType {
	case PodNullValue:
		return []byte("null"), nil

	case PodBooleanValue:
		return json.Marshal(p.BoolVal)

	case PodStringValue:
		return json.Marshal(p.StringVal)

	case PodBytesValue:
		enc := noPadB64.EncodeToString(p.BytesVal)
		return json.Marshal(map[string]string{"bytes": enc})

	case PodEdDSAPubkeyValue:
		return json.Marshal(map[string]string{"eddsa_pubkey": p.StringVal})

	case PodDateValue:
		// Pass in sample string with 3 digits of precision to match TS
		iso := p.TimeVal.UTC().Format("2006-01-02T15:04:05.000Z")
		return json.Marshal(map[string]string{"date": iso})

	case PodCryptographicValue:
		if fitsInSafeJSRange(p.BigVal) {
			return json.Marshal(map[string]interface{}{"cryptographic": float64(p.BigVal.Int64())})
		}
		return json.Marshal(map[string]interface{}{"cryptographic": formatBigIntToString(p.BigVal)})

	case PodIntValue:
		// If the given BigVal fits in ±(2^53 - 1), produce a raw JSON integer.
		// Otherwise return { "int": "..."}, with either decimal or hex serialization.
		if p.BigVal == nil {
			return nil, fmt.Errorf("nil big.Int in PodIntValue")
		}
		// Check ±2^53
		if fitsInSafeJSRange(p.BigVal) {
			return []byte(strconv.FormatInt(p.BigVal.Int64(), 10)), nil
		}
		// otherwise produce object with string
		rep := formatBigIntToString(p.BigVal)
		return json.Marshal(map[string]string{"int": rep})

	default:
		return nil, fmt.Errorf("unknown PodValueType %q", p.ValueType)
	}
}

// formatBigIntToString() is called when an integer goes out of bounds of the
// safe JS range. It returns a string representation of the integer, using hex
// for positive values and decimal for negative values.
func formatBigIntToString(z *big.Int) string {
	if z.Sign() < 0 {
		return z.String()
	}
	return "0x" + strings.ToLower(z.Text(16))
}

// fitsInSafeJSRange checks if |z| <= 2^53 - 1
func fitsInSafeJSRange(z *big.Int) bool {
	minSafe := big.NewInt(-9007199254740991)
	maxSafe := big.NewInt(9007199254740991)
	return z.Cmp(minSafe) >= 0 && z.Cmp(maxSafe) <= 0
}
