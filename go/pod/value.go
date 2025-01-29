package pod

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"strconv"
	"strings"
	"time"

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

func (p *PodValue) UnmarshalJSON(data []byte) error {
	var raw interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	switch val := raw.(type) {
	case nil:
		p.ValueType = PodNullValue
		return nil
	case bool:
		p.ValueType = PodBooleanValue
		p.BoolVal = val
		return nil

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
		return nil

	case string:
		p.ValueType = PodStringValue
		p.StringVal = val
		return nil

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
            if (!typeExists || !valueExists || !typeIsString) {
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
				return nil

			case "boolean":
				p.ValueType = PodBooleanValue
				b, ok := jsonValue.(bool)
				if !ok {
					return fmt.Errorf("invalid 'boolean' encoding, got %T", jsonValue)
				}
				p.BoolVal = b
				return nil

			case "int":
				p.ValueType = PodIntValue
				return p.parseBigIntFromJSON(jsonValue)

			case "cryptographic":
				p.ValueType = PodCryptographicValue
				return p.parseBigIntFromJSON(jsonValue)

			case "bytes":
				p.ValueType = PodBytesValue
				s, ok := jsonValue.(string)
				if !ok {
					return fmt.Errorf("invalid 'bytes' encoding, got %T", jsonValue)
				}
				decoded, err := base64.StdEncoding.DecodeString(s)
				if err != nil {
					return fmt.Errorf("invalid base64 for 'bytes': %w", err)
				}
				p.BytesVal = decoded
				return nil

			case "eddsa_pubkey":
				p.ValueType = PodEdDSAPubkeyValue
				s, ok := jsonValue.(string)
				if !ok {
					return fmt.Errorf("invalid 'eddsa_pubkey' encoding, got %T", jsonValue)
				}
				p.StringVal = s
				return nil

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
				return nil

			case "null":
				if jsonValue != nil {
					return fmt.Errorf("invalid 'null' encoding, must be {\"null\":null}")
				}
				p.ValueType = PodNullValue
				return nil

			default:
				return fmt.Errorf("unknown key %q in object PodValue", jsonType)
			}

	default:
		return fmt.Errorf("invalid PodValue, got %T", val)
	}

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
	// case PodEdDSAPubkeyValue:
		// TODO: remove this
		// return poseidon.Hash([]*big.Int{big.NewInt(0)})
	case PodNullValue:
		nullHash, ok := new(big.Int).SetString(
			nullHashHex,
			16,
		)
		if !ok {
			return nil, fmt.Errorf("failed to create nullHash")
		}
		return nullHash, nil
	}
	return nil, fmt.Errorf("unknown PodValue kind %q", p.ValueType)
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
		enc := base64.StdEncoding.EncodeToString(p.BytesVal) // TODO: Change to unpadded Base64 encoding
		return json.Marshal(map[string]string{"bytes": enc})

	case PodEdDSAPubkeyValue:
		return json.Marshal(map[string]string{"eddsa_pubkey": p.StringVal}) // TODO: Change to unpadded Base64 encoding

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
