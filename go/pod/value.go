package pod

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/v2/poseidon"
)

// PodValue can represent one of { "string": "..." }, { "boolean": ... }, or { "int": ... }.
type PodValue struct {
	kind    string
	strVal  string
	boolVal bool
	intVal  int64
}

// UnmarshalJSON supports exactly one top-level key ("string","boolean","int").
func (p *PodValue) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw) != 1 {
		return fmt.Errorf("invalid PodValue: must have exactly one key")
	}
	for k, v := range raw {
		switch k {
		case "string":
			p.kind = "string"
			return json.Unmarshal(v, &p.strVal)
		case "boolean":
			p.kind = "boolean"
			return json.Unmarshal(v, &p.boolVal)
		case "int":
			p.kind = "int"
			return json.Unmarshal(v, &p.intVal)
		default:
			return fmt.Errorf("unknown key %q in PodValue", k)
		}
	}
	return nil
}

// MarshalJSON writes PodValue as { "string": ... }, { "boolean": ... }, or { "int": ... }.
func (p PodValue) MarshalJSON() ([]byte, error) {
	switch p.kind {
	case "string":
		return json.Marshal(map[string]string{"string": p.strVal})
	case "boolean":
		return json.Marshal(map[string]bool{"boolean": p.boolVal})
	case "int":
		return json.Marshal(map[string]int64{"int": p.intVal})
	}
	return nil, fmt.Errorf("cannot marshal unknown PodValue kind %q", p.kind)
}

func (p PodValue) Hash() (*big.Int, error) {
	switch p.kind {
	case "string":
		return hashString(p.strVal), nil
	case "boolean":
		if p.boolVal {
			return poseidon.Hash([]*big.Int{big.NewInt(1)})
		}
		return poseidon.Hash([]*big.Int{big.NewInt(0)})
	case "int":
		return poseidon.Hash([]*big.Int{fieldSafeInt64(p.intVal)})
	}
	return nil, fmt.Errorf("unknown PodValue kind %q", p.kind)
}

