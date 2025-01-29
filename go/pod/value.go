package pod

import (
	"encoding/json"
	"fmt"
)

// Currently, only supports string, boolean, and int.
type PodValue struct {
	kind    string
	strVal  string
	boolVal bool
	intVal  int64
}

func rawToPodValueInt(val int64) interface{} {
	if val >= -(1<<52) && val < (1<<52) {
		return val
	} else if val >= (1 << 52) {
		return fmt.Sprintf("0x%x", val)
	} else {
		return fmt.Sprintf("%d", val)
	}
}

func podValueToRawInt(data interface{}) (int64, error) {
	switch v := data.(type) {
	case float64:
		return int64(v), nil
	case string:
		if len(v) > 2 && v[:2] == "0x" {
			var val int64
			_, err := fmt.Sscanf(v, "0x%x", &val)
			if err != nil {
				return 0, fmt.Errorf("invalid hex integer: %v", err)
			}
			return val, nil
		} else {
			var val int64
			_, err := fmt.Sscanf(v, "%d", &val)
			if err != nil {
				return 0, fmt.Errorf("invalid decimal integer: %v", err)
			}
			return val, nil
		}
	default:
		return 0, fmt.Errorf("unexpected type %T for integer representation", data)
	}
}

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
			var temp interface{}
			if err := json.Unmarshal(v, &temp); err != nil {
				return err
			}
			parsedVal, err := podValueToRawInt(temp)
			if err != nil {
				return err
			}
			p.intVal = parsedVal
		default:
			return fmt.Errorf("unknown key %q in PodValue", k)
		}
	}
	return nil
}

func (p PodValue) MarshalJSON() ([]byte, error) {
	switch p.kind {
	case "string":
		return json.Marshal(map[string]string{"string": p.strVal})
	case "boolean":
		return json.Marshal(map[string]bool{"boolean": p.boolVal})
	case "int":
		rep := rawToPodValueInt(p.intVal)
		return json.Marshal(map[string]interface{}{"int": rep})
	}
	return nil, fmt.Errorf("cannot marshal unknown PodValue kind %q", p.kind)
}
