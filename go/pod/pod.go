package pod

import (
	"encoding/json"
	"fmt"
)

// Provable Object Datatype containing a cryptographically verified key/value store
type Pod struct {
	Entries         PodEntries `json:"entries"`
	Signature       string     `json:"signature"`
	SignerPublicKey string     `json:"signerPublicKey"`
}

// Checks that the data in this POD is well-formed and in valid ranges, including
// all entries.  This does check the cryptographic signature.  For that you should
// call Verify() instead, in which case this function would be redundant.
func (p *Pod) CheckFormat() error {
	if err := p.Entries.Check(); err != nil {
		return err
	}
	if err := p.checkFormatWithoutEntries(); err != nil {
		return err
	}
	return nil
}

func (p *Pod) checkFormatWithoutEntries() error {
	if !SignatureRegex.MatchString(p.Signature) {
		return fmt.Errorf("POD signature does not match expected format - 64 bytes Base64 or hex: '%s'", p.Signature)
	}
	if !SignatureRegex.MatchString(p.Signature) {
		return fmt.Errorf("POD signature does not match expected format - 64 bytes Base64 or hex: '%s'", p.Signature)
	}
	return nil
}

// Parse a POD from JSON in POD's terse human-readable format
func (p *Pod) UnmarshalJSON(data []byte) error {
	// Use the default unmarshal behavior, using a typecast to avoid
	// recursing back into this customized unmarshaler.
	type podWithoutUnmarshal Pod
	var deserialized podWithoutUnmarshal
	if err := json.Unmarshal(data, &deserialized); err != nil {
		return err
	}

	// Overwrite the output with a new object, to ensure any keys missing
	// in JSON aren't left over from input.
	*p = (Pod)(deserialized)

	// Perform validity checks after unmarshaling. Entries are already checked
	// by their own unmarshaling.
	return p.checkFormatWithoutEntries()
}
