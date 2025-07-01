package pod

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// The keys and values stored in a POD
type PodEntries map[string]PodValue

// Checks that all the names and values in entries are well-formed and in
// valid ranges for their types.  Returns nil if all are legal.
func (p *PodEntries) Check() error {
	if p == nil || *p == nil {
		return fmt.Errorf("PodEntries should not be nil")
	}
	for n, v := range *p {
		err := CheckPodName(n)
		if err != nil {
			return err
		}
		err = v.checkWithNamePrefix(fmt.Sprintf("%s: ", n))
		if err != nil {
			return err
		}
	}
	return nil
}

// Regular expression defining the legal format for the name of a POD entry.
var PodNameRegex = regexp.MustCompile(`^[A-Za-z_]\w*$`)

// Checks that the given name is legal for a POD entry.  Returns nil if so.
func CheckPodName(name string) error {
	if !PodNameRegex.MatchString(name) {
		return fmt.Errorf("invalid POD name \"%s\": only alphanumeric characters and underscores are allowed", name)
	}
	return nil
}

// Parse entries from JSON in POD's terse human-readable format
func (p *PodEntries) UnmarshalJSON(data []byte) error {
	// Use the default unmarshal behavior, using a typecast to avoid
	// recursing back into this customized unmarshaler.
	type podEntriesWithoutUnmarshal PodEntries
	var deserialized podEntriesWithoutUnmarshal
	if err := json.Unmarshal(data, &deserialized); err != nil {
		return err
	}

	// Overwrite the output with a new object, to ensure any keys missing
	// in JSON aren't left over from input.
	*p = (PodEntries)(deserialized)

	// If there are no entries, we want an empty map, not a nil one
	if *p == nil {
		return fmt.Errorf("unmarshalled POD entries are nil")
	}

	// Perform validity checks after unmarshaling.
	return p.Check()
}
