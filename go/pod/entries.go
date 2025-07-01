package pod

import (
	"encoding/json"
	"fmt"
	"regexp"
)

type PodEntries map[string]PodValue

// Checks that all the names and values in entries are well-formed and in
// valid ranges for their types.  Returns nil if all are legal.
func (p PodEntries) Check() error {
	for n, v := range p {
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

var PodNameRegex = regexp.MustCompile(`^[A-Za-z_]\w*$`)

// Checks that the given name is legal for a POD entry.  Returns nil if so.
func CheckPodName(name string) error {
	if !PodNameRegex.MatchString(name) {
		return fmt.Errorf("invalid POD name \"%s\": only alphanumeric characters and underscores are allowed", name)
	}
	return nil
}

func (p *PodEntries) UnmarshalJSON(data []byte) error {
	// Use the default unmarshal behavior, using a typecast to avoid
	// recursing back into this customized unmarshaler.
	type podEntriesWithoutUnmarshal PodEntries
	if err := json.Unmarshal(data, (*podEntriesWithoutUnmarshal)(p)); err != nil {
		return err
	}

	// Perform validity checks after unmarshaling.
	return p.Check()
}
