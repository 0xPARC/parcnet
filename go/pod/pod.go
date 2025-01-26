package pod

type PodEntries map[string]PodValue

type Pod struct {
	Entries         PodEntries `json:"entries"`
	Signature       string     `json:"signature"`
	SignerPublicKey string     `json:"signerPublicKey"`
}
