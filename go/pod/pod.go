package pod

import "encoding/base64"

type PodEntries map[string]PodValue

type Pod struct {
	Entries         PodEntries `json:"entries"`
	Signature       string     `json:"signature"`
	SignerPublicKey string     `json:"signerPublicKey"`
}

// noPadB64 matches Rust's base64::STANDARD_NO_PAD
var noPadB64 = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/").WithPadding(base64.NoPadding)
