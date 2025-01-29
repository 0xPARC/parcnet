# pod

Package `pod` provides functionality to create and verify a cryptographically signed [POD](https://pod.org) (Provable Object Datatype). PODs signed in Go include:

- Arbitrary key-value pairs (`PodEntries`)
- A cryptographic signature (`Signature`)
- The public key of the signer (`SignerPublicKey`)

## Table of Contents

- [Installation](#installation)
- [Pod Struct](#pod-struct)
- [Creating a POD](#creating-a-pod)
- [Verifying a POD](#verifying-a-pod)
- [Example Usage](#example-usage)

---

## Installation

To install this package, run:

```bash
go get github.com/0xPARC/parcnet/go/pod@v0.1.0-beta
```

Then import it in your Go code:

```go
import "github.com/0xPARC/parcnet/go/pod"
```

## POD Struct

```go
type Pod struct {
  Entries         PodEntries `json:"entries"`
  Signature       string     `json:"signature"`
  SignerPublicKey string     `json:"signerPublicKey"`
}
```

- Entries: A map of string keys to PodValue values. Currently supports string, boolean, and int types.
- Signature: The BabyJubjub Eddsa signature (hex-compressed) over the content ID.
- SignerPublicKey: The public key (hex-compressed) of the signer.

## Creating a POD

Use the function CreatePod() to sign a set of key-value pairs (PodEntries) with a Baby Jubjub private key, returning a new Pod. Internally, the data is hashed via Poseidon, then signed using the provided private key.

```go
func CreatePod(privateKeyHex string, entries PodEntries) (*Pod, error)
```

## Verifying a POD

Use the function Verify() to verify a POD. Internally, the data is hashed into a content ID via a Poseidon-hash lean incremental merkle tree, then compared to the signature.

```go
func Verify(pod Pod) (bool, error)
```

## Example Usage

For a more comprehensive illustration, see the cmd/example/main.go file, which shows how to:

1. Create a new POD with specific entries.
1. Expose endpoints (in an HTTP server) to create and verify PODs.
1. Combine with external services (e.g., Redis).

```go
package main

import (
    "fmt"
    "log"

    "github.com/0xPARC/parcnet/go/pod"
)

func main() {
    // 1) Create your entries
    entries := pod.PodEntries{
        "message": {kind: "string", strVal: "Welcome to PARCNET!"},
    }

    // Use your EdDSA private key in hex format (32 bytes)
    privateKey := "YOUR_PRIVATE_KEY_HEX"
    newPod, err := pod.CreatePod(privateKey, entries)
    if err != nil {
        log.Fatalf("Error creating POD: %v", err)
    }

    // 2) Verify the POD
    isValid, err := newPod.Verify()
    if err != nil {
        log.Fatalf("Verification error: %v", err)
    }
    fmt.Printf("Is the POD valid? %v\n", isValid)
}
```
