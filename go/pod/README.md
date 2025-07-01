# pod

Package `pod` provides functionality to create and verify a cryptographically signed [POD](https://pod.org/pod/introduction) (Provable Object Datatype). PODs signed in Go include:

- Arbitrary key-value pairs (`PodEntries`)
- A cryptographic signature (`Signature`)
- The public key of the signer (`SignerPublicKey`)

## Table of Contents

- [Installation](#installation)
- [Pod Struct](#pod-struct)
- [Creating a POD](#creating-a-pod)
- [Verifying a POD](#verifying-a-pod)
- [Example Usage](#example-usage)
- [More Resources](#more-resources)

---

## Installation

To install this package, run:

```bash
go get github.com/0xPARC/parcnet/go/pod
```

Then import it in your Go code:

```go
import "github.com/0xPARC/parcnet/go/pod"
```

## Types

A `Pod` struct consists of:

- Entries: A map of string keys to `PodValue` items.
- Signature: The EdDSA-Poseidon signature over the content ID, in unpadded base64.
- SignerPublicKey: The EdDSA public key of the signer, in unpadded base64.

```go
type Pod struct {
  Entries         PodEntries `json:"entries"`
  Signature       string     `json:"signature"`
  SignerPublicKey string     `json:"signerPublicKey"`
}
```

`PodValue` is a union type that can hold any of the POD [value types](https://pod.org/pod/values#value-types)

```go

type PodEntries map[string]PodValue

type PodValue struct {
	ValueType PodValueType // string, bytes, cryptographic, int, boolean, or date
	StringVal string
	BytesVal  []byte
	BigVal    *big.Int
	BoolVal   bool
	TimeVal   time.Time
}
```

## API

### Creating a POD

Use the function CreatePod() to sign a set of key-value pairs (PodEntries) with a Baby Jubjub private key, returning a new Pod. Internally, the data is hashed via Poseidon, then signed using the provided private key.

```go
func CreatePod(privateKeyHex string, entries PodEntries) (*Pod, error)
```

### Verifying a POD

Use the function Verify() to verify a POD. Internally, the data is hashed into a content ID via a Poseidon-hash lean incremental merkle tree, then compared to the signature.

```go
func Verify(pod Pod) (bool, error)
```

## Example Usage

```go
package main

import (
	"encoding/json"
    "fmt"
    "log"

    "github.com/0xPARC/parcnet/go/pod"
)

func main() {
    // 1) Initialize your entries
    entries := pod.PodEntries{
        "message": {ValueType: pod.PodStringValue, StringVal: "Welcome to PARCNET!"},
    }

    // Replace with your own EdDSA private key in hex (32 bytes)
    privateKey := "0000000000000000000000000000000000000000000000000000000000000000"

    // 2) Create and sign the POD
    newPod, err := pod.CreatePod(privateKey, entries)
    if err != nil {
        log.Fatalf("Error creating POD: %v", err)
    }

    // 3) Verify the POD
    isValid, err := newPod.Verify()
    if err != nil {
        log.Fatalf("Verification error: %v", err)
    }
    fmt.Printf("Is the POD valid? %v\n", isValid)

    // 4) Serialize the POD to JSON
    jsonPod, err := json.Marshal(newPod)
    if err != nil {
        log.Fatalf("JSON marshalling error: %v", err)
    }

    // 5) Deserialize a POD from JSON
    var deserializedPOD Pod
    err = json.Unmarshal(jsonPod, &deserializedPod)
    if err != nil {
        log.Fatalf("JSON unmarshalling error: %v", err)
    }
}
```

For a more comprehensive illustration, see the cmd/server/main.go file, which shows how to:

1. Create a new POD with specific entries.
1. Expose endpoints (in an HTTP server) to create and verify PODs.
1. Combine with external services (e.g., Redis).

## More Resources

You can find more documentation in the [code](https://github.com/0xPARC/parcnet/tree/main/go/pod), or on [go.dev](https://pkg.go.dev/github.com/0xPARC/parcnet/go/pod#section-documentation)