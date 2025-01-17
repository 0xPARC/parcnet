package main

import (
	"fmt"

	"github.com/0xPARC/parcnet/pkg/pod"
)

func main() {
	fmt.Println("=== CREATE POD  ===")
	myPod, jsonPod, err := pod.CreatePod(
		"0001020304050607080900010203040506070809000102030405060708090001",
		map[string]interface{}{
			"created_by": "Golang",
			"year":       2025,
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Pod:", myPod)
	fmt.Println("JSONPOD:", jsonPod)

	fmt.Println("\n=== VERIFY POD  ===")
	ok, verr := myPod.Verify()
	if verr != nil {
		panic(verr)
	}
	fmt.Println("Verified valid POD:", ok)

	myPod.Proof.Signature = "0001020304050607080900010203040506070809000102030405060708090001"
	ok2, verr2 := myPod.Verify()
	fmt.Println("Verified invalid POD:", ok2, verr2)
}