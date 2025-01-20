package main

import (
	"fmt"
	// "os"

	"github.com/0xPARC/parcnet/go/pod"
)

func main() {
	// filePath := os.Getenv("POD_EXEC_PATH")
	// if filePath == "" {
	// 	filePath := "./pod_cli"
	// }
	fmt.Println("=== CREATE POD  ===")
	myPod, jsonPod, err := pod.CreatePod(
		"0001020304050607080900010203040506070809000102030405060708090001",
		map[string]interface{}{
			"created_by": map[string]interface{}{"string": "Golang"},
			"year":       map[string]interface{}{"int": 2025},
		},
	)
	if err != nil {
		fmt.Println("Error creating POD:", err)
	} else {
		fmt.Println("Pod:", myPod)
		fmt.Println("JSONPOD:", jsonPod)
	}

	fmt.Println("\n=== VERIFY POD  ===")
	ok, verr := myPod.Verify()
	if verr != nil {
		fmt.Println("Error verifying valid POD:", verr)
	} else {
		fmt.Println("Verified valid POD:", ok)
	}

	myPod.Signature = "0001020304050607080900010203040506070809000102030405060708090001"
	ok2, verr2 := myPod.Verify()
	if verr2 != nil {
		fmt.Println("Error verifying invalid POD:", verr2)
	} else {
		fmt.Println("Verified invalid POD:", ok2)
	}
}
