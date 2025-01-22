package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/0xPARC/parcnet/go/pod"
)

var (
	// TODO: Eventually move to DB / Redis
	hitCount   int64
	privateKey = os.Getenv("PRIVATE_KEY")
)

func handleRoot(w http.ResponseWriter, r *http.Request) {
	// To prevent fallback to the root from requests like /favicon.ico
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, r.Method+" not allowed", http.StatusMethodNotAllowed)
		return
	}

	newCount := atomic.AddInt64(&hitCount, 1)
	entries := map[string]interface{}{
		"message": map[string]interface{}{
			"string": fmt.Sprintf("Welcome to PARCNET, visitor #%d", newCount),
		},
		"visitorCount": map[string]interface{}{
			"int": newCount,
		},
	}

	startTime := time.Now()
	_, jsonPod, err := pod.CreatePod(privateKey, entries)
	elapsed := time.Since(startTime)
	log.Printf("[%s /] pod.CreatePod: %s", r.Method, elapsed)

	if err != nil {
		http.Error(w, "Error creating POD: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(jsonPod))
}

type signRequest struct {
	Entries map[string]interface{} `json:"entries"`
}

func handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, r.Method+" not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req signRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	startTime := time.Now()
	_, jsonPod, err := pod.CreatePod(privateKey, req.Entries)
	elapsed := time.Since(startTime)
	log.Printf("[%s /sign] pod.CreatePod: %s", r.Method, elapsed)
	if err != nil {
		http.Error(w, "Error creating POD: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(jsonPod))
}

type verifyResponse struct {
	IsValid bool   `json:"isValid"`
	Error   string `json:"error,omitempty"`
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, r.Method+" not allowed", http.StatusMethodNotAllowed)
		return
	}

	var p pod.Pod
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		response := verifyResponse{
			IsValid: false,
			Error:   "Invalid POD JSON: " + err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	startTime := time.Now()
	ok, verr := p.Verify()
	elapsed := time.Since(startTime)
	log.Printf("[%s /verify] pod.Verify: %s", r.Method, elapsed)

	response := verifyResponse{
		IsValid: ok && verr == nil,
	}

	if verr != nil {
		response.Error = verr.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func main() {
	if privateKey == "" {
		log.Fatal("Missing PRIVATE_KEY environment variable.")
	}

	log.Println("Loaded PRIVATE_KEY...")
	log.Println("Starting server on port 8080")

	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/sign", handleSign)
	http.HandleFunc("/verify", handleVerify)

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("ListenAndServe Error: ", err)
	}
}
