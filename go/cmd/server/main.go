package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/0xPARC/parcnet/go/pod"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

// Global variables
var (
	privateKey = os.Getenv("PRIVATE_KEY")

	// Redis client and context
	rdb *redis.Client
	ctx = context.Background()
)

// handleRoot increments the Redis-based counter and responds with a POD containing the visitor count.
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

	// INCR the counter in Redis
	newCount, err := rdb.Incr(ctx, "visitorCount").Result()
	if err != nil {
		log.Printf("Error incrementing visitorCount in Redis: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

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
		log.Printf("[%s /] pod.CreatePod: %s", r.Method, err)
		http.Error(w, "Error creating POD: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(jsonPod))
}

// signRequest struct for /sign endpoint
type signRequest struct {
	Entries map[string]interface{} `json:"entries"`
}

// handleSign creates a POD from user-supplied entries and returns it.
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
	_, _ = w.Write([]byte(jsonPod))
}

type verifyResponse struct {
	IsValid bool   `json:"isValid"`
	Error   string `json:"error,omitempty"`
}

// handleVerify checks a POD’s validity.
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
		_ = json.NewEncoder(w).Encode(response)
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
	_ = json.NewEncoder(w).Encode(response)
}

func handleZupassSignAndAdd(w http.ResponseWriter, r *http.Request) {
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
	pod, jsonPod, err := pod.CreatePod(privateKey, req.Entries)
	if err != nil {
		http.Error(w, "Error creating POD: "+err.Error(), http.StatusInternalServerError)
		return
	}
	elapsed := time.Since(startTime)
	log.Printf("[%s /zupass/add] pod.CreatePod: %s", r.Method, elapsed)

	fmt.Println("jsonPod: ", jsonPod)

	serialized, err := SerializePODPCD(uuid.New().String(), *pod)
	if err != nil {
		http.Error(w, "Error serializing PODPCD: "+err.Error(), http.StatusInternalServerError)
		return
	}

	folder := "Go PODs"
	zupassUrl, err := createZupassAddRequestUrl("https://zupass.org", "https://zupass.org/#/popup", *serialized, &folder, false, nil)
	if err != nil {
		http.Error(w, "Error creating Zupass URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"zupassUrl": zupassUrl,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func initRedis() {
    redisURL := os.Getenv("REDIS_URL")

    if redisURL == "" {
        redisURL = "redis://127.0.0.1:6379"
    }

    opts, err := redis.ParseURL(redisURL)
    if err != nil {
        log.Fatalf("Failed to parse REDIS_URL: %v", err)
    }

    rdb = redis.NewClient(opts)

    if err := rdb.Ping(ctx).Err(); err != nil {
        log.Fatalf("Could not connect to Redis: %v", err)
    }

    log.Printf("Connected to Redis at %s", redisURL)
}

func main() {
	_ = godotenv.Load()

	if privateKey == "" {
		log.Fatal("Missing PRIVATE_KEY environment variable.")
	}

	// Initialize PARCNET pod
	if err := pod.Init(); err != nil {
		log.Fatal("Failed to initialize pod: ", err)
	}

	initRedis();

	// Test connection quickly (optional, but good practice)
	if _, err := rdb.Ping(ctx).Result(); err != nil {
		log.Fatalf("Could not connect to Redis: %v", err)
	}

	log.Println("Loaded PRIVATE_KEY...")
	log.Println("Initialized pod service...")
	log.Println("Connected to Redis...")
	log.Println("Starting server on port 8080")

	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/sign", handleSign)
	http.HandleFunc("/verify", handleVerify)
	http.HandleFunc("/zupass", handleZupassSignAndAdd)

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("ListenAndServe Error: ", err)
	}
}