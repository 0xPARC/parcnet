package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/0xPARC/parcnet/go/pod"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

var (
	privateKey = os.Getenv("PRIVATE_KEY")
	rdb        *redis.Client
	ctx        = context.Background()
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

	podInstance, err := createVisitorPOD()
	if err != nil {
		http.Error(w, "Error creating POD: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	jsonPod, err := json.Marshal(podInstance)
	if err != nil {
		http.Error(w, "Error marshalling POD: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(jsonPod)
}

type signRequest struct {
	Entries pod.PodEntries `json:"entries"`
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

	podInstance, err := pod.CreatePod(privateKey, req.Entries)
	if err != nil {
		http.Error(w, "Error creating POD: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	jsonPod, err := json.Marshal(podInstance)
	if err != nil {
		http.Error(w, "Error marshalling POD: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(jsonPod)
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
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	ok, verr := p.Verify()

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

// If GET, we sign a visitor POD and redirect to add the POD via Zupass
// If POST, we sign the given entries and return the given Zupass URL
func handleZupass(w http.ResponseWriter, r *http.Request) {
	var podInstance *pod.Pod
	var err error

	switch r.Method {
	case http.MethodPost:
		var req signRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
			return
		}

		podInstance, err = pod.CreatePod(privateKey, req.Entries)
		if err != nil {
			http.Error(w, "Error creating POD: "+err.Error(), http.StatusInternalServerError)
			return
		}

	case http.MethodGet:
		podInstance, err = createVisitorPOD()
		if err != nil {
			http.Error(w, "Error creating POD: "+err.Error(), http.StatusInternalServerError)
			return
		}

	default:
		http.Error(w, r.Method+" not allowed", http.StatusMethodNotAllowed)
		return
	}

	serialized, err := SerializePODPCD(uuid.New().String(), *podInstance)
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

	if r.Method == http.MethodPost {
		response := map[string]string{
			"zupassUrl": zupassUrl,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	} else if r.Method == http.MethodGet {
		http.Redirect(w, r, zupassUrl, http.StatusSeeOther)
	}
}

func createVisitorPOD() (*pod.Pod, error) {
	newCount, err := rdb.Incr(ctx, "visitorCount").Result()
	if err != nil {
		log.Printf("Error incrementing visitorCount in Redis: %v", err)
		return nil, err
	}

	jsonData := fmt.Sprintf(`{
		"message": {"string": "Welcome to PARCNET, visitor #%d"},
		"visitorCount": {"int": %d}
	}`, newCount, newCount)

	var entries pod.PodEntries
	if err := json.Unmarshal([]byte(jsonData), &entries); err != nil {
		log.Printf("Error unmarshalling POD entries: %v", err)
		return nil, err
	}

	podInstance, err := pod.CreatePod(privateKey, entries)

	if err != nil {
		log.Printf("Error creating POD: %v", err)
		return nil, err
	}

	return podInstance, nil
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
	log.Println("Loaded PRIVATE_KEY...")

	initRedis()

	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/sign", handleSign)
	http.HandleFunc("/verify", handleVerify)
	http.HandleFunc("/zupass", handleZupass)

	log.Println("Starting server on port 8080")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("ListenAndServe Error: ", err)
	}
}
