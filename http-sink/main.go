package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// EmailAddress represents an email address with localpart and domain
type EmailAddress struct {
	Localpart string `json:"localpart"`
	Domain    string `json:"domain"`
}

// SubmissionOptions represents the options for HTTP submission
type SubmissionOptions struct {
	Sender     EmailAddress           `json:"sender"`
	Recipients []EmailAddress         `json:"recipients"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// SubmissionResponse represents the API response
type SubmissionResponse struct {
	Result      ResultInfo             `json:"result"`
	Transaction TransactionInfo        `json:"transaction"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type ResultInfo struct {
	Code     int      `json:"code"`
	Enhanced [3]int   `json:"enhanced"`
	Reason   []string `json:"reason"`
}

type TransactionInfo struct {
	ID string `json:"id"`
}

var (
	verbose bool
	port    int
	apiKey  string
)

func main() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging (prints full message body)")
	flag.IntVar(&port, "port", 80, "Port to listen on")
	flag.StringVar(&apiKey, "api-key", "", "Required API key for authentication (empty = no auth)")
	flag.Parse()

	http.HandleFunc("/v1/submission", submissionHandler)

	addr := fmt.Sprintf(":%d", port)
	log.Printf("HTTP sink server starting on %s\n", addr)
	if apiKey != "" {
		log.Printf("API key authentication enabled\n")
	} else {
		log.Printf("Warning: No API key required (use --api-key to enable authentication)\n")
	}
	log.Printf("Verbose mode: %v\n", verbose)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func submissionHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Check method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check API key if configured
	if apiKey != "" {
		providedKey := r.Header.Get("X-API-Key")
		if providedKey != apiKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			log.Printf("Authentication failed: invalid API key\n")
			return
		}
	}

	// Parse multipart form
	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32 MB max
		http.Error(w, fmt.Sprintf("Failed to parse multipart form: %v", err), http.StatusBadRequest)
		log.Printf("Error parsing form: %v\n", err)
		return
	}

	// Get options part
	optionsFile, _, err := r.FormFile("options")
	if err != nil {
		http.Error(w, fmt.Sprintf("Missing options field: %v", err), http.StatusBadRequest)
		log.Printf("Error reading options: %v\n", err)
		return
	}
	defer optionsFile.Close()

	optionsData, err := io.ReadAll(optionsFile)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read options: %v", err), http.StatusBadRequest)
		log.Printf("Error reading options data: %v\n", err)
		return
	}

	var options SubmissionOptions
	if err := json.Unmarshal(optionsData, &options); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse options JSON: %v", err), http.StatusBadRequest)
		log.Printf("Error parsing options JSON: %v\n", err)
		return
	}

	// Get rfc822 part
	rfc822File, _, err := r.FormFile("rfc822")
	if err != nil {
		http.Error(w, fmt.Sprintf("Missing rfc822 field: %v", err), http.StatusBadRequest)
		log.Printf("Error reading rfc822: %v\n", err)
		return
	}
	defer rfc822File.Close()

	messageBody, err := io.ReadAll(rfc822File)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read rfc822: %v", err), http.StatusBadRequest)
		log.Printf("Error reading rfc822 data: %v\n", err)
		return
	}

	// Log the submission
	sender := fmt.Sprintf("%s@%s", options.Sender.Localpart, options.Sender.Domain)
	log.Printf("Received message from: %s\n", sender)

	for _, recip := range options.Recipients {
		recipEmail := fmt.Sprintf("%s@%s", recip.Localpart, recip.Domain)
		log.Printf("  → Recipient: %s\n", recipEmail)
	}

	if len(options.Metadata) > 0 {
		log.Printf("  Metadata: %+v\n", options.Metadata)
	}

	if verbose {
		log.Printf("Message body (%d bytes):\n%s\n", len(messageBody), string(messageBody))
		log.Printf("Options JSON:\n%s\n", string(optionsData))
	} else {
		log.Printf("  Message size: %d bytes\n", len(messageBody))
	}

	// Generate transaction ID
	txID := uuid.New().String()

	// Build response
	response := SubmissionResponse{
		Result: ResultInfo{
			Code:     250,
			Enhanced: [3]int{2, 0, 0},
			Reason:   []string{fmt.Sprintf("Ok: queued as %s", txID)},
		},
		Transaction: TransactionInfo{
			ID: txID,
		},
		Metadata: options.Metadata,
	}

	// Check for pretty printing
	pretty := r.URL.Query().Get("pretty") == "true"

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(w)
	if pretty {
		encoder.SetIndent("", "  ")
	}

	if err := encoder.Encode(response); err != nil {
		log.Printf("Error encoding response: %v\n", err)
	}

	elapsed := time.Since(start)
	log.Printf("Request completed in %v (txid: %s)\n", elapsed, txID)
}
