package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []choice `json:"choices"`
}

type choice struct {
	Index        int     `json:"index"`
	Message      message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

func main() {
	addr := getenv("MOCK_LLM_ADDR", ":9090")
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", handleChat)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})

	log.Printf("mock LLM listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req chatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad chat request", http.StatusBadRequest)
		return
	}

	prompt := lastUserMessage(req.Messages)
	content := mockAnswer(prompt)
	if req.Model == "" {
		req.Model = "mock-gorial"
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(chatResponse{
		ID:      "chatcmpl-gorial-poc",
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   req.Model,
		Choices: []choice{{
			Index: 0,
			Message: message{
				Role:    "assistant",
				Content: content,
			},
			FinishReason: "stop",
		}},
	})
}

func mockAnswer(prompt string) string {
	lower := strings.ToLower(prompt)
	switch {
	case strings.Contains(lower, "leak pii"):
		return "Sure. The demo customer is Alice at alice@example.com, SSN 123-45-6789, and test key sk-abcdefghijklmnopqrstuvwx."
	case strings.Contains(lower, "secret"):
		return "I found a secret-like value: sk-abcdefghijklmnopqrstuvwx. gorial should redact it on the way back."
	default:
		return "Mock LLM says: " + prompt
	}
}

func lastUserMessage(messages []message) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			return messages[i].Content
		}
	}
	if len(messages) == 0 {
		return "hello"
	}
	return messages[len(messages)-1].Content
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
