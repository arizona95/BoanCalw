package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-whitelist-proxy/internal/cache"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

func main() {
	store := cache.NewStore(3)
	llmURL := env("BOAN_LLM_URL", "http://boan-security-llm:8080")
	listen := env("BOAN_LISTEN", ":8090")

	go evictionLoop(store)

	mux := http.NewServeMux()

	mux.HandleFunc("/v1/prompt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Prompt string `json:"prompt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sentences := splitSentences(req.Prompt)

		var missed []string
		var cached []string
		for _, s := range sentences {
			if resp, ok := store.Get(s); ok {
				cached = append(cached, resp)
			} else {
				missed = append(missed, s)
			}
		}

		response := strings.Join(cached, " ")
		if len(missed) > 0 {
			llmResp := forwardToLLM(llmURL, strings.Join(missed, " "))
			for _, s := range missed {
				store.AddCandidate(s, llmResp)
			}
			if response != "" {
				response += " "
			}
			response += llmResp
		}

		wl, cands := store.Stats()
		w.Header().Set("X-Boan-Cache-Whitelist", fmt.Sprintf("%d", wl))
		w.Header().Set("X-Boan-Cache-Candidates", fmt.Sprintf("%d", cands))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"response": strings.TrimSpace(response)})
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		wl, cands := store.Stats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"whitelisted": wl, "candidates": cands})
	})

	log.Printf("boan-whitelist-proxy listening on %s", listen)
	log.Fatal(http.ListenAndServe(listen, mux))
}

func splitSentences(text string) []string {
	normalized := strings.NewReplacer("!", ".", "?", ".", "\n", ".").Replace(text)
	var out []string
	for _, s := range strings.Split(normalized, ".") {
		s = strings.TrimSpace(s)
		if len(s) > 5 {
			out = append(out, s)
		}
	}
	if len(out) == 0 && len(strings.TrimSpace(text)) > 0 {
		out = append(out, strings.TrimSpace(text))
	}
	return out
}

func forwardToLLM(url, prompt string) string {
	body, _ := json.Marshal(map[string]any{
		"model": "security",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})
	resp, err := httpClient.Post(url+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("llm forward error: %v", err)
		return ""
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &result); err == nil && len(result.Choices) > 0 {
		return result.Choices[0].Message.Content
	}
	return string(raw)
}

func evictionLoop(store *cache.Store) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		n := store.Evict()
		if n > 0 {
			log.Printf("evicted %d entries", n)
		}
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
