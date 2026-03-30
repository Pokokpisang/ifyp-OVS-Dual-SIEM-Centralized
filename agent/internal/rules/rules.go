package rules

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Rule struct {
	ID       int      `json:"id"`
	Name     string   `json:"name"`
	Version  int      `json:"version"`
	Keywords []string `json:"keywords"`
	Patterns []struct {
		Name  string   `json:"name"`
		AllOf []string `json:"all_of"`
	} `json:"patterns"`
}

type RulesManager struct {
	apiQueryURL string
	mu          sync.RWMutex
	rules       []Rule
}

func New(apiQueryURL string) *RulesManager {
	return &RulesManager{
		apiQueryURL: apiQueryURL,
		rules:       []Rule{},
	}
}

func (m *RulesManager) StartPoll(interval time.Duration) {
	m.FetchRules() // Initial fetch
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			m.FetchRules()
		}
	}()
}

func (m *RulesManager) FetchRules() {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(m.apiQueryURL)
	if err != nil {
		fmt.Printf("Failed to fetch agent rules: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Agent rules endpoint returned %d\n", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Failed to read agent rules body: %v\n", err)
		return
	}

	var fetchedRules []Rule
	if err := json.Unmarshal(body, &fetchedRules); err != nil {
		fmt.Printf("Failed to parse agent rules: %v\n", err)
		return
	}

	m.mu.Lock()
	m.rules = fetchedRules
	m.mu.Unlock()
	// fmt.Printf("Successfully synced %d agent rules.\n", len(fetchedRules))
}

func (m *RulesManager) Match(message string) (matched bool, ruleID *int, version *int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	msgLower := strings.ToLower(message)

	for _, rule := range m.rules {
		// Keyword match (Any of)
		for _, kw := range rule.Keywords {
			if strings.Contains(msgLower, strings.ToLower(kw)) {
				id, v := rule.ID, rule.Version
				return true, &id, &v
			}
		}

		// Pattern match (All of)
		for _, pattern := range rule.Patterns {
			allFound := true
			for _, part := range pattern.AllOf {
				if !strings.Contains(msgLower, strings.ToLower(part)) {
					allFound = false
					break
				}
			}
			if allFound && len(pattern.AllOf) > 0 {
				id, v := rule.ID, rule.Version
				return true, &id, &v
			}
		}
	}

	return false, nil, nil
}
