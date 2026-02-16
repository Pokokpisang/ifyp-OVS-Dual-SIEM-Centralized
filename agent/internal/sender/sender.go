package sender

import (
	"agent/internal/collector"
	"agent/internal/config"
	"agent/internal/model"
	"agent/internal/queue"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Sender struct {
	cfg    *config.Config
	client *http.Client
	queue  *queue.LocalQueue
}

func New(cfg *config.Config, q *queue.LocalQueue) *Sender {
	return &Sender{
		cfg:   cfg,
		queue: q,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (s *Sender) Send(event model.LogEvent) error {
	return s.post("/ingest/log", event)
}

func (s *Sender) SendMetric(metric collector.Metrics) error {
	return s.post("/api/metrics", metric)
}

func (s *Sender) post(endpoint string, data interface{}) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}

	resp, err := s.client.Post(s.cfg.ServerURL+endpoint, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		fmt.Printf("Failed to send to %s: %v\n", endpoint, err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

func (s *Sender) DrainQueue() {
	// Simple drain implementation for Logs only for now to keep it simple
	// In production, we'd queue metrics too, but logs are more critical.
	events, err := s.queue.Drain()
	if err != nil {
		fmt.Printf("Failed to drain queue: %v\n", err)
		return
	}
	if len(events) > 0 {
		fmt.Printf("Resending %d queued events...\n", len(events))
		for _, event := range events {
			s.Send(event)
		}
	}
}
