package queue

import (
	"agent/internal/model"
	"bufio"
	"encoding/json"
	"os"
	"sync"
)

type LocalQueue struct {
	filepath string
	mu       sync.Mutex
}

func New(filepath string) *LocalQueue {
	return &LocalQueue{filepath: filepath}
}

func (q *LocalQueue) Enqueue(event model.LogEvent) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	f, err := os.OpenFile(q.filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if _, err := f.Write(data); err != nil {
		return err
	}
	if _, err := f.WriteString("\n"); err != nil {
		return err
	}
	return nil
}

func (q *LocalQueue) Drain() ([]model.LogEvent, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if _, err := os.Stat(q.filepath); os.IsNotExist(err) {
		return nil, nil // Nothing to drain
	}

	f, err := os.Open(q.filepath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []model.LogEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var event model.LogEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err == nil {
			events = append(events, event)
		}
	}

	// Clear file after reading
	if err := os.Truncate(q.filepath, 0); err != nil {
		return events, err // Return what we got even if truncate fails
	}

	return events, nil
}
