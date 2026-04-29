package main

import (
	"agent/internal/collector"
	"agent/internal/config"
	"agent/internal/model"
	"agent/internal/queue"
	"agent/internal/rules"
	"agent/internal/sender"
	"agent/internal/tailer"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg := config.Load()
	
	fmt.Println("========================================")
	fmt.Println("       FYP SIEM AGENT STARTED")
	fmt.Println("========================================")
	fmt.Printf("Detected OS   : %s\n", cfg.DetectedOS)
	fmt.Printf("Agent Name    : %s\n", cfg.AgentName)
	fmt.Printf("Server URL    : %s\n", cfg.ServerURL)
	fmt.Printf("Logs Enabled  : %v\n", cfg.EnableLogs)
	fmt.Printf("Metrics Enabled: %v\n", cfg.EnableMetrics)
	fmt.Printf("FIM Enabled    : %v\n", cfg.EnableFIM)
	fmt.Println("========================================")

	if cfg.EnableLogs {
		fmt.Println("Using Log Paths:")
		fmt.Printf("  - Auth   : %s\n", cfg.LogPaths.Auth)
		fmt.Printf("  - Syslog : %s\n", cfg.LogPaths.Syslog)
		fmt.Printf("  - Auditd : %s\n", cfg.LogPaths.Auditd)
	}

	if cfg.EnableFIM {
		fmt.Println("[FIM] Implementation pending. Watcher skipped.")
	}

	q := queue.New("agent_queue.jsonl")
	snd := sender.New(cfg, q)

	// Start Heartbeat Loop (60s)
	go func() {
		fmt.Println("Starting heartbeat loop (60s interval)...")
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		// Send initial heartbeat
		_ = snd.SendHeartbeat()
		for range ticker.C {
			if err := snd.SendHeartbeat(); err != nil {
				log.Printf("[heartbeat] Error: %v", err)
			}
		}
	}()

	rm := rules.New(cfg.ServerURL + "/api/agent/rules")
	rm.StartPoll(5 * time.Minute)

	// Try to drain queue on startup
	snd.DrainQueue()

	host, _ := os.Hostname()

	// 1. Start Log Tailers if enabled
	if cfg.EnableLogs {
		// Define tailer pairs: (path, type)
		tails := []struct {
			path    string
			logType string
		}{
			{cfg.LogPaths.Auth, "auth"},
			{cfg.LogPaths.Syslog, "syslog"},
			{cfg.LogPaths.Auditd, "auditd"},
		}

		for _, t := range tails {
			if t.path == "" {
				continue
			}

			// Check if file exists before starting
			if _, err := os.Stat(t.path); os.IsNotExist(err) {
				fmt.Printf("[%s] Warning: Log file not found at %s. Skipping.\n", t.logType, t.path)
				continue
			}

			path := t.path
			lType := t.logType
			
			// Start tailer in goroutine
			go func(p string, lt string) {
				fmt.Printf("[%s] Starting tailer for %s\n", lt, p)
				
				t := tailer.New(cfg, p, lt) 
				t.Start(func(msg string) {
					event := model.LogEvent{
						Timestamp: time.Now().UTC(),
						Host:      host,
						LogType:   lt,
						FilePath:  p,
						Message:   msg,
					}
					if matched, rID, rev := rm.Match(event.Message); matched {
						event.LocalFlag = true
						event.AgentRuleID = rID
						event.LocalRuleVersion = rev
					}
					if err := snd.Send(event); err != nil {
						log.Printf("[%s] Error sending: %v", lt, err)
					}
				})
			}(path, lType)
		}
	}

	// 2. Start Metrics Collector if enabled
	if cfg.EnableMetrics {
		fmt.Println("Starting metrics collector (5s interval)...")
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				m, err := collector.GetMetrics(host)
				if err != nil {
					log.Printf("Metrics error: %v", err)
					continue
				}
				if err := snd.SendMetric(m); err != nil {
					log.Printf("Metrics send error: %v", err)
				}
			}
		}()
	}

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	fmt.Println("\nShutting down agent...")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
