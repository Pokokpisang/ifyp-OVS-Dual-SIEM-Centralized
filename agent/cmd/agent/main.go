package main

import (
	"agent/internal/collector"
	"agent/internal/config"
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
	fmt.Printf("Starting Agent... URL=%s Log=%s\n", cfg.ServerURL, cfg.LogPath)

	q := queue.New("agent_queue.jsonl")
	snd := sender.New(cfg, q)

	rm := rules.New(cfg.ServerURL + "/api/agent/rules")
	rm.StartPoll(5 * time.Minute)

	// Try to drain queue on startup
	snd.DrainQueue()

	// 1a. Start Primary Log Tailer
	tl := tailer.New(cfg)
	// Hack: Temporarily overwrite cfg for the first tailer if needed, but here we just tail LogPath
	events, err := tl.Start()
	if err != nil {
		log.Fatalf("Failed to start tailer: %v", err)
	}

	// 1b. Start Auditd Tailer (if file exists or configured)
	// We create a temp config for the second tailer to reuse the struct
	if cfg.AuditdPath != "" {
		auditCfg := *cfg // copy
		auditCfg.LogPath = cfg.AuditdPath
		auditCfg.LogType = "auditd"
		
		auditTailer := tailer.New(&auditCfg)
		auditEvents, err := auditTailer.Start()
		if err == nil {
			fmt.Printf("Successfully started Auditd Tailer: %s\n", cfg.AuditdPath)
			// Launch separate consumer for simplicity
			go func() {
				for event := range auditEvents {
					if matched, rID, rev := rm.Match(event.Message); matched {
						event.LocalFlag = true
						event.AgentRuleID = rID
						event.LocalRuleVersion = rev
					}
					fmt.Printf("Sending AUDIT log: %s...\n", event.Message[:min(len(event.Message), 20)])
					if err := snd.Send(event); err != nil {
						fmt.Printf("Error sending audit log: %v\n", err)
					}
				}
			}()
		} else {
			fmt.Printf("Warning: Auditd tailer could not start (path: %s). Error: %v\n", cfg.AuditdPath, err)
			fmt.Println("This is expected if Auditd is not installed or configured on this system.")
		}
	}
	
	// Main Loop for Primary Logs
	go func() {
		for event := range events {
			if matched, rID, rev := rm.Match(event.Message); matched {
				event.LocalFlag = true
				event.AgentRuleID = rID
				event.LocalRuleVersion = rev
			}
			fmt.Printf("Sending log: %s...\n", event.Message[:min(len(event.Message), 20)])
			if err := snd.Send(event); err != nil {
				fmt.Println("Error sending log:", err)
			}
		}
	}()

	// 2. Start Metrics Collector (Ticker)
	go func() {
		host, _ := os.Hostname()
		ticker := time.NewTicker(5 * time.Second) // Fast 5s updates for demo
		defer ticker.Stop()
		
		for range ticker.C {
			m, err := collector.GetMetrics(host)
			if err != nil {
				fmt.Println("Error collecting metrics:", err)
				continue
			}
			fmt.Printf("Sending metrics: CPU=%.1f%% RAM=%.1f%%\n", m.CPUPercent, m.RAMPercent)
			if err := snd.SendMetric(m); err != nil {
				fmt.Println("Error sending metric:", err.Error())
			}
		}
	}()

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	fmt.Println("Shutting down agent...")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
