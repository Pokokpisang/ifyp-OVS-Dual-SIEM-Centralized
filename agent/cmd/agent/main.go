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
	fmt.Printf("Server URL    : %s\n", cfg.ServerURL)
	fmt.Printf("Primary Log   : %s (%s)\n", cfg.LogPath, cfg.LogType)
	fmt.Printf("Auditd Log    : %s\n", cfg.AuditdPath)
	fmt.Printf("Tail Mode     : follow=true reopen=true poll=true start_from_end=%v\n", cfg.TailFromEnd)
	fmt.Println("========================================")

	q := queue.New("agent_queue.jsonl")
	snd := sender.New(cfg, q)

	rm := rules.New(cfg.ServerURL + "/api/agent/rules")
	rm.StartPoll(5 * time.Minute)

	// Try to drain queue on startup
	snd.DrainQueue()

	host, _ := os.Hostname()

	// 1. Start Primary Log Tailer
	primaryTailer := tailer.New(cfg)
	go primaryTailer.Start(func(msg string) {
		event := model.LogEvent{
			Timestamp: time.Now().UTC(),
			Host:      host,
			LogType:   cfg.LogType,
			FilePath:  cfg.LogPath,
			Message:   msg,
		}
		if matched, rID, rev := rm.Match(event.Message); matched {
			event.LocalFlag = true
			event.AgentRuleID = rID
			event.LocalRuleVersion = rev
		}
		// In a real agent we might want more quiet logs, but for FYP we keep it visible
		// fmt.Printf("[%s] Sending: %s...\n", cfg.LogType, event.Message[:min(len(event.Message), 30)])
		if err := snd.Send(event); err != nil {
			log.Printf("[%s] Error sending: %v", cfg.LogType, err)
		}
	})

	// 2. Start Auditd Tailer
	if cfg.AuditdPath != "" {
		auditCfg := *cfg
		auditCfg.LogPath = cfg.AuditdPath
		auditCfg.LogType = "auditd"

		auditTailer := tailer.New(&auditCfg)
		go auditTailer.Start(func(msg string) {
			event := model.LogEvent{
				Timestamp: time.Now().UTC(),
				Host:      host,
				LogType:   "auditd",
				FilePath:  cfg.AuditdPath,
				Message:   msg,
			}
			if matched, rID, rev := rm.Match(event.Message); matched {
				event.LocalFlag = true
				event.AgentRuleID = rID
				event.LocalRuleVersion = rev
			}
			if err := snd.Send(event); err != nil {
				log.Printf("[auditd] Error sending: %v", err)
			}
		})
	}

	// 3. Start Metrics Collector
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
