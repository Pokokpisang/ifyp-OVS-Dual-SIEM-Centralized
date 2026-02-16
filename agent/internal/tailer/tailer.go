package tailer

import (
	"agent/internal/config"
	"agent/internal/model"
	"fmt"
	"github.com/hpcloud/tail"
	"os"
	"time"
)

type Tailer struct {
	cfg   *config.Config
	lines chan model.LogEvent
}

func New(cfg *config.Config) *Tailer {
	return &Tailer{
		cfg:   cfg,
		lines: make(chan model.LogEvent),
	}
}

func (t *Tailer) Start() (<-chan model.LogEvent, error) {
	// Create file if it doesn't exist for test purposes, or fail if strictly read mode
	// But usually log file exists. If we are testing locally, maybe we need to create it.
	if _, err := os.Stat(t.cfg.LogPath); os.IsNotExist(err) {
		fmt.Printf("Log file %s does not exist, waiting for it...\n", t.cfg.LogPath)
	}

	tailConfig := tail.Config{
		ReOpen:    true,
		Follow:    true,
		MustExist: false,
		Poll:      true, // Polling is often safer on mounted volumes/Docker
	}

	tailFile, err := tail.TailFile(t.cfg.LogPath, tailConfig)
	if err != nil {
		return nil, err
	}

	go func() {
		host, _ := os.Hostname()
		for line := range tailFile.Lines {
			event := model.LogEvent{
				Timestamp: time.Now().UTC(),
				Host:      host,
				LogType:   t.cfg.LogType,
				FilePath:  t.cfg.LogPath,
				Message:   line.Text,
			}
			t.lines <- event
		}
	}()

	return t.lines, nil
}
