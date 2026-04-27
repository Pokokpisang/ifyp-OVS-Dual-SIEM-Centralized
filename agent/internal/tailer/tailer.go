package tailer

import (
	"agent/internal/config"
	"fmt"
	"github.com/hpcloud/tail"
	"io"
	"log"
	"os"
	"time"
)

type Tailer struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Tailer {
	return &Tailer{
		cfg: cfg,
	}
}

// Start runs the tailer loop. It is intended to be run in a goroutine.
func (t *Tailer) Start(handler func(string)) {
	for {
		err := t.tailLoop(handler)
		if err != nil {
			log.Printf("[%s] Tailer error: %v", t.cfg.LogType, err)
		}
		log.Printf("[%s] Tailer stopped for %s. Restarting in 5s...", t.cfg.LogType, t.cfg.LogPath)
		time.Sleep(5 * time.Second)
	}
}

func (t *Tailer) tailLoop(handler func(string)) error {
	// 1. Setup SeekInfo based on config
	var seek *tail.SeekInfo
	if t.cfg.TailFromEnd {
		seek = &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd}
	}

	tailConfig := tail.Config{
		ReOpen:    true,
		Follow:    true,
		MustExist: true,
		Poll:      true,
		Location:  seek,
	}

	// Verify file existence before starting
	if _, err := os.Stat(t.cfg.LogPath); os.IsNotExist(err) {
		return fmt.Errorf("file %s does not exist", t.cfg.LogPath)
	}

	tf, err := tail.TailFile(t.cfg.LogPath, tailConfig)
	if err != nil {
		return err
	}

	// 2. Heartbeat Ticker
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	// 3. Line processing loop
	log.Printf("[%s] Tailer active: %s (start_from_end=%v)", t.cfg.LogType, t.cfg.LogPath, t.cfg.TailFromEnd)

	for {
		select {
		case line, ok := <-tf.Lines:
			if !ok {
				return fmt.Errorf("line channel closed")
			}
			if line.Err != nil {
				return line.Err
			}
			handler(line.Text)

		case <-heartbeat.C:
			log.Printf("[%s] tailer alive: %s", t.cfg.LogType, t.cfg.LogPath)
		}
	}
}
