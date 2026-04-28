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
	cfg     *config.Config
	path    string
	logType string
}

func New(cfg *config.Config, path string, logType string) *Tailer {
	return &Tailer{
		cfg:     cfg,
		path:    path,
		logType: logType,
	}
}

// Start runs the tailer loop. It is intended to be run in a goroutine.
func (t *Tailer) Start(handler func(string)) {
	for {
		err := t.tailLoop(handler)
		if err != nil {
			log.Printf("[%s] Tailer error: %v", t.logType, err)
		}
		log.Printf("[%s] Tailer stopped for %s. Restarting in 5s...", t.logType, t.path)
		time.Sleep(5 * time.Second)
	}
}

func (t *Tailer) tailLoop(handler func(string)) error {
	// 1. Setup SeekInfo - always from end for now to avoid massive backlogs
	seek := &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd}

	tailConfig := tail.Config{
		ReOpen:    true,
		Follow:    true,
		MustExist: true,
		Poll:      true,
		Location:  seek,
	}

	// Verify file existence before starting
	if _, err := os.Stat(t.path); os.IsNotExist(err) {
		return fmt.Errorf("file %s does not exist", t.path)
	}

	tf, err := tail.TailFile(t.path, tailConfig)
	if err != nil {
		return err
	}

	// 2. Heartbeat Ticker
	heartbeat := time.NewTicker(5 * time.Minute) // Reduced logging frequency
	defer heartbeat.Stop()

	// 3. Line processing loop
	log.Printf("[%s] Tailer active: %s", t.logType, t.path)

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
			log.Printf("[%s] tailer alive: %s", t.logType, t.path)
		}
	}
}
