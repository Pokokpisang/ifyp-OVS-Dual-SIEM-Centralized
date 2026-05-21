// Package setup provides one-time host bootstrap tasks that the agent
// performs at startup when explicitly enabled by the operator.
package setup

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"
)

const (
	auditRulesPath = "/etc/audit/rules.d/siem-detections.rules"
	auditLogPath   = "/var/log/audit/audit.log"
)

// rulesContent is the canonical SIEM detection ruleset written to the host.
const rulesContent = `## OVS SIEM agent — auto-generated, do not edit manually

# T1543.002 — Systemd service persistence
-w /etc/systemd/system/      -p wa -k t1543_persistence
-w /usr/lib/systemd/system/  -p wa -k t1543_persistence
-w /lib/systemd/system/      -p wa -k t1543_persistence

# T1059 — Command and Scripting Interpreter (process execution monitoring)
-a always,exit -F arch=b64 -S execve -k T1059
-a always,exit -F arch=b32 -S execve -k T1059
`

// EnsureAuditd ensures auditd is installed, running, and configured with
// SIEM detection rules.  Every step is non-fatal — the agent continues
// regardless of outcome.  Must be called before log tailers are started.
func EnsureAuditd(logger *log.Logger) error {
	if os.Getuid() != 0 {
		logger.Println("[setup] warning: not running as root — auditd setup skipped")
		return fmt.Errorf("not running as root")
	}

	// 1. Check if auditctl is already installed; install if missing.
	if _, err := exec.LookPath("auditctl"); err != nil {
		logger.Println("[setup] auditctl not found — attempting installation")
		if err := installAuditd(logger); err != nil {
			logger.Printf("[setup] auditd install warning: %v", err)
		}
	} else {
		logger.Println("[setup] auditd already installed")
	}

	// 2. Enable and start the auditd service.
	runCmd(logger, 5*time.Second, "systemctl", "enable", "auditd")
	runCmd(logger, 10*time.Second, "systemctl", "start", "auditd")

	// 3. Write SIEM detection rules if the file is missing or outdated.
	if err := writeRules(logger); err != nil {
		logger.Printf("[setup] rules write warning: %v", err)
	}

	// 4. Reload rules into the running kernel.
	if err := runCmd(logger, 5*time.Second, "augenrules", "--load"); err != nil {
		// augenrules not available on older distros; fall back to direct load.
		runCmd(logger, 5*time.Second, "auditctl", "-R", auditRulesPath)
	}

	// 5. Wait up to 10 s for the audit log file to appear.
	waitForAuditLog(logger)

	return nil
}

// installAuditd detects the package manager and installs the auditd package.
func installAuditd(logger *log.Logger) error {
	pm := detectPkgManager()
	var name string
	var args []string
	switch pm {
	case "apt-get":
		name = "apt-get"
		args = []string{"install", "-y", "auditd", "audispd-plugins"}
	case "dnf":
		name = "dnf"
		args = []string{"install", "-y", "audit"}
	case "yum":
		name = "yum"
		args = []string{"install", "-y", "audit"}
	default:
		return fmt.Errorf("no supported package manager found — install auditd manually")
	}
	logger.Printf("[setup] installing auditd via %s…", pm)
	return runCmd(logger, 120*time.Second, name, args...)
}

// detectPkgManager returns the name of the first available package manager.
func detectPkgManager() string {
	for _, pm := range []string{"apt-get", "dnf", "yum"} {
		if _, err := exec.LookPath(pm); err == nil {
			return pm
		}
	}
	return ""
}

// writeRules writes rulesContent to auditRulesPath only when the content differs,
// avoiding unnecessary auditd reloads on subsequent agent restarts.
func writeRules(logger *log.Logger) error {
	existing, err := os.ReadFile(auditRulesPath)
	if err == nil && string(existing) == rulesContent {
		logger.Println("[setup] audit rules file is already up to date")
		return nil
	}
	logger.Printf("[setup] writing audit rules to %s", auditRulesPath)
	if err := os.MkdirAll("/etc/audit/rules.d", 0755); err != nil {
		return fmt.Errorf("mkdir /etc/audit/rules.d: %w", err)
	}
	return os.WriteFile(auditRulesPath, []byte(rulesContent), 0644)
}

// waitForAuditLog polls for audit.log existence for up to 10 s.
// The tailer has its own retry loop, so a timeout here is non-fatal.
func waitForAuditLog(logger *log.Logger) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(auditLogPath); err == nil {
			logger.Printf("[setup] %s is ready", auditLogPath)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	logger.Printf("[setup] timeout waiting for %s — tailer will retry when available", auditLogPath)
}

// runCmd runs a command with a context timeout.  Stdout and stderr are
// logged on failure.  Returns nil on success.
func runCmd(logger *log.Logger, timeout time.Duration, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		logger.Printf("[setup] %s %v → %v\n%s", name, args, err, out.String())
		return err
	}
	logger.Printf("[setup] %s %v → ok", name, args)
	return nil
}
