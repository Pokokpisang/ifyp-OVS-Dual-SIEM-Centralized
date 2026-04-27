package config

import (
	"os"
)

type Config struct {
	ServerURL  string
	LogPath    string
	LogType    string
	AuditdPath string
	TailFromEnd bool
}

func Load() *Config {
	return &Config{
		ServerURL:  getEnv("AGENT_SERVER_URL", "http://localhost:8000"),
		LogPath:    getEnv("AGENT_LOG_PATH", "/home/pokokpisang/Desktop/FYP/ifyp/prototype/agent/test_auth.log"),
		LogType:    getEnv("AGENT_LOG_TYPE", "auth"),
		AuditdPath: getEnv("AGENT_AUDITD_PATH", "/var/log/audit/audit.log"),
		TailFromEnd: getEnv("AGENT_TAIL_FROM_END", "true") == "true",
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
