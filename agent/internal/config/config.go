package config

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type LogPaths struct {
	Auth   string `yaml:"auth"`
	Syslog string `yaml:"syslog"`
	Auditd string `yaml:"auditd"`
}

type Config struct {
	ServerURL     string   `yaml:"server_url"`
	AgentName     string   `yaml:"agent_name"`
	AgentKey      string   `yaml:"agent_key"`
	EnableLogs    bool     `yaml:"enable_logs"`
	EnableFIM     bool     `yaml:"enable_fim"`
	EnableMetrics bool     `yaml:"enable_metrics"`
	LogPaths      LogPaths `yaml:"log_paths"`

	// Runtime info
	DetectedOS string
}

func Load() *Config {
	configPath := flag.String("config", "", "Path to configuration file")
	flag.Parse()

	// 1. Detect OS first for defaults
	osID, osLike := detectOS()

	// 2. Set Defaults based on OS
	cfg := &Config{
		ServerURL:     "http://localhost:8000",
		AgentName:     "ovs-agent",
		EnableLogs:    true,
		EnableFIM:     false,
		EnableMetrics: true,
		DetectedOS:    osID,
		LogPaths:      getDefaultLogPaths(osID, osLike),
	}

	// 3. Override from YAML if provided
	if *configPath != "" {
		data, err := os.ReadFile(*configPath)
		if err != nil {
			fmt.Printf("Warning: Could not read config file %s: %v\n", *configPath, err)
		} else {
			// Create a temp struct to handle partial YAML parsing if needed
			// but here we just unmarshal into the main struct.
			if err := yaml.Unmarshal(data, cfg); err != nil {
				fmt.Printf("Warning: Error parsing YAML config: %v\n", err)
			} else {
				fmt.Printf("Loaded config from %s\n", *configPath)
			}
		}
	}

	// 4. Environment Variable Overrides (Legacy support & quick testing)
	if val := os.Getenv("AGENT_SERVER_URL"); val != "" {
		cfg.ServerURL = val
	}
	if val := os.Getenv("AGENT_NAME"); val != "" {
		cfg.AgentName = val
	}
	if val := os.Getenv("AGENT_KEY"); val != "" {
		cfg.AgentKey = val
	}
	if val := os.Getenv("AGENT_LOG_PATH"); val != "" {
		cfg.LogPaths.Auth = val
	}

	return cfg
}

func detectOS() (string, string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "linux", ""
	}

	lines := strings.Split(string(data), "\n")
	var id, idLike string
	for _, line := range lines {
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		}
		if strings.HasPrefix(line, "ID_LIKE=") {
			idLike = strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), "\"")
		}
	}
	return id, idLike
}

func getDefaultLogPaths(osID, osLike string) LogPaths {
	// Default to Debian/Ubuntu style
	paths := LogPaths{
		Auth:   "/var/log/auth.log",
		Syslog: "/var/log/syslog",
		Auditd: "/var/log/audit/audit.log",
	}

	// Check for RHEL/Rocky/CentOS
	isRHEL := osID == "rocky" || osID == "rhel" || osID == "centos" ||
		strings.Contains(osLike, "rhel") || strings.Contains(osLike, "fedora")

	if isRHEL {
		paths.Auth = "/var/log/secure"
		paths.Syslog = "/var/log/messages"
	}

	return paths
}
