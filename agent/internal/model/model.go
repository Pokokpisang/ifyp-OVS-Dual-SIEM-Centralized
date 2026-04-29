package model

import "time"

type LogEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Host      string    `json:"host"`
	LogType   string    `json:"log_type"`
	FilePath  string    `json:"file_path"`
	Message          string    `json:"message"`
	LocalFlag        bool      `json:"local_flag"`
	AgentRuleID      *int      `json:"agent_rule_id,omitempty"`
	LocalRuleVersion *int      `json:"local_rule_version,omitempty"`
}
