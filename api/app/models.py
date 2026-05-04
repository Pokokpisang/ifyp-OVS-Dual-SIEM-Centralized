from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, Text, Boolean, Float
from .db import Base
from pydantic import BaseModel
from datetime import datetime

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True)
    host = Column(String, index=True)
    log_type = Column(String)
    file_path = Column(String)
    message = Column(Text)
    local_flag = Column(Boolean, default=False)
    agent_id = Column(String, index=True, nullable=True)
    agent_rule_id = Column(Integer, nullable=True)
    local_rule_version = Column(Integer, nullable=True)

class Metric(Base):
    __tablename__ = "metrics"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True)
    host = Column(String, index=True)
    cpu_percent = Column(String) # Store as string for flexibility or float
    ram_percent = Column(String)
    net_in_bytes = Column(String) # Big ints often safer as strings or BigInteger
    net_out_bytes = Column(String)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True)
    host = Column(String, index=True)
    severity = Column(String) # HIGH, MED, LOW
    title = Column(String)
    description = Column(Text)
    source = Column(String) # MITRE technique ID or legacy source
    is_read = Column(Boolean, default=False)

    # v2.0.0 Generic Metadata Fields
    agent_id = Column(String, index=True, nullable=True)
    rule_id = Column(String, index=True, nullable=True)
    rule_name = Column(String, nullable=True)
    risk_score = Column(Integer, default=0)
    mitre_tactic = Column(String, nullable=True)
    mitre_technique = Column(String, nullable=True)
    detection_engine = Column(String, default="LEGACY") # YAML, LEGACY
    detection_metadata = Column(Text, nullable=True) # JSON match reasons/details

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    rule_type = Column(String, default="server")
    enabled = Column(Boolean, default=True)
    severity_default = Column(String) # HIGH, MED, LOW
    mitre_technique_id = Column(String) # e.g. T1059
    mitre_technique_name = Column(String)
    log_type_scope = Column(String) # e.g. auditd
    logic_json = Column(Text) # JSON stored as text for simplicity in prototype
    created_at_utc = Column(DateTime, default=datetime.utcnow)
    updated_at_utc = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class RuleMatch(Base):
    __tablename__ = "rule_matches"
    
    id = Column(Integer, primary_key=True, index=True)
    matched_at_utc = Column(DateTime, default=datetime.utcnow, index=True)
    rule_id = Column(Integer) # ForeignKey loosely coupled
    log_id = Column(Integer)
    host = Column(String)
    severity = Column(String)
    match_reason = Column(String)
    matched_tokens = Column(Text) # JSON
    message_excerpt = Column(Text)

class ActivityAudit(Base):
    __tablename__ = "activity_audit"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp_utc = Column(DateTime, default=datetime.utcnow, index=True)
    actor = Column(String)
    action = Column(String) # RULE_CREATED, RULE_MATCHED, etc
    object_type = Column(String)
    object_id = Column(String)
    details = Column(Text) # JSON

class AlertAssessment(Base):
    __tablename__ = "alert_assessments"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, unique=True, index=True, nullable=False)
    status = Column(String, default="New")  # New | Investigating | Resolved | False Positive
    analyst_notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AgentRecord(Base):
    """
    Represents a registered (or pending) monitoring agent.
    Tokens are stored as SHA-256 hashes — raw values are never persisted.
    """
    __tablename__ = "agent_records"

    id = Column(Integer, primary_key=True, index=True)
    agent_name = Column(String, nullable=False)
    agent_id = Column(String, unique=True, index=True, nullable=False)  # UUID

    # One-time registration token (hashed). Nulled after first use.
    registration_token_hash = Column(String, nullable=True)
    registration_token_expires_at = Column(DateTime, nullable=True)

    # Permanent agent key (hashed). Set on first registration.
    agent_key_hash = Column(String, nullable=True)

    # Grouping / metadata
    group = Column(String, default="Default Group")
    tags = Column(String, default="")  # comma-separated
    os_type = Column(String, default="Linux")
    distribution = Column(String, default="Ubuntu")
    architecture = Column(String, default="x86_64")

    # Feature flags
    enable_logs = Column(Boolean, default=True)
    enable_fim = Column(Boolean, default=False)
    enable_metrics = Column(Boolean, default=True)

    # Lifecycle
    status = Column(String, default="pending")  # pending | active | offline
    hostname = Column(String, nullable=True)    # filled on registration
    ip_address = Column(String, nullable=True)  # filled on registration
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class SOARActionExecution(Base):
    __tablename__ = "soar_action_executions"

    id                 = Column(Integer, primary_key=True, index=True)
    alert_id           = Column(Integer, ForeignKey("alerts.id"), index=True, nullable=False)
    playbook_id        = Column(String, nullable=False)
    playbook_name      = Column(String, nullable=False)
    action_id          = Column(String, nullable=False)
    action_name        = Column(String, nullable=False)
    action_type        = Column(String, nullable=False)
    target             = Column(String, nullable=True)
    mode               = Column(String, nullable=False)
    status             = Column(String, nullable=False)  # "success" | "failed"
    executed_by        = Column(String, nullable=True)
    executed_at        = Column(DateTime, default=datetime.utcnow)
    result_message     = Column(Text, nullable=True)
    error_message      = Column(Text, nullable=True)
    rollback_supported = Column(Boolean, default=False)
    rollback_status    = Column(String, nullable=True)
    exec_metadata      = Column(Text, nullable=True)  # JSON blob


class SystemHealthRule(Base):
    __tablename__ = "system_health_rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, unique=True, index=True)
    rule_name = Column(String)
    metric_name = Column(String) # cpu, ram, net_in, net_out
    threshold_value = Column(Float)
    operator = Column(String, default=">")
    severity = Column(String, default="MEDIUM")
    enabled = Column(Boolean, default=True)
    detection_engine = Column(String, default="MetricEngine")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_triggered = Column(DateTime, nullable=True)


# Pydantic Models

class LogCreate(BaseModel):
    timestamp: datetime
    host: str
    log_type: str
    file_path: str
    message: str
    local_flag: bool = False
    agent_rule_id: int | None = None
    local_rule_version: int | None = None

class MetricCreate(BaseModel):
    timestamp: datetime
    host: str
    cpu_percent: float
    ram_percent: float
    net_in_bytes: int
    net_out_bytes: int

class AlertCreate(BaseModel):
    timestamp: datetime
    host: str
    severity: str
    title: str
    description: str
    source: str

class LogOut(LogCreate):
    id: int

    class Config:
        from_attributes = True

class SystemHealthRuleBase(BaseModel):
    rule_id: str
    rule_name: str
    metric_name: str
    threshold_value: float
    operator: str
    severity: str
    enabled: bool

class SystemHealthRuleOut(SystemHealthRuleBase):
    id: int
    detection_engine: str
    last_triggered: datetime | None = None

    class Config:
        from_attributes = True

class SystemHealthRuleUpdate(BaseModel):
    enabled: bool | None = None
    threshold_value: float | None = None
    severity: str | None = None
