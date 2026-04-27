from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
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
    source = Column(String) # Rule name
    is_read = Column(Boolean, default=False)

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
