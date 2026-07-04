"""
agent_monitor — dead-silence detection for registered agents.

A background sweep (started in main.py) periodically calls
``check_silent_agents``: any active agent whose ``last_seen`` is older than
the silence threshold (AGENT_SILENCE_THRESHOLD_MINUTES, default 5) gets ONE
alert per silence episode. The dedup key embeds ``last_seen``, so:

- repeated sweeps during the same outage do not re-alert (same key), and
- an agent that recovers and later goes silent again alerts again
  (``last_seen`` advanced → new key).

Alerts flow through ``alert_service.create_alert``, so notification channels
fire automatically. SOAR auto-run is intentionally NOT triggered — silence is
a health/tamper signal, not a confirmed intrusion.
"""
import logging
from datetime import datetime, timedelta
from typing import List

from sqlalchemy.orm import Session

from .. import models
from .agent_service import get_offline_threshold_minutes
from .alert_service import AlertSpec, create_alert

logger = logging.getLogger("services.agent_monitor")

RULE_ID = "agent_dead_silence"


def list_silent_agents(db: Session) -> List[models.AgentRecord]:
    """Active, non-deleted agents that have heartbeated before but not recently."""
    cutoff = datetime.utcnow() - timedelta(minutes=get_offline_threshold_minutes())
    return (
        db.query(models.AgentRecord)
        .filter(
            models.AgentRecord.is_deleted == False,  # noqa: E712
            models.AgentRecord.status == "active",
            models.AgentRecord.last_seen != None,  # noqa: E711 — never-seen agents are "pending", not "silent"
            models.AgentRecord.last_seen < cutoff,
        )
        .all()
    )


def check_silent_agents(db: Session) -> List[models.Alert]:
    """Create one alert per newly-silent agent. Returns created alerts."""
    threshold = get_offline_threshold_minutes()
    created: List[models.Alert] = []
    for agent in list_silent_agents(db):
        silent_for = datetime.utcnow() - agent.last_seen
        spec = AlertSpec(
            host=agent.hostname or agent.agent_name,
            severity="HIGH",
            title=f"Agent silent: {agent.agent_name} stopped reporting",
            description=(
                f"Agent '{agent.agent_name}' ({agent.hostname or 'unknown host'}) has sent no "
                f"heartbeat for {int(silent_for.total_seconds() // 60)} minutes "
                f"(threshold: {threshold} min; last seen {agent.last_seen:%Y-%m-%d %H:%M:%S} UTC). "
                "Possible causes: host down, network partition, agent crashed, or the agent "
                "process was killed — the last is a defense-evasion signal worth verifying."
            ),
            detection_engine="AgentMonitor",
            agent_id=agent.agent_id,
            rule_id=RULE_ID,
            rule_name="Agent Dead-Silence Monitor",
            risk_score=60,
            dedup_key=f"{RULE_ID}:{agent.agent_id}:{agent.last_seen.isoformat()}",
            detection_metadata={
                "last_seen": agent.last_seen.isoformat(),
                "threshold_minutes": threshold,
                "agent_name": agent.agent_name,
                "hostname": agent.hostname,
                "ip_address": agent.ip_address,
            },
        )
        alert = create_alert(db, spec, trigger_soar=False)
        if alert is not None:
            logger.warning("[AGENT_MONITOR] Silent agent alert #%s for %s", alert.id, agent.agent_name)
            created.append(alert)
    return created
