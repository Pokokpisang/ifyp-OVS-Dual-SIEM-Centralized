"""
dashboard_service — data assembly for the heavy dashboard views.

Extracted from routers/dashboard.py so those handlers stay thin (fetch → call
service → render). Every function here is strictly read-only (queries only, no
commit) and returns the exact template-context dict the handler passes to the
template, minus ``request``. The router does ``{"request": request, **ctx}``.
"""
import math
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

from sqlalchemy import desc
from sqlalchemy.orm import Session

from .. import models
from .agent_service import get_all_agents_for_history, get_offline_threshold_minutes, list_agents

_AGENTS_PER_PAGE = 20


def _paginate_list(items: list, page: int, size: int) -> Tuple[list, int, int]:
    """Return (page_items, total_count, total_pages) for an in-memory list.

    total_pages is at least 1 (matches the router's max(ceil, 1) semantics).
    """
    total_count = len(items)
    total_pages = max(math.ceil(total_count / size), 1)
    offset = (page - 1) * size
    return items[offset:offset + size], total_count, total_pages


def _latest_metric(db: Session, host: str) -> Optional[models.Metric]:
    if not host or host == "—":
        return None
    return (
        db.query(models.Metric)
        .filter(models.Metric.host == host)
        .order_by(desc(models.Metric.timestamp))
        .first()
    )


def build_agents_view(
    db: Session, *, q: str = "", status_filter: str = "All", page: int = 1
) -> dict:
    """Agent inventory: registered agents merged with metric-only hosts, with
    status/HIGH-LOAD computation, cpu/ram injection, filtering, summary and
    pagination. Read-only."""
    registered = list_agents(db, include_deleted=False)

    hosts_with_metrics = {h[0] for h in db.query(models.Metric.host).distinct().all()}

    # Hostnames of ALL agent records (including deleted / retired / test), so a
    # deleted or uninstalled agent's stale metric rows do not resurrect it as a
    # metric-only "ghost" that 404s when opened. Only truly-unregistered hosts
    # (never had an AgentRecord) appear as metric-only entries.
    known_agent_hostnames = {
        h[0] for h in db.query(models.AgentRecord.hostname).distinct().all()
        if h[0] and h[0] != "—"
    }

    now = datetime.utcnow()
    agents: List[dict] = list(registered)

    for host in hosts_with_metrics - known_agent_hostnames:
        latest = _latest_metric(db, host)
        if not latest:
            continue
        is_offline = (now - latest.timestamp) > timedelta(minutes=get_offline_threshold_minutes())
        is_high_load = float(latest.cpu_percent) > 85.0
        status = "offline" if is_offline else ("HIGH LOAD" if is_high_load else "active")
        agents.append({
            "id": None,
            "agent_id": host,
            "agent_name": host,
            "group": "—",
            "tags": "",
            "os_type": "Linux",
            "distribution": "—",
            "architecture": "—",
            "status": status,
            "hostname": host,
            "ip_address": "—",
            "last_seen": latest.timestamp.strftime("%Y-%m-%d %H:%M UTC"),
            "created_at": "—",
            "cpu": round(float(latest.cpu_percent), 1),
            "ram": round(float(latest.ram_percent), 1),
        })

    # Inject cpu/ram for registered agents that also have metrics
    for a in agents:
        if "cpu" not in a:
            latest = _latest_metric(db, a.get("hostname", ""))
            a["cpu"] = round(float(latest.cpu_percent), 1) if latest else 0
            a["ram"] = round(float(latest.ram_percent), 1) if latest else 0

    if q:
        agents = [
            a for a in agents
            if q.lower() in a["agent_name"].lower() or q.lower() in a["hostname"].lower()
        ]
    if status_filter != "All":
        agents = [a for a in agents if a["status"].lower() == status_filter.lower()]

    total_online = sum(1 for a in agents if a["status"] in ("active", "HIGH LOAD"))
    total_offline = sum(1 for a in agents if a["status"] == "offline")
    total_pending = sum(1 for a in agents if a["status"] == "pending")
    total_high_load = sum(1 for a in agents if a["status"] == "HIGH LOAD")

    paginated, total_count, total_pages = _paginate_list(agents, page, _AGENTS_PER_PAGE)

    return {
        "agents": paginated,
        "page": page,
        "total_count": total_count,
        "total_pages": total_pages,
        "q": q,
        "status_filter": status_filter,
        "summary": {
            "total": total_count,
            "online": total_online,
            "offline": total_offline,
            "high_load": total_high_load,
            "pending": total_pending,
        },
    }


def build_agents_history_view(
    db: Session, *, q: str = "", lifecycle_filter: str = "all", page: int = 1
) -> dict:
    """Agent lifecycle history with cpu/ram injection and pagination. Read-only."""
    agents = get_all_agents_for_history(db, q=q, lifecycle_filter=lifecycle_filter)

    for a in agents:
        latest = _latest_metric(db, a.get("hostname", ""))
        a["cpu"] = round(float(latest.cpu_percent), 1) if latest else 0
        a["ram"] = round(float(latest.ram_percent), 1) if latest else 0

    paginated, total_count, total_pages = _paginate_list(agents, page, _AGENTS_PER_PAGE)

    return {
        "agents": paginated,
        "page": page,
        "total_count": total_count,
        "total_pages": total_pages,
        "q": q,
        "lifecycle_filter": lifecycle_filter,
    }


def build_network_view(db: Session) -> dict:
    """Network investigation view: agent rows with net stats, recent-alert map,
    and summary counts. Read-only."""
    registered = list_agents(db, include_deleted=False)

    now = datetime.utcnow()
    agent_rows = []
    for a in registered:
        host = a.get("hostname") or a.get("agent_name", "")
        latest = _latest_metric(db, host)
        is_offline = (now - latest.timestamp) > timedelta(minutes=get_offline_threshold_minutes()) if latest else True
        net_in = int(float(latest.net_in_bytes)) if latest else 0
        net_out = int(float(latest.net_out_bytes)) if latest else 0
        agent_rows.append({
            "name": a.get("agent_name", "—"),
            "host": a.get("ip_address", "—"),
            "status": a.get("status", "offline"),
            "last_seen": a.get("last_seen", "—"),
            "net_in": net_in,
            "net_out": net_out,
            "risk": "low",  # TODO: derive from alert severity when network alert model exists
        })

    recent_alerts = (
        db.query(models.Alert)
        .order_by(desc(models.Alert.timestamp))
        .limit(20)
        .all()
    )
    alert_map = {a.id: {"id": a.id, "title": a.title, "severity": a.severity} for a in recent_alerts}

    total_agents = len(agent_rows)
    online_agents = sum(1 for a in agent_rows if a["status"] in ("active", "HIGH LOAD"))

    return {
        "agent_rows": agent_rows,
        "alert_map": alert_map,
        "total_agents": total_agents,
        "online_agents": online_agents,
    }


def build_soar_history_view(
    db: Session,
    *,
    status: Optional[str] = None,
    mode: Optional[str] = None,
    action_type: Optional[str] = None,
    alert_id: Optional[int] = None,
) -> dict:
    """SOAR execution history: filtered records, unfiltered summary counts, and
    distinct filter options. Read-only."""
    q = db.query(models.SOARActionExecution)
    if status:
        q = q.filter(models.SOARActionExecution.status == status)
    if mode:
        q = q.filter(models.SOARActionExecution.mode == mode)
    if action_type:
        q = q.filter(models.SOARActionExecution.action_type == action_type)
    if alert_id:
        q = q.filter(models.SOARActionExecution.alert_id == alert_id)

    records = q.order_by(models.SOARActionExecution.id.desc()).limit(100).all()

    all_rows = db.query(models.SOARActionExecution)
    total = all_rows.count()
    pending = all_rows.filter(models.SOARActionExecution.status == "pending_approval").count()
    executed = all_rows.filter(models.SOARActionExecution.status.in_(["executed", "success"])).count()
    failed = all_rows.filter(models.SOARActionExecution.status == "failed").count()
    rejected = all_rows.filter(models.SOARActionExecution.status == "rejected").count()

    statuses = [r[0] for r in db.query(models.SOARActionExecution.status).distinct().all() if r[0]]
    modes = [r[0] for r in db.query(models.SOARActionExecution.mode).distinct().all() if r[0]]
    action_types = [r[0] for r in db.query(models.SOARActionExecution.action_type).distinct().all() if r[0]]

    return {
        "records": records,
        "filters": {
            "status": status or "",
            "mode": mode or "",
            "action_type": action_type or "",
            "alert_id": alert_id or "",
        },
        "summary": {
            "total": total,
            "pending": pending,
            "executed": executed,
            "failed": failed,
            "rejected": rejected,
        },
        "filter_options": {
            "statuses": statuses,
            "modes": modes,
            "action_types": action_types,
        },
    }
