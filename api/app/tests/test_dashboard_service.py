"""
test_dashboard_service.py — the extracted dashboard data builders + a router
context-key parity check.

Unit tests hit the pure builders against in-memory sqlite (no HTTP/templates).
The parity test drives the real router handlers with templates patched, asserting
the template context is exactly {request} + the builder's keys (guards against a
key rename during the extraction).
"""
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.models import Base
from app.services import dashboard_service

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_Session = sessionmaker(bind=_engine)


def _clear(s):
    for m in (models.SOARActionExecution, models.Alert, models.Metric, models.AgentRecord):
        s.query(m).delete()
    s.commit()


def _metric(s, host, cpu, *, minutes_ago=0, net_in="0", net_out="0"):
    s.add(models.Metric(
        timestamp=datetime.utcnow() - timedelta(minutes=minutes_ago),
        host=host, cpu_percent=str(cpu), ram_percent="30.0",
        net_in_bytes=net_in, net_out_bytes=net_out,
    ))
    s.commit()


def _soar(s, *, status, mode="simulation", action_type="create_case_note", alert_id=1):
    s.add(models.SOARActionExecution(
        alert_id=alert_id, playbook_id="pb", playbook_name="PB", action_id="a",
        action_name="A", action_type=action_type, mode=mode, status=status,
    ))
    s.commit()


# ---------------------------------------------------------------------------
# build_agents_view — metric-only merge, status, pagination
# ---------------------------------------------------------------------------

def test_agents_view_merges_metric_only_hosts_with_status():
    s = _Session()
    _clear(s)
    _metric(s, "busy", 90.0, minutes_ago=0)     # recent + high cpu -> HIGH LOAD
    _metric(s, "idle", 10.0, minutes_ago=0)     # recent + low cpu  -> active
    _metric(s, "stale", 10.0, minutes_ago=30)   # old -> offline

    ctx = dashboard_service.build_agents_view(s)
    by_host = {a["hostname"]: a for a in ctx["agents"]}
    assert by_host["busy"]["status"] == "HIGH LOAD"
    assert by_host["busy"]["cpu"] == 90.0
    assert by_host["idle"]["status"] == "active"
    assert by_host["stale"]["status"] == "offline"
    assert ctx["summary"] == {"total": 3, "online": 2, "offline": 1, "high_load": 1, "pending": 0}
    assert ctx["total_count"] == 3 and ctx["total_pages"] == 1
    s.close()


def test_agents_view_excludes_deleted_agent_with_stale_metrics():
    """A soft-deleted agent must not reappear as a metric-only ghost (its stale
    metrics used to resurrect it, which then 404'd on click)."""
    from app.services.agent_service import create_agent, delete_agent_by_id
    s = _Session()
    _clear(s)

    agent, _ = create_agent(
        agent_name="gone-1", group="g", tags="", os_type="Linux",
        distribution="Ubuntu", architecture="x86_64",
        enable_logs=True, enable_fim=False, enable_metrics=True, db=s,
    )
    agent.hostname = "gone-1"
    s.commit()
    _metric(s, "gone-1", 10.0, minutes_ago=1)     # stale metrics for the deleted host
    delete_agent_by_id(agent.agent_id, s)          # soft delete

    _metric(s, "legacy-host", 10.0, minutes_ago=1)  # truly-unregistered metric host

    ctx = dashboard_service.build_agents_view(s)
    hostnames = {a["hostname"] for a in ctx["agents"]}
    assert "gone-1" not in hostnames               # deleted agent is gone
    assert "legacy-host" in hostnames              # unregistered host still shown
    s.close()


def test_agents_view_filter_and_pagination():
    s = _Session()
    _clear(s)
    for i in range(25):
        _metric(s, f"h{i:02d}", 10.0, minutes_ago=0)  # all active

    page1 = dashboard_service.build_agents_view(s, page=1)
    assert page1["total_count"] == 25
    assert page1["total_pages"] == 2
    assert len(page1["agents"]) == 20

    filtered = dashboard_service.build_agents_view(s, q="h07")
    assert [a["hostname"] for a in filtered["agents"]] == ["h07"]

    none_offline = dashboard_service.build_agents_view(s, status_filter="offline")
    assert none_offline["total_count"] == 0
    assert none_offline["total_pages"] == 1  # never below 1
    s.close()


# ---------------------------------------------------------------------------
# build_soar_history_view — summary + filters + options
# ---------------------------------------------------------------------------

def test_soar_history_summary_and_filters():
    s = _Session()
    _clear(s)
    _soar(s, status="executed")
    _soar(s, status="success")          # legacy success counts as executed
    _soar(s, status="pending_approval")
    _soar(s, status="failed", action_type="isolate_host")
    _soar(s, status="rejected")

    ctx = dashboard_service.build_soar_history_view(s)
    assert ctx["summary"] == {"total": 5, "pending": 1, "executed": 2, "failed": 1, "rejected": 1}
    assert set(ctx["filter_options"]["statuses"]) == {"executed", "success", "pending_approval", "failed", "rejected"}
    assert set(ctx["filter_options"]["action_types"]) == {"create_case_note", "isolate_host"}

    only_failed = dashboard_service.build_soar_history_view(s, status="failed")
    assert len(only_failed["records"]) == 1
    assert only_failed["records"][0].status == "failed"
    assert only_failed["filters"]["status"] == "failed"
    s.close()


# ---------------------------------------------------------------------------
# build_network_view
# ---------------------------------------------------------------------------

def test_network_view_rows_and_alert_map():
    s = _Session()
    _clear(s)
    from app.services.agent_service import create_agent
    agent, _ = create_agent(
        agent_name="web-1", group="g", tags="", os_type="Linux",
        distribution="Ubuntu", architecture="x86_64",
        enable_logs=True, enable_fim=False, enable_metrics=True, db=s,
    )
    s.add(models.Alert(timestamp=datetime.utcnow(), host="web-1", severity="HIGH", title="t"))
    s.commit()

    ctx = dashboard_service.build_network_view(s)
    assert ctx["total_agents"] == 1
    assert len(ctx["agent_rows"]) == 1
    row = ctx["agent_rows"][0]
    assert row["name"] == "web-1"
    assert "net_in" in row and "net_out" in row and row["risk"] == "low"
    assert len(ctx["alert_map"]) == 1
    (aid, meta), = ctx["alert_map"].items()
    assert meta["severity"] == "HIGH" and meta["title"] == "t"
    s.close()


# ---------------------------------------------------------------------------
# build_agents_history_view
# ---------------------------------------------------------------------------

def test_agents_history_view_injects_metrics_and_paginates():
    s = _Session()
    _clear(s)
    from app.services.agent_service import create_agent
    agent, _ = create_agent(
        agent_name="hist-1", group="g", tags="", os_type="Linux",
        distribution="Ubuntu", architecture="x86_64",
        enable_logs=True, enable_fim=False, enable_metrics=True, db=s,
    )
    # give it a hostname + a metric so cpu/ram inject
    agent.hostname = "hist-1"
    s.commit()
    _metric(s, "hist-1", 42.0, minutes_ago=0)

    ctx = dashboard_service.build_agents_history_view(s)
    assert ctx["total_count"] == 1 and ctx["total_pages"] == 1
    assert ctx["agents"][0]["cpu"] == 42.0
    assert ctx["lifecycle_filter"] == "all"
    s.close()


# ---------------------------------------------------------------------------
# Router parity: handler context == {request} + builder keys
# ---------------------------------------------------------------------------

def test_router_handlers_pass_service_context_through():
    import app.routers.dashboard as dash
    s = _Session()
    _clear(s)
    request = SimpleNamespace(state=SimpleNamespace(user={"username": "u", "role": "admin"}))

    captured = {}

    def fake_template_response(name, ctx):
        captured[name] = ctx
        return MagicMock()

    with patch.object(dash, "templates") as mock_templates:
        mock_templates.TemplateResponse.side_effect = fake_template_response
        dash.view_agents(request=request, page=1, q="", status_filter="All", database=s)
        dash.view_agents_history(request=request, page=1, q="", lifecycle_filter="all", database=s)
        dash.view_network(request=request, database=s)
        dash.view_soar_history(request=request, database=s)

    assert set(captured["agents.html"].keys()) == {
        "request", "agents", "page", "total_count", "total_pages", "q", "status_filter", "summary"}
    assert set(captured["agents_history.html"].keys()) == {
        "request", "agents", "page", "total_count", "total_pages", "q", "lifecycle_filter"}
    assert set(captured["network_investigation.html"].keys()) == {
        "request", "agent_rows", "alert_map", "total_agents", "online_agents"}
    assert set(captured["soar_history.html"].keys()) == {
        "request", "records", "filters", "summary", "filter_options"}
    s.close()
