#!/usr/bin/env python3
"""
cleanup_test_agents.py — Permanently hard-delete selected test/development agents.

Usage:
    python scripts/cleanup_test_agents.py

Reads DATABASE_URL from the environment, or falls back to loading api/.env,
then docker-compose.yml credentials.

Two types of agents are shown:
  [registered] — have an agent_records row (went through /agents/new registration)
  [metric-only] — appeared via metrics/logs ingestion only; no agent_records row

Both types can be selected and deleted. For metric-only hosts, all metrics and
log rows for that host are permanently removed.
"""

import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Env / URL loading
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent


def _load_env_file(path: Path) -> None:
    if not path.exists():
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def _load_docker_compose_db_url(repo_root: Path) -> str | None:
    import re
    compose = repo_root / "docker-compose.yml"
    if not compose.exists():
        return None
    content = compose.read_text()
    match = re.search(r"DATABASE_URL=(postgresql://[^\s\"']+)", content)
    if not match:
        return None
    url = match.group(1)
    url = re.sub(r"@(?!localhost|127\.0\.0\.1)([^:/]+)(:\d+/)", r"@localhost\2", url)
    return url


def _to_localhost(url: str) -> str:
    import re
    return re.sub(r"@(?!localhost|127\.0\.0\.1)([^:/]+)(:\d+/)", r"@localhost\2", url)


if "DATABASE_URL" not in os.environ:
    _load_env_file(_REPO_ROOT / "api" / ".env")

DATABASE_URL = _to_localhost(os.environ.get("DATABASE_URL", ""))

# ---------------------------------------------------------------------------
# DB connection
# ---------------------------------------------------------------------------

try:
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker
except ImportError:
    print("ERROR: sqlalchemy is not installed. Activate the api virtualenv first:")
    print("  source api/.venv/bin/activate")
    sys.exit(1)


def _make_session_factory(url: str):
    eng = create_engine(url, connect_args={"connect_timeout": 5})
    return sessionmaker(bind=eng)


def _get_working_session_factory() -> object:
    """Return a connected session factory, trying .env URL first then docker-compose."""
    candidates = []
    if DATABASE_URL:
        candidates.append(DATABASE_URL)
    compose_url = _load_docker_compose_db_url(_REPO_ROOT)
    if compose_url and compose_url not in candidates:
        candidates.append(compose_url)

    last_err = None
    for url in candidates:
        factory = _make_session_factory(url)
        try:
            with factory() as s:
                s.execute(text("SELECT 1"))
            return factory
        except Exception as e:
            last_err = e

    print(f"\nERROR: Could not connect to the database.\n  {last_err}")
    print("\nMake sure the SIEM stack is running ('make up') and try again.")
    print("Or set DATABASE_URL manually:")
    print("  DATABASE_URL=postgresql://user:password@localhost:5432/siemdb python scripts/cleanup_test_agents.py")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Data fetching
# ---------------------------------------------------------------------------

def _fetch_all(session_factory) -> list[dict]:
    """
    Return a unified list of all agents visible on the /agents dashboard.
    Each entry has a '_type' key: 'registered' or 'metric-only'.
    """
    with session_factory() as session:
        # Registered agents from agent_records
        reg_rows = list(session.execute(text(
            "SELECT agent_id, agent_name, hostname, ip_address, status, last_seen, created_at "
            "FROM agent_records ORDER BY created_at DESC"
        )).mappings())

        registered_hostnames = {r["hostname"] for r in reg_rows if r["hostname"]}

        # Metric-only hosts: distinct hosts in metrics not covered by agent_records
        metric_hosts = session.execute(text(
            "SELECT host, MAX(timestamp) AS last_seen, MIN(timestamp) AS created_at "
            "FROM metrics GROUP BY host ORDER BY last_seen DESC"
        )).mappings()

        result = []
        for r in reg_rows:
            result.append({
                "_type": "registered",
                "agent_id": r["agent_id"],
                "agent_name": r["agent_name"],
                "hostname": r["hostname"] or "—",
                "ip_address": r["ip_address"] or "—",
                "status": r["status"] or "—",
                "last_seen": r["last_seen"],
                "created_at": r["created_at"],
            })

        for m in metric_hosts:
            if m["host"] not in registered_hostnames:
                result.append({
                    "_type": "metric-only",
                    "agent_id": m["host"],  # use host as the selection key
                    "agent_name": m["host"],
                    "hostname": m["host"],
                    "ip_address": "—",
                    "status": "metric-only",
                    "last_seen": m["last_seen"],
                    "created_at": m["created_at"],
                })

    return result


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _print_table(rows: list[dict]) -> None:
    headers = ["#", "type", "agent_name", "hostname", "ip_address", "status", "last_seen"]
    col_widths = {h: len(h) for h in headers}
    for i, row in enumerate(rows):
        col_widths["#"] = max(col_widths["#"], len(str(i + 1)))
        col_widths["type"] = max(col_widths["type"], len(row.get("_type", "—")))
        for h in ["agent_name", "hostname", "ip_address", "status"]:
            col_widths[h] = max(col_widths[h], len(str(row.get(h) or "—")))
        col_widths["last_seen"] = max(col_widths["last_seen"], len(str(row.get("last_seen") or "Never")))

    def _fmt(values):
        return "  ".join(str(v).ljust(col_widths[h]) for h, v in zip(headers, values))

    print(_fmt(headers))
    print("  ".join("-" * col_widths[h] for h in headers))
    for i, row in enumerate(rows):
        print(_fmt([
            str(i + 1),
            row.get("_type", "—"),
            row.get("agent_name") or "—",
            row.get("hostname") or "—",
            row.get("ip_address") or "—",
            row.get("status") or "—",
            str(row.get("last_seen") or "Never"),
        ]))


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

def _resolve_selection(raw: str, agents: list[dict]) -> list[dict]:
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    selected = []
    for token in tokens:
        # Match by number, agent_id, or agent_name
        matched = None
        if token.isdigit():
            idx = int(token) - 1
            if 0 <= idx < len(agents):
                matched = agents[idx]
        if not matched:
            matched = next(
                (a for a in agents if a["agent_id"] == token or a["agent_name"] == token),
                None,
            )
        if matched:
            if matched not in selected:
                selected.append(matched)
        else:
            print(f"  WARNING: No agent found matching '{token}' — skipped.")
    return selected


# ---------------------------------------------------------------------------
# Deletion
# ---------------------------------------------------------------------------

def _delete_agents(selected: list[dict], session_factory) -> list[str]:
    deleted_names = []
    with session_factory() as session:
        for agent in selected:
            name = agent["agent_name"]
            host = agent["hostname"] if agent["hostname"] != "—" else None

            if agent["_type"] == "registered":
                result = session.execute(
                    text("DELETE FROM agent_records WHERE agent_id = :aid"),
                    {"aid": agent["agent_id"]},
                )
                if result.rowcount:
                    deleted_names.append(name)
                    print(f"  DELETED (agent_records): {name}")
                else:
                    print(f"  SKIPPED: {name} — not found in agent_records")

            elif agent["_type"] == "metric-only":
                host = agent["agent_id"]  # for metric-only, agent_id == host
                m_del = session.execute(text("DELETE FROM metrics WHERE host = :h"), {"h": host})
                l_del = session.execute(text("DELETE FROM logs WHERE host = :h"), {"h": host})
                deleted_names.append(name)
                print(f"  DELETED (metric-only): {name}  "
                      f"[{m_del.rowcount} metric rows, {l_del.rowcount} log rows removed]")

        session.commit()
    return deleted_names


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 70)
    print("  OVS SIEM — Test Agent Cleanup (Hard Delete)")
    print("  WARNING: Deletions are permanent and cannot be undone.")
    print("=" * 70)
    print()

    sf = _get_working_session_factory()
    agents = _fetch_all(sf)

    if not agents:
        print("No agents found in the database.")
        return

    print(f"Found {len(agents)} agent(s) visible on the dashboard:\n")
    _print_table(agents)
    print()
    print("  [registered]  = has an agent_records row (formal registration)")
    print("  [metric-only] = appeared via metrics/logs only (no registration)\n")

    print("Enter agent numbers, agent_ids, or agent names to delete (comma-separated).")
    print("Example: 2, 3, 4, 5  or  verify-host, TestHost\n")

    raw = input("Agents to delete: ").strip()
    if not raw:
        print("\nNo input provided. Aborting.")
        return

    if raw.lower() in ("all", "all-offline", "*"):
        print("\nBulk 'all' selection is not allowed. Please select agents explicitly.")
        return

    selected = _resolve_selection(raw, agents)

    if not selected:
        print("\nNo matching agents found. Nothing to delete.")
        return

    print(f"\nThe following {len(selected)} agent(s) will be PERMANENTLY DELETED:\n")
    _print_table(selected)
    print()

    confirm = input(f"Type CONFIRM to permanently delete these {len(selected)} agent(s): ").strip()
    if confirm != "CONFIRM":
        print("\nConfirmation not received. Aborting — no changes made.")
        return

    print()
    deleted_names = _delete_agents(selected, sf)

    remaining = len(agents) - len(deleted_names)
    print()
    print("=" * 70)
    print(f"  Deleted:   {len(deleted_names)}  → {', '.join(deleted_names)}")
    print(f"  Remaining: {remaining}")
    print("=" * 70)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted. No changes made.")
        sys.exit(0)
