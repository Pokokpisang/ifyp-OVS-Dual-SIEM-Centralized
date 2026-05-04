#!/usr/bin/env python3
"""
cleanup_test_agents.py — Permanently hard-delete selected test/development agents.

Usage:
    python scripts/cleanup_test_agents.py

Reads DATABASE_URL from the environment, or falls back to loading api/.env.
Requires explicit selection and confirmation — no bulk auto-delete.
"""

import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Load DATABASE_URL from env or api/.env fallback
# ---------------------------------------------------------------------------

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


if "DATABASE_URL" not in os.environ:
    _load_env_file(Path(__file__).parent.parent / "api" / ".env")

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    print("ERROR: DATABASE_URL is not set. Set it in the environment or in api/.env.")
    sys.exit(1)

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

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_table(rows: list[dict]) -> None:
    headers = ["#", "agent_name", "hostname", "ip_address", "status", "last_seen", "created_at"]
    col_widths = {h: len(h) for h in headers}
    for i, row in enumerate(rows):
        col_widths["#"] = max(col_widths["#"], len(str(i + 1)))
        for h in headers[1:]:
            col_widths[h] = max(col_widths[h], len(str(row.get(h) or "—")))

    def _fmt_row(values: list[str]) -> str:
        return "  ".join(str(v).ljust(col_widths[h]) for h, v in zip(headers, values))

    separator = "  ".join("-" * col_widths[h] for h in headers)
    print(_fmt_row(headers))
    print(separator)
    for i, row in enumerate(rows):
        print(_fmt_row([
            str(i + 1),
            row.get("agent_name") or "—",
            row.get("hostname") or "—",
            row.get("ip_address") or "—",
            row.get("status") or "—",
            str(row.get("last_seen") or "Never"),
            str(row.get("created_at") or "—"),
        ]))


def _fetch_agents(session) -> list[dict]:
    result = session.execute(text(
        "SELECT agent_id, agent_name, hostname, ip_address, status, last_seen, created_at "
        "FROM agent_records ORDER BY created_at DESC"
    ))
    rows = []
    for r in result.mappings():
        rows.append(dict(r))
    return rows


def _resolve_selection(raw: str, agents: list[dict]) -> list[dict]:
    """
    Match comma-separated agent_ids or exact agent_names against the agent list.
    Returns the matched subset. Prints warnings for unmatched tokens.
    """
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    selected = []
    for token in tokens:
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
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 70)
    print("  OVS SIEM — Test Agent Cleanup (Hard Delete)")
    print("  WARNING: Deletions are permanent and cannot be undone.")
    print("=" * 70)
    print()

    with Session() as session:
        agents = _fetch_agents(session)

    if not agents:
        print("No agent records found in the database.")
        return

    print(f"Found {len(agents)} agent record(s):\n")
    _print_table(agents)
    print()

    print("Enter agent IDs or agent names to delete (comma-separated).")
    print("Example: verify-host, TestHost, e2e-host, ProdClientAsia")
    print("(Do NOT enter 'all' — explicit selection only.)\n")

    raw = input("Agents to delete: ").strip()
    if not raw:
        print("\nNo input provided. Aborting.")
        return

    if raw.lower() in ("all", "all-offline", "*"):
        print("\nBulk 'all' selection is not allowed. Please name agents explicitly.")
        return

    with Session() as session:
        agents = _fetch_agents(session)  # re-fetch for freshness
        selected = _resolve_selection(raw, agents)

    if not selected:
        print("\nNo matching agents found. Nothing to delete.")
        return

    print(f"\nThe following {len(selected)} agent(s) will be PERMANENTLY DELETED:\n")
    _print_table(selected)
    print()

    confirm = input(f"Type CONFIRM to permanently hard-delete these {len(selected)} agent(s): ").strip()
    if confirm != "CONFIRM":
        print("\nConfirmation not received. Aborting — no changes made.")
        return

    print()
    deleted_names = []
    with Session() as session:
        for agent in selected:
            result = session.execute(
                text("DELETE FROM agent_records WHERE agent_id = :aid"),
                {"aid": agent["agent_id"]},
            )
            if result.rowcount:
                deleted_names.append(agent["agent_name"])
                print(f"  DELETED: {agent['agent_name']} ({agent['agent_id']})")
            else:
                print(f"  SKIPPED: {agent['agent_name']} — not found (may have been deleted already)")
        session.commit()

    remaining = len(agents) - len(deleted_names)
    print()
    print("=" * 70)
    print(f"  Deleted:   {len(deleted_names)} agent(s): {', '.join(deleted_names)}")
    print(f"  Remaining: {remaining} agent(s)")
    print("=" * 70)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted. No changes made.")
        sys.exit(0)
