"""
routers/audit.py — Audit Trail page + read-only JSON/CSV endpoints.

Routes (all admin-only; audit records are append-only — no write endpoints)
------
GET /audit                  HTML page (System → Audit Trail)
GET /api/audit/events       Filtered + paginated events for the table
GET /api/audit/meta         KPI summary + distinct actors/object types for filters
GET /api/audit/export.csv   CSV export of the current filter set (redacted)
"""
import csv
import io
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .. import db, models
from ..auth.dependencies import require_admin_auth, require_admin_html
from ..services import audit_service

router = APIRouter()
templates = Jinja2Templates(directory="templates")

_EXPORT_MAX_ROWS = 10_000


@router.get("/audit", response_class=HTMLResponse, dependencies=[Depends(require_admin_html)])
def view_audit_trail(request: Request):
    return templates.TemplateResponse("audit_trail.html", {"request": request})


def _filter_params(
    category: str = Query("", description="UI category chip; empty = all"),
    actor: str = Query(""),
    object_type: str = Query(""),
    object_id: str = Query(""),
    q: str = Query(""),
    range: str = Query("24h", description="24h | 7d | 30d | all"),
) -> dict:
    return {
        "category": category or None,
        "actor": actor or None,
        "object_type": object_type or None,
        "object_id": object_id or None,
        "q": q or None,
        "since": audit_service.range_to_since(range),
    }


@router.get("/api/audit/events", dependencies=[Depends(require_admin_auth)])
def get_audit_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(12, ge=1, le=100),
    filters: dict = Depends(_filter_params),
    database: Session = Depends(db.get_db),
):
    rows, total = audit_service.query_audit_events(
        database, page=page, page_size=page_size, **filters
    )
    page_count = max((total + page_size - 1) // page_size, 1)
    return {
        "events": [audit_service.event_to_dict(r) for r in rows],
        "total": total,
        "page": page,
        "page_count": page_count,
    }


@router.get("/api/audit/meta", dependencies=[Depends(require_admin_auth)])
def get_audit_meta(
    range: str = Query("24h"),
    database: Session = Depends(db.get_db),
):
    since = audit_service.range_to_since(range)
    object_types = [
        r[0] for r in database.query(models.ActivityAudit.object_type).distinct().all() if r[0]
    ]
    return {
        "summary": audit_service.summarize_audit_events(database, since=since),
        "actors": audit_service.list_distinct_actors(database),
        "object_types": sorted(object_types),
    }


@router.get("/api/audit/export.csv", dependencies=[Depends(require_admin_auth)])
def export_audit_csv(
    filters: dict = Depends(_filter_params),
    database: Session = Depends(db.get_db),
):
    rows, _total = audit_service.query_audit_events(
        database, page=1, page_size=_EXPORT_MAX_ROWS, **filters
    )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id", "timestamp_utc", "actor", "action", "category",
        "object_type", "object_id", "source_ip", "result", "details",
    ])
    for row in rows:
        e = audit_service.event_to_dict(row)  # read-side redaction applied
        writer.writerow([
            e["id"], e["timestamp_utc"], e["actor"], e["action"], e["category"],
            e["object_type"] or "", e["object_id"] or "", e["source_ip"] or "",
            e["result"], "; ".join(f"{k}={v}" for k, v in e["details"]),
        ])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="ovs-audit-trail.csv"'},
    )
