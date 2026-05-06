from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from .. import models

_VALID_SOAR_MODES = {"manual", "automatic"}
_SOAR_MODE_LABELS = {
    "manual": "Manual Approval",
    "automatic": "Automatic Simulation",
}


def get_setting(db: Session, key: str, default: Optional[str] = None) -> Optional[str]:
    row = db.query(models.SystemSetting).filter_by(key=key).first()
    return row.value if row else default


def set_setting(
    db: Session,
    key: str,
    value: str,
    description: Optional[str] = None,
    updated_by: str = "admin",
) -> None:
    row = db.query(models.SystemSetting).filter_by(key=key).first()
    if row:
        row.value = value
        row.updated_by = updated_by
    else:
        db.add(
            models.SystemSetting(
                key=key,
                value=value,
                description=description,
                updated_by=updated_by,
            )
        )
    db.commit()


def get_soar_execution_mode(db: Session) -> str:
    val = get_setting(db, "soar_execution_mode", "manual")
    return val if val in _VALID_SOAR_MODES else "manual"
