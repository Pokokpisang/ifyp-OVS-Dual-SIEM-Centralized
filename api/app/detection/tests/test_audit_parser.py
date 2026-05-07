"""
Unit tests for AuditdParser PATH record normalisation.

auditd emits type=PATH records when a file-watch rule fires (auditctl -w).
These carry file.path and nametype but no process command_line — that lives
in the accompanying SYSCALL/EXECVE/PROCTITLE records under the same event ID.
"""

import pytest
from app.detection.engine.audit_parser import AuditdParser

PATH_RECORD_CREATE = (
    'type=PATH msg=audit(1710000000.123:456): item=0 '
    'name="/etc/systemd/system/ovs-t1543-demo.service" '
    'inode=123 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 '
    'nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0'
)

PATH_RECORD_DELETE = (
    'type=PATH msg=audit(1710000000.124:457): item=0 '
    'name="/etc/systemd/system/ovs-t1543-demo.service" '
    'inode=123 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 '
    'nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0'
)

PATH_RECORD_NORMAL = (
    'type=PATH msg=audit(1710000000.125:458): item=0 '
    'name="/etc/cron.d/evil" '
    'inode=999 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 '
    'nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0'
)

PATH_RECORD_NO_NAME = (
    'type=PATH msg=audit(1710000000.126:459): item=0 '
    'inode=111 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 '
    'nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0'
)


def _normalize(message: str) -> dict:
    return AuditdParser.normalize_log({"message": message, "log_type": "auditd"})


def test_audit_parser_extracts_file_path_from_path_record():
    result = _normalize(PATH_RECORD_CREATE)
    assert result.get("file", {}).get("path") == "/etc/systemd/system/ovs-t1543-demo.service"


def test_audit_parser_extracts_file_name_from_path_record():
    result = _normalize(PATH_RECORD_CREATE)
    assert result.get("file", {}).get("name") == "ovs-t1543-demo.service"


def test_audit_parser_maps_create_nametype_to_created():
    result = _normalize(PATH_RECORD_CREATE)
    assert result.get("event", {}).get("action") == "created"


def test_audit_parser_maps_normal_nametype_to_write():
    result = _normalize(PATH_RECORD_NORMAL)
    assert result.get("event", {}).get("action") == "write"


def test_audit_parser_maps_delete_nametype_to_deleted():
    result = _normalize(PATH_RECORD_DELETE)
    assert result.get("event", {}).get("action") == "deleted"


def test_audit_parser_path_record_sets_event_category_and_type():
    result = _normalize(PATH_RECORD_CREATE)
    assert result.get("event", {}).get("category") == "file"
    assert result.get("event", {}).get("type") == "change"


def test_audit_parser_path_record_without_name_does_not_crash():
    # Should not raise; file dict should remain absent or empty
    result = _normalize(PATH_RECORD_NO_NAME)
    assert result.get("file", {}).get("path") is None


def test_audit_parser_non_path_record_does_not_set_file_path():
    execve = (
        'type=EXECVE msg=audit(1710000000.200:500): argc=3 '
        'a0="bash" a1="-c" a2="echo hello"'
    )
    result = _normalize(execve)
    assert result.get("file") is None
