"""
test_installer_service.py — installer bash-script generation.

Regression guard for the T1543.002 detection gap: the install script's
embedded auditd ruleset (/etc/audit/rules.d/ovs-siem.rules) runs
unconditionally on every install/reinstall (unlike the separate, opt-in
Go-level EnsureAuditd() mechanism), so it must include the systemd unit
directory watches or linux_t1543_002_systemd_service_persistence can never
receive the file-write event it needs.
"""
from app.services.installer_service import generate_install_script


def test_script_watches_systemd_unit_directories_for_t1543():
    script = generate_install_script(server="http://siem.example.com", port=8000)
    for path in ("/etc/systemd/system/", "/usr/lib/systemd/system/", "/lib/systemd/system/"):
        assert f"-w {path} -p wa -k T1543" in script, (
            f"Missing auditd watch rule for {path} — T1543.002 file-write "
            f"detection will stay silent on any newly (re)installed agent."
        )


def test_script_still_watches_execve_for_t1059():
    """Regression guard: adding the T1543 watches must not remove the
    existing execve monitoring the T1059 rules depend on."""
    script = generate_install_script(server="http://siem.example.com", port=8000)
    assert "-a exit,always -F arch=b64 -S execve -k T1059" in script
    assert "-a exit,always -F arch=b32 -S execve -k T1059" in script


def test_script_embeds_server_url():
    script = generate_install_script(server="http://siem.example.com", port=8000)
    assert "http://siem.example.com:8000" in script
