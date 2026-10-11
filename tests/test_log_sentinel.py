"""Unit tests for Log Sentinel parsers, correlation engine, and reporters."""

from pathlib import Path
from log_sentinel.engine import DetectionEngine
from log_sentinel.parsers import (
    load_events_from_path,
    parse_apache_line,
    parse_linux_auth_line,
    parse_windows_json_records,
)
from log_sentinel.reporter import generate_html_dashboard, generate_json_report


def test_parse_linux_ssh_failed_and_accepted() -> None:
    fail_line = "Apr 18 12:35:01 web-server sshd[2104]: Failed password for invalid user admin from 10.0.10.254 port 49112 ssh2"
    ev_fail = parse_linux_auth_line(fail_line)
    assert len(ev_fail) == 1
    assert ev_fail[0].event_id == "SSH_AUTH_FAILURE"
    assert ev_fail[0].user == "admin"
    assert ev_fail[0].source_ip == "10.0.10.254"

    acc_line = "Apr 18 12:52:09 web-server sshd[2341]: Accepted publickey for root from 10.0.10.254 port 50214 ssh2"
    ev_acc = parse_linux_auth_line(acc_line)
    assert len(ev_acc) == 1
    assert ev_acc[0].event_id == "SSH_AUTH_SUCCESS"
    assert ev_acc[0].metadata["method"] == "publickey"


def test_parse_apache_webshell_upload() -> None:
    line = '10.0.10.254 - - [18/Apr/2023:12:43:00 +0000] "GET /hackable/uploads/backdoor.php HTTP/1.1" 200 13585'
    ev = parse_apache_line(line)
    assert len(ev) == 1
    assert ev[0].event_id == "HTTP_GET"
    assert ev[0].metadata["uri"] == "/hackable/uploads/backdoor.php"


def test_detect_pass_the_hash_and_kerberoasting() -> None:
    records = [
        {
            "TimeCreated": "2023-04-19T09:20:00Z",
            "EventID": 4769,
            "Computer": "dc01.acme.skb",
            "TargetUserName": "user1@ACME.SKB",
            "ServiceName": "mssql_svc",
            "TicketEncryptionType": "0x17",
            "IpAddress": "10.0.30.53",
        },
        {
            "TimeCreated": "2023-04-19T09:34:29Z",
            "EventID": 4624,
            "Computer": "dc01.acme.skb",
            "TargetUserName": "domainadmin",
            "IpAddress": "10.0.30.53",
            "LogonType": 3,
            "AuthenticationPackageName": "NTLM",
            "LogonProcessName": "NtLmSsp",
            "KeyLength": 0,
        },
    ]
    events = parse_windows_json_records(records)
    engine = DetectionEngine()
    alerts = engine.analyze(events)
    rule_ids = {a.rule_id for a in alerts}
    assert "LS-RULE-004" in rule_ids  # Kerberoasting
    assert "LS-RULE-005" in rule_ids  # Pass-the-Hash


def test_detect_asrep_roasting_and_sysmon_lsass() -> None:
    records = [
        {
            "TimeCreated": "2023-04-19T09:11:31Z",
            "EventID": 10,
            "Computer": "ws01.acme.skb",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "TargetUserName": "SYSTEM",
            "IpAddress": "10.0.10.254",
            "SourceImage": "\\\\tsclient\\_home_kali_Documents_Brute-RDP.py_rdpshare_\\mimikatz.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
        },
        {
            "TimeCreated": "2023-04-19T09:18:45Z",
            "EventID": 4768,
            "Computer": "dc01.acme.skb",
            "TargetUserName": "legacy_svc@ACME.SKB",
            "TicketEncryptionType": "0x17",
            "PreAuthType": "0",
            "IpAddress": "10.0.30.53",
        },
    ]
    events = parse_windows_json_records(records)
    engine = DetectionEngine()
    alerts = engine.analyze(events)
    rule_ids = {a.rule_id for a in alerts}
    assert "LS-RULE-009" in rule_ids  # AS-REP Roasting
    assert "LS-RULE-010" in rule_ids  # Sysmon Event ID 10 LSASS Access


def test_full_samples_directory_pipeline() -> None:
    samples_dir = Path(__file__).resolve().parent.parent / "samples"
    events = load_events_from_path(samples_dir)
    assert len(events) >= 22

    engine = DetectionEngine()
    alerts = engine.analyze(events)
    rule_ids = {a.rule_id for a in alerts}

    # Verify all 10 core detection rules fire on the acme.skb sample bundle
    assert "LS-RULE-001" in rule_ids  # Web Shell
    assert "LS-RULE-002" in rule_ids  # SSH Brute-force -> login
    assert "LS-RULE-003" in rule_ids  # Windows RDP 4625 -> 4624
    assert "LS-RULE-004" in rule_ids  # Kerberoasting 4769 0x17
    assert "LS-RULE-005" in rule_ids  # Pass-the-Hash 4624 NTLM
    assert "LS-RULE-006" in rule_ids  # Defender 5001 / Wazuh 506
    assert "LS-RULE-007" in rule_ids  # WER AppCrash CVE-2019-0623
    assert "LS-RULE-008" in rule_ids  # Mimikatz via \\tsclient
    assert "LS-RULE-009" in rule_ids  # AS-REP Roasting 4768 PreAuthType 0
    assert "LS-RULE-010" in rule_ids  # Sysmon Event ID 10 LSASS Access

    json_rep = generate_json_report(events, alerts)
    assert json_rep["summary"]["total_alerts_triggered"] == len(alerts)

    html_out = generate_html_dashboard(events, alerts)
    assert "Log Sentinel v1.3.0" in html_out
    assert "LS-RULE-010" in html_out
