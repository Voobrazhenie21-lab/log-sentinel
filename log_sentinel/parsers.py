"""Log parsers for Linux auth.log, Apache access.log, and Windows Event JSON/CSV logs."""

import csv
import io
import json
import re
from pathlib import Path
from typing import List

from .models import NormalizedEvent

# Linux auth.log regex patterns
SSH_FAILED_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T[\d:.+-]+)\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+)\s+"
    r"from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
)

SSH_ACCEPTED_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T[\d:.+-]+)\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted\s+(?P<method>password|publickey)\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
)

WAZUH_STOP_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T[\d:.+-]+)\s+"
    r"(?P<host>\S+)\s+(?:systemd\[\d+\]|wazuh-agent).*?(?:Stopping|Stopped)\s+Wazuh\s+agent",
    re.IGNORECASE,
)

# Apache Combined Log Format regex
APACHE_RE = re.compile(
    r'^(?P<ip>[\d.]+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>GET|POST|PUT|DELETE|HEAD)\s+(?P<uri>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
)


def parse_linux_auth_line(line: str) -> List[NormalizedEvent]:
    """Parse a single line from Linux /var/log/auth.log or syslog."""
    line = line.strip()
    if not line:
        return []

    m_fail = SSH_FAILED_RE.search(line)
    if m_fail:
        return [
            NormalizedEvent(
                timestamp=m_fail.group("ts"),
                source_type="linux_auth",
                host=m_fail.group("host"),
                event_id="SSH_AUTH_FAILURE",
                user=m_fail.group("user"),
                source_ip=m_fail.group("ip"),
                action="ssh_login",
                status="FAILURE",
                raw_message=line,
                metadata={"port": m_fail.group("port")},
            )
        ]

    m_acc = SSH_ACCEPTED_RE.search(line)
    if m_acc:
        return [
            NormalizedEvent(
                timestamp=m_acc.group("ts"),
                source_type="linux_auth",
                host=m_acc.group("host"),
                event_id="SSH_AUTH_SUCCESS",
                user=m_acc.group("user"),
                source_ip=m_acc.group("ip"),
                action="ssh_login",
                status="SUCCESS",
                raw_message=line,
                metadata={
                    "method": m_acc.group("method"),
                    "port": m_acc.group("port"),
                },
            )
        ]

    m_wazuh = WAZUH_STOP_RE.search(line)
    if m_wazuh:
        return [
            NormalizedEvent(
                timestamp=m_wazuh.group("ts"),
                source_type="linux_auth",
                host=m_wazuh.group("host"),
                event_id="WAZUH_AGENT_STOPPED",
                user="root",
                source_ip="local",
                action="service_stop",
                status="SUCCESS",
                raw_message=line,
            )
        ]

    return []


def parse_apache_line(line: str, default_host: str = "web-server") -> List[NormalizedEvent]:
    """Parse a single line from Apache access.log."""
    line = line.strip()
    if not line:
        return []

    m = APACHE_RE.search(line)
    if not m:
        return []

    return [
        NormalizedEvent(
            timestamp=m.group("ts"),
            source_type="apache_access",
            host=default_host,
            event_id=f"HTTP_{m.group('method')}",
            user=None,
            source_ip=m.group("ip"),
            action=m.group("method"),
            status=m.group("status"),
            raw_message=line,
            metadata={"uri": m.group("uri"), "size": m.group("size")},
        )
    ]


def parse_windows_json_records(data: object) -> List[NormalizedEvent]:
    """Parse Windows Event records from JSON array or object."""
    records = data if isinstance(data, list) else [data]
    events: List[NormalizedEvent] = []

    for rec in records:
        if not isinstance(rec, dict):
            continue
        event_id = str(rec.get("EventID", rec.get("event_id", "UNKNOWN")))
        host = str(rec.get("Computer", rec.get("host", "windows-host")))
        timestamp = str(rec.get("TimeCreated", rec.get("timestamp", "")))
        user = rec.get("TargetUserName", rec.get("user", "SYSTEM"))
        ip = rec.get("IpAddress", rec.get("source_ip", "local"))
        raw = rec.get("Message", json.dumps(rec, ensure_ascii=False))

        events.append(
            NormalizedEvent(
                timestamp=timestamp,
                source_type="windows_event",
                host=host,
                event_id=event_id,
                user=str(user) if user else None,
                source_ip=str(ip) if ip else "local",
                action=str(rec.get("Channel", "Security")),
                status=str(rec.get("Status", "INFO")),
                raw_message=str(raw),
                metadata=rec,
            )
        )
    return events


def parse_windows_csv_content(content: str) -> List[NormalizedEvent]:
    """Parse Windows Event CSV export (EventID,TimeCreated,TargetUserName,IpAddress,...)."""
    reader = csv.DictReader(io.StringIO(content))
    rows = [dict(r) for r in reader if r.get("EventID")]
    return parse_windows_json_records(rows)


def load_events_from_path(target_path: Path) -> List[NormalizedEvent]:
    """Recursively load and normalize logs from a file or directory."""
    files: List[Path] = []
    if target_path.is_dir():
        for p in sorted(target_path.rglob("*")):
            if p.is_file() and p.suffix.lower() in {".log", ".txt", ".json", ".jsonl", ".csv"}:
                if p.name == "sample_report.json" or p.name == "report.json":
                    continue
                files.append(p)
    elif target_path.is_file():
        files.append(target_path)

    all_events: List[NormalizedEvent] = []
    for file_path in files:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        suffix = file_path.suffix.lower()
        if suffix == ".csv":
            all_events.extend(parse_windows_csv_content(content))
            continue
        if suffix == ".json":
            try:
                parsed_json = json.loads(content)
                all_events.extend(parse_windows_json_records(parsed_json))
                continue
            except json.JSONDecodeError:
                pass
        elif suffix == ".jsonl":
            for line in content.splitlines():
                if line.strip():
                    try:
                        all_events.extend(parse_windows_json_records(json.loads(line)))
                    except json.JSONDecodeError:
                        pass
            continue

        # Line-based log parsing (Linux auth.log or Apache access.log)
        for line in content.splitlines():
            ev = parse_linux_auth_line(line)
            if ev:
                all_events.extend(ev)
                continue
            ev_web = parse_apache_line(line)
            if ev_web:
                all_events.extend(ev_web)

    return all_events
