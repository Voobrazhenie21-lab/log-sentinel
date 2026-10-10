"""Data models for normalized security events and SOC alerts."""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedEvent:
    """Standardized representation of a Linux, Web, or Windows security log entry."""

    timestamp: str
    source_type: str  # 'linux_auth', 'apache_access', 'windows_event'
    host: str
    event_id: str
    user: Optional[str] = None
    source_ip: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    raw_message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    """Represents a correlated security detection alert for SOC L1/L2 triage."""

    rule_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    mitre_tactic: str
    mitre_technique: str
    host: str
    source_ip: str
    target_user: str
    timestamp_first: str
    timestamp_last: str
    event_count: int
    description: str
    evidence: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    wazuh_rule_equivalent: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
