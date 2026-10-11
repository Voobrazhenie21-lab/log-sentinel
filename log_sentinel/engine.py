"""Correlation & Threat Detection Engine for Log Sentinel."""

from collections import defaultdict
from typing import Dict, List, Tuple

from .models import Alert, NormalizedEvent

WEBSHELL_INDICATORS = ("backdoor.php", "shell.php", "cmd.php", "c99.php", "/hackable/uploads/")


class DetectionEngine:
    """Evaluates normalized log events against SOC L1/L2 correlation rules."""

    def __init__(self, ssh_threshold: int = 4, rdp_threshold: int = 5) -> None:
        self.ssh_threshold = ssh_threshold
        self.rdp_threshold = rdp_threshold

    def analyze(self, events: List[NormalizedEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        alerts.extend(self._detect_webshell_activity(events))
        alerts.extend(self._detect_ssh_bruteforce_and_root_key(events))
        alerts.extend(self._detect_windows_rdp_bruteforce(events))
        alerts.extend(self._detect_kerberoasting(events))
        alerts.extend(self._detect_pass_the_hash(events))
        alerts.extend(self._detect_defense_evasion_and_wer(events))
        alerts.extend(self._detect_malware_and_tsclient(events))
        alerts.extend(self._detect_asrep_roasting(events))
        alerts.extend(self._detect_sysmon_lsass_access(events))
        return alerts

    def _detect_webshell_activity(self, events: List[NormalizedEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        grouped: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)

        for ev in events:
            if ev.source_type != "apache_access":
                continue
            uri = str(ev.metadata.get("uri", "")).lower()
            if any(ind in uri for ind in WEBSHELL_INDICATORS) or (
                "/uploads/" in uri and uri.endswith(".php")
            ):
                grouped[(ev.host, ev.source_ip or "unknown")].append(ev)

        for (host, src_ip), matched in grouped.items():
            alerts.append(
                Alert(
                    rule_id="LS-RULE-001",
                    title="Web Shell Upload & Execution Detected (DVWA / Unrestricted Upload)",
                    severity="CRITICAL",
                    mitre_tactic="Persistence / Initial Access",
                    mitre_technique="T1505.003 (Server Software Component: Web Shell)",
                    host=host,
                    source_ip=src_ip,
                    target_user="root / www-data",
                    timestamp_first=matched[0].timestamp,
                    timestamp_last=matched[-1].timestamp,
                    event_count=len(matched),
                    description=(
                        f"Detected {len(matched)} HTTP requests indicating upload and execution of a PHP web shell "
                        f"(e.g. backdoor.php) from {src_ip} on {host}."
                    ),
                    evidence=[e.raw_message for e in matched[:5]],
                    remediation=[
                        "Isolate the web server and remove malicious PHP scripts from the uploads directory.",
                        "Ensure Apache is NOT compiled with -DBIG_SECURITY_HOLE and does not run as root.",
                        "Disable PHP execution (php_flag engine off) inside user upload directories.",
                    ],
                    wazuh_rule_equivalent="Wazuh Rule 31106 / 550 (FIM Webshell)",
                )
            )
        return alerts

    def _detect_ssh_bruteforce_and_root_key(self, events: List[NormalizedEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        failures: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)
        successes: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)

        for ev in events:
            if ev.source_type != "linux_auth":
                continue
            key = (ev.host, ev.source_ip or "unknown")
            if ev.event_id == "SSH_AUTH_FAILURE":
                failures[key].append(ev)
            elif ev.event_id == "SSH_AUTH_SUCCESS":
                successes[key].append(ev)

        for (host, src_ip), fail_list in failures.items():
            if len(fail_list) >= self.ssh_threshold:
                succ_list = successes.get((host, src_ip), [])
                compromised = len(succ_list) > 0
                users = sorted({e.user or "unknown" for e in fail_list + succ_list})
                alerts.append(
                    Alert(
                        rule_id="LS-RULE-002",
                        title=(
                            "SSH Brute-Force Followed by Successful Login"
                            if compromised
                            else "SSH Brute-Force Attack Detected"
                        ),
                        severity="CRITICAL" if compromised else "HIGH",
                        mitre_tactic="Credential Access / Initial Access",
                        mitre_technique="T1110.001 (Password Guessing)",
                        host=host,
                        source_ip=src_ip,
                        target_user=", ".join(users),
                        timestamp_first=fail_list[0].timestamp,
                        timestamp_last=(succ_list[-1] if compromised else fail_list[-1]).timestamp,
                        event_count=len(fail_list) + len(succ_list),
                        description=(
                            f"Detected {len(fail_list)} failed SSH login attempts from {src_ip} against {host}"
                            + (
                                f", followed by {len(succ_list)} successful login(s)."
                                if compromised
                                else "."
                            )
                        ),
                        evidence=[e.raw_message for e in (fail_list[:3] + succ_list[:2])],
                        remediation=[
                            "Block the offending source IP via firewall / Fail2ban.",
                            "Audit /root/.ssh/authorized_keys for unauthorized SSH keys (e.g. kali@kali).",
                            "Disable PermitRootLogin in /etc/ssh/sshd_config.",
                        ],
                        wazuh_rule_equivalent="Wazuh Rule 5712 / 5720",
                    )
                )

        # Also check direct root publickey login (persistence via authorized_keys)
        for (host, src_ip), succ_list in successes.items():
            if len(failures.get((host, src_ip), [])) >= self.ssh_threshold:
                continue
            root_pub = [
                e for e in succ_list if e.user == "root" and e.metadata.get("method") == "publickey"
            ]
            if root_pub:
                alerts.append(
                    Alert(
                        rule_id="LS-RULE-002B",
                        title="Direct Root SSH Publickey Login & Potential Reverse Tunneling",
                        severity="HIGH",
                        mitre_tactic="Persistence / Command and Control",
                        mitre_technique="T1098.004 (SSH Authorized Keys) / T1572 (Protocol Tunneling)",
                        host=host,
                        source_ip=src_ip,
                        target_user="root",
                        timestamp_first=root_pub[0].timestamp,
                        timestamp_last=root_pub[-1].timestamp,
                        event_count=len(root_pub),
                        description=(
                            f"Root user authenticated via SSH publickey from {src_ip} on {host}. "
                            "In post-webshell scenarios, this indicates key injection into /root/.ssh/authorized_keys "
                            "and potential sshd -R pivoting into the internal network."
                        ),
                        evidence=[e.raw_message for e in root_pub[:3]],
                        remediation=[
                            "Inspect /root/.ssh/authorized_keys and remove unauthorized keys.",
                            "Set PermitRootLogin no and AllowTcpForwarding no in /etc/ssh/sshd_config.",
                        ],
                        wazuh_rule_equivalent="Wazuh Rule 5715",
                    )
                )
        return alerts

    def _detect_windows_rdp_bruteforce(self, events: List[NormalizedEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        failed_4625: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)
        success_4624: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)

        for ev in events:
            if ev.source_type != "windows_event":
                continue
            key = (ev.host, ev.source_ip or "local")
            if ev.event_id == "4625":
                failed_4625[key].append(ev)
            elif ev.event_id == "4624":
                success_4624[key].append(ev)

        for (host, src_ip), fails in failed_4625.items():
            if len(fails) >= self.rdp_threshold:
                succs = success_4624.get((host, src_ip), [])
                compromised = len(succs) > 0
                users = sorted({e.user or "unknown" for e in fails + succs})
                workstation = fails[0].metadata.get("WorkstationName", "unknown")
                alerts.append(
                    Alert(
                        rule_id="LS-RULE-003",
                        title="Windows RDP/Network Brute-Force Attack (Event ID 4625 -> 4624)",
                        severity="CRITICAL" if compromised else "HIGH",
                        mitre_tactic="Credential Access / Lateral Movement",
                        mitre_technique="T1110.001 (Password Guessing) / T1021.001 (RDP)",
                        host=host,
                        source_ip=src_ip,
                        target_user=", ".join(users),
                        timestamp_first=fails[0].timestamp,
                        timestamp_last=(succs[-1] if compromised else fails[-1]).timestamp,
                        event_count=len(fails) + len(succs),
                        description=(
                            f"Detected {len(fails)} failed Windows logon attempts (Event ID 4625) from {src_ip} "
                            f"(WorkstationName: {workstation}) on {host}"
                            + (
                                f", followed by {len(succs)} successful logon(s) (Event ID 4624)."
                                if compromised
                                else "."
                            )
                        ),
                        evidence=[e.raw_message for e in (fails[:3] + succs[:2])],
                        remediation=[
                            "Enforce Account Lockout Policy in Active Directory GPO.",
                            "Restrict RDP access by IP and require Network Level Authentication (NLA) + MFA.",
                            "Rotate compromised user credentials immediately.",
                        ],
                        wazuh_rule_equivalent="Wazuh Rule 60204 (Multiple Windows Logon Failures)",
                    )
                )
        return alerts

    def _detect_kerberoasting(self, events: List[NormalizedEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        rc4_tickets: List[NormalizedEvent] = []

        for ev in events:
            if ev.source_type == "windows_event" and ev.event_id == "4769":
                enc = str(ev.metadata.get("TicketEncryptionType", "")).lower()
                spn = str(ev.metadata.get("ServiceName", ""))
                if enc in {"0x17", "23"} and not spn.endswith("$"):
                    rc4_tickets.append(ev)

        if rc4_tickets:
            first = rc4_tickets[0]
            alerts.append(
                Alert(
                    rule_id="LS-RULE-004",
                    title="Kerberoasting Attack Detected (RC4-HMAC TGS Request - Event ID 4769)",
                    severity="HIGH",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)",
                    host=first.host,
                    source_ip=first.source_ip or "unknown",
                    target_user=str(first.metadata.get("ServiceName", first.user or "SPN")),
                    timestamp_first=rc4_tickets[0].timestamp,
                    timestamp_last=rc4_tickets[-1].timestamp,
                    event_count=len(rc4_tickets),
                    description=(
                        f"Detected {len(rc4_tickets)} Kerberos TGS ticket request(s) (Event ID 4769) using legacy "
                        "RC4-HMAC encryption (0x17) targeting service accounts for offline cracking."
                    ),
                    evidence=[e.raw_message for e in rc4_tickets[:4]],
                    remediation=[
                        "Migrate service accounts to Group Managed Service Accounts (gMSA) with 240-char passwords.",
                        "Enforce AES128/AES256 Kerberos encryption and disable RC4-HMAC in Domain Policy.",
                    ],
                    wazuh_rule_equivalent="Wazuh Rule 60115 / Custom Kerberoasting Rule",
                )
            )
        return alerts

    def _detect_pass_the_hash(self, events: List[NormalizedEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        pth_events: List[NormalizedEvent] = []

        for ev in events:
            if ev.source_type == "windows_event" and ev.event_id == "4624":
                logon_type = str(ev.metadata.get("LogonType", ""))
                auth_pkg = str(ev.metadata.get("AuthenticationPackageName", "")).upper()
                logon_proc = str(ev.metadata.get("LogonProcessName", "")).strip()
                key_len = str(ev.metadata.get("KeyLength", ""))

                if (
                    logon_type in {"3", "9"}
                    and "NTLM" in auth_pkg
                    and logon_proc.lower() == "ntlmssp"
                    and key_len == "0"
                ):
                    pth_events.append(ev)

        if pth_events:
            first = pth_events[0]
            alerts.append(
                Alert(
                    rule_id="LS-RULE-005",
                    title="Pass-the-Hash (PtH) Lateral Movement Detected (Event ID 4624 NTLM)",
                    severity="CRITICAL",
                    mitre_tactic="Lateral Movement / Defense Evasion",
                    mitre_technique="T1550.002 (Use Alternate Authentication Material: Pass the Hash)",
                    host=first.host,
                    source_ip=first.source_ip or "unknown",
                    target_user=first.user or "domainadmin",
                    timestamp_first=pth_events[0].timestamp,
                    timestamp_last=pth_events[-1].timestamp,
                    event_count=len(pth_events),
                    description=(
                        f"Detected {len(pth_events)} NTLM network logon(s) (LogonType 3, NtLmSsp, KeyLength=0) "
                        f"to {first.host} as '{first.user}' from {first.source_ip}, characteristic of Pass-the-Hash."
                    ),
                    evidence=[e.raw_message for e in pth_events[:4]],
                    remediation=[
                        "Add privileged accounts to the Active Directory 'Protected Users' security group.",
                        "Enable Windows Defender Credential Guard (LSA Protection / RunAsPPL) on all domain hosts.",
                        "Reset KRBTGT and privileged domain account passwords twice.",
                    ],
                    wazuh_rule_equivalent="Wazuh Rule 92652 (Pass-the-Hash Activity)",
                )
            )
        return alerts

    def _detect_defense_evasion_and_wer(self, events: List[NormalizedEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        tampering: List[NormalizedEvent] = []
        wer_crashes: List[NormalizedEvent] = []

        for ev in events:
            if ev.event_id in {"5001", "5007", "WAZUH_AGENT_STOPPED"}:
                tampering.append(ev)
            elif ev.event_id == "1001" and "cve-" in ev.raw_message.lower():
                wer_crashes.append(ev)

        if tampering:
            first = tampering[0]
            alerts.append(
                Alert(
                    rule_id="LS-RULE-006",
                    title="Security Monitoring / Windows Defender Tampering Detected",
                    severity="CRITICAL",
                    mitre_tactic="Defense Evasion",
                    mitre_technique="T1562.001 (Impair Defenses: Disable or Modify Tools)",
                    host=first.host,
                    source_ip=first.source_ip or "local",
                    target_user=first.user or "SYSTEM",
                    timestamp_first=tampering[0].timestamp,
                    timestamp_last=tampering[-1].timestamp,
                    event_count=len(tampering),
                    description=(
                        "Detected disabling of Microsoft Defender Real-Time Protection (Event ID 5001/5007) "
                        "and/or termination of the Wazuh SIEM agent service."
                    ),
                    evidence=[e.raw_message for e in tampering],
                    remediation=[
                        "Enable Tamper Protection in Microsoft Defender and enforce settings via GPO.",
                        "Configure immediate high-priority SOC escalation on Wazuh Rule 506 (Agent stopped).",
                    ],
                    wazuh_rule_equivalent="Wazuh Rule 62152 / Rule 506",
                )
            )

        if wer_crashes:
            first = wer_crashes[0]
            alerts.append(
                Alert(
                    rule_id="LS-RULE-007",
                    title="Forensic Artifact: Deleted LPE Exploit Detected via WER AppCrash",
                    severity="HIGH",
                    mitre_tactic="Privilege Escalation / Defense Evasion",
                    mitre_technique="T1068 (Exploitation for Privilege Escalation) / T1070.004 (File Deletion)",
                    host=first.host,
                    source_ip=first.source_ip or "local",
                    target_user=first.user or "user1",
                    timestamp_first=wer_crashes[0].timestamp,
                    timestamp_last=wer_crashes[-1].timestamp,
                    event_count=len(wer_crashes),
                    description=(
                        "Windows Error Reporting (WER Event ID 1001) recorded an application crash matching "
                        "a known privilege escalation exploit (e.g. CVE-2019-0623.exe), proving execution even "
                        "if the attacker subsequently deleted the binary."
                    ),
                    evidence=[e.raw_message for e in wer_crashes],
                    remediation=[
                        "Preserve C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\ for forensic analysis.",
                        "Apply cumulative Windows kernel security updates (Win32k LPE patches).",
                    ],
                    wazuh_rule_equivalent="Forensic WER Artifact Correlation",
                )
            )
        return alerts

    def _detect_malware_and_tsclient(self, events: List[NormalizedEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        detections: List[NormalizedEvent] = []

        for ev in events:
            if ev.source_type == "windows_event" and ev.event_id in {"1116", "1117"}:
                detections.append(ev)

        if detections:
            first = detections[0]
            has_tsclient = any("\\\\tsclient" in e.raw_message.lower() for e in detections)
            alerts.append(
                Alert(
                    rule_id="LS-RULE-008",
                    title=(
                        "Malware / Mimikatz Execution via Redirected RDP Drive (\\\\tsclient)"
                        if has_tsclient
                        else "Endpoint Malware / HackTool Detection (Event ID 1116/1117)"
                    ),
                    severity="CRITICAL",
                    mitre_tactic="Credential Access / Execution",
                    mitre_technique="T1003.001 (LSASS Memory) / T1021.001 (RDP Drive Redirection)",
                    host=first.host,
                    source_ip=first.source_ip or "local",
                    target_user=first.user or "SYSTEM",
                    timestamp_first=detections[0].timestamp,
                    timestamp_last=detections[-1].timestamp,
                    event_count=len(detections),
                    description=(
                        f"Microsoft Defender logged {len(detections)} malware/hacktool detection(s) "
                        "(including HackTool:Win32/Mimikatz.D and Trojan:Win32/Sabsik.TE.A!ml). "
                        + (
                            "UNC path analysis reveals execution directly from an attacker-mounted RDP shared drive "
                            "(\\\\tsclient\\...), exposing the attacker host filesystem."
                            if has_tsclient
                            else ""
                        )
                    ),
                    evidence=[e.raw_message for e in detections],
                    remediation=[
                        "Disable RDP Drive Redirection via GPO (Do not allow drive redirection).",
                        "Isolate affected workstation and rotate all domain credentials cached in LSASS.",
                    ],
                    wazuh_rule_equivalent="Wazuh Rule 62123 / Defender Malware Alert",
                )
            )
        return alerts

    def _detect_asrep_roasting(self, events: List[NormalizedEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        suspicious: List[NormalizedEvent] = []

        for ev in events:
            if ev.source_type == "windows_event" and ev.event_id == "4768":
                enc = str(ev.metadata.get("TicketEncryptionType", "")).lower()
                pre_auth = str(ev.metadata.get("PreAuthType", "")).strip()
                if (enc in {"0x17", "23"} and pre_auth in {"0", "-", ""}) or (
                    "0x17" in ev.raw_message.lower() and "preauthtype: 0" in ev.raw_message.lower()
                ):
                    suspicious.append(ev)

        if suspicious:
            first = suspicious[0]
            target_acct = str(first.metadata.get("TargetUserName", first.user or "unknown"))
            alerts.append(
                Alert(
                    rule_id="LS-RULE-009",
                    title="Kerberos AS-REP Roasting Detected (Event ID 4768 PreAuthType 0 / RC4-HMAC)",
                    severity="HIGH",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1558.004 (Steal or Forge Kerberos Tickets: AS-REP Roasting)",
                    host=first.host,
                    source_ip=first.source_ip or "unknown",
                    target_user=target_acct,
                    timestamp_first=suspicious[0].timestamp,
                    timestamp_last=suspicious[-1].timestamp,
                    event_count=len(suspicious),
                    description=(
                        f"Detected {len(suspicious)} Kerberos TGT request(s) (Event ID 4768) without pre-authentication "
                        f"(PreAuthType=0) using weak RC4-HMAC encryption (0x17) for account '{target_acct}' "
                        f"from {first.source_ip}, indicating an AS-REP Roasting attack (e.g. GetNPUsers.py / Rubeus)."
                    ),
                    evidence=[e.raw_message for e in suspicious[:4]],
                    remediation=[
                        "Enforce Kerberos Pre-Authentication on all AD accounts (clear 'Do not require Kerberos preauthentication').",
                        "Audit domain accounts via: Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' and rotate passwords (25+ chars).",
                        "Disable RC4-HMAC (0x17) in favor of AES256-CTS-HMAC-SHA1-96 across Active Directory.",
                    ],
                    wazuh_rule_equivalent="Wazuh Rule 60116 / Custom AS-REP Roast Detection",
                )
            )
        return alerts

    def _detect_sysmon_lsass_access(self, events: List[NormalizedEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        lsass_hits: List[NormalizedEvent] = []
        suspicious_masks = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x01000", "0x1038"}

        for ev in events:
            if ev.source_type == "windows_event" and ev.event_id == "10":
                target_img = str(ev.metadata.get("TargetImage", "")).lower()
                granted = str(ev.metadata.get("GrantedAccess", "")).lower()
                raw_lower = ev.raw_message.lower()
                if "lsass.exe" in target_img or "lsass.exe" in raw_lower:
                    if not granted or granted in suspicious_masks or any(m in raw_lower for m in suspicious_masks):
                        lsass_hits.append(ev)

        if lsass_hits:
            first = lsass_hits[0]
            src_img = str(first.metadata.get("SourceImage", "unknown_process"))
            granted_mask = str(first.metadata.get("GrantedAccess", "0x1010"))
            alerts.append(
                Alert(
                    rule_id="LS-RULE-010",
                    title="Sysmon LSASS Memory Credential Dumping Detected (Sysmon Event ID 10)",
                    severity="CRITICAL",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1003.001 (OS Credential Dumping: LSASS Memory)",
                    host=first.host,
                    source_ip=first.source_ip or "local",
                    target_user=first.user or "SYSTEM",
                    timestamp_first=lsass_hits[0].timestamp,
                    timestamp_last=lsass_hits[-1].timestamp,
                    event_count=len(lsass_hits),
                    description=(
                        f"Sysmon Event ID 10 (ProcessAccess) recorded process '{src_img}' opening a handle "
                        f"to C:\\Windows\\System32\\lsass.exe with GrantedAccess={granted_mask} "
                        "(PROCESS_VM_READ), directly confirming in-memory credential dumping (Mimikatz sekurlsa::logonpasswords)."
                    ),
                    evidence=[e.raw_message for e in lsass_hits[:4]],
                    remediation=[
                        "Enable LSA Protection (RunAsPPL=1 in HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa) and Credential Guard.",
                        "Enable Microsoft Defender ASR rule 'Block credential stealing from the Windows local security authority subsystem (lsass.exe)'.",
                        "Isolate host immediately and revoke all active Kerberos TGTs / NTLM sessions cached on the endpoint.",
                    ],
                    wazuh_rule_equivalent="Wazuh Rule 92910 (Sysmon Event 10: Process Accessed lsass.exe)",
                )
            )
        return alerts

