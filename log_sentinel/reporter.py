"""Report generators (JSON, Console, and Interactive SOC HTML Dashboard) for Log Sentinel."""

import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from .models import Alert, NormalizedEvent


def generate_json_report(events: List[NormalizedEvent], alerts: List[Alert]) -> Dict[str, Any]:
    """Build structured JSON incident triage report."""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1

    return {
        "tool": "Log Sentinel",
        "version": "1.3.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_events_parsed": len(events),
            "total_alerts_triggered": len(alerts),
            "severity_breakdown": severity_counts,
        },
        "alerts": [a.to_dict() for a in alerts],
    }


def format_console_summary(events: List[NormalizedEvent], alerts: List[Alert]) -> str:
    """Render a clean CLI triage summary."""
    lines = [
        "=" * 78,
        "🔍 LOG SENTINEL v1.3.0 — SOC L1/L2 THREAT DETECTION & TRIAGE REPORT",
        "=" * 78,
        f"Total Normalized Events Parsed : {len(events)}",
        f"Total Correlated Alerts Fired  : {len(alerts)}",
        "-" * 78,
    ]
    for idx, alert in enumerate(alerts, 1):
        lines.extend(
            [
                f"[{idx}] [{alert.severity}] {alert.rule_id}: {alert.title}",
                f"    Host / Source IP : {alert.host} <- {alert.source_ip} (User: {alert.target_user})",
                f"    MITRE ATT&CK     : {alert.mitre_tactic} | {alert.mitre_technique}",
                f"    Wazuh Equivalent : {alert.wazuh_rule_equivalent or 'N/A'}",
                f"    Time Window      : {alert.timestamp_first} -> {alert.timestamp_last} ({alert.event_count} events)",
                f"    Summary          : {alert.description}",
                "-" * 78,
            ]
        )
    return "\n".join(lines)


def generate_html_dashboard(events: List[NormalizedEvent], alerts: List[Alert]) -> str:
    """Generate a standalone Dark-Mode SOC L1/L2 Interactive HTML Dashboard."""
    crit_count = sum(1 for a in alerts if a.severity == "CRITICAL")
    high_count = sum(1 for a in alerts if a.severity == "HIGH")
    hosts = sorted({e.host for e in events})

    cards_html = []
    for alert in alerts:
        badge_class = "badge-critical" if alert.severity == "CRITICAL" else "badge-high"
        evidence_items = "".join(
            f"<li><code>{html.escape(ev)}</code></li>" for ev in alert.evidence
        )
        rem_items = "".join(f"<li>{html.escape(r)}</li>" for r in alert.remediation)
        cards_html.append(
            f"""
            <div class="alert-card" data-severity="{html.escape(alert.severity)}">
              <div class="alert-header">
                <div>
                  <span class="rule-id">{html.escape(alert.rule_id)}</span>
                  <span class="badge {badge_class}">{html.escape(alert.severity)}</span>
                  <span class="wazuh-tag">{html.escape(alert.wazuh_rule_equivalent or '')}</span>
                </div>
                <span class="time-range">{html.escape(alert.timestamp_first)} &rarr; {html.escape(alert.timestamp_last)}</span>
              </div>
              <h3>{html.escape(alert.title)}</h3>
              <p class="desc">{html.escape(alert.description)}</p>
              <div class="meta-grid">
                <div><strong>Affected Host:</strong> <code>{html.escape(alert.host)}</code></div>
                <div><strong>Source IP:</strong> <code>{html.escape(alert.source_ip)}</code></div>
                <div><strong>Target Account:</strong> <code>{html.escape(alert.target_user)}</code></div>
                <div><strong>Correlated Events:</strong> <code>{alert.event_count}</code></div>
                <div class="span-2"><strong>MITRE ATT&amp;CK:</strong> <span class="mitre">{html.escape(alert.mitre_tactic)} &bull; {html.escape(alert.mitre_technique)}</span></div>
              </div>
              <details>
                <summary>📂 View Forensic Log Evidence ({len(alert.evidence)} samples) &amp; Remediation Playbook</summary>
                <div class="details-body">
                  <h4>Forensic Log Evidence:</h4>
                  <ul class="evidence-list">{evidence_items}</ul>
                  <h4>SOC L1/L2 Remediation Playbook:</h4>
                  <ul class="rem-list">{rem_items}</ul>
                </div>
              </details>
            </div>
            """
        )

    cards_joined = "\n".join(cards_html)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Log Sentinel — SOC L1/L2 Threat Triage Dashboard</title>
  <style>
    :root {{
      --bg: #0b0f19;
      --card: #111827;
      --border: #1f2937;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --accent: #38bdf8;
      --crit: #ef4444;
      --high: #f59e0b;
      --ok: #10b981;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem 1rem;
    }}
    .container {{ max-width: 1120px; margin: 0 auto; }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 1rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
    }}
    h1 {{ font-size: 1.85rem; color: #fff; display: flex; align-items: center; gap: 0.6rem; }}
    .subtitle {{ color: var(--muted); font-size: 0.95rem; margin-top: 0.3rem; }}
    .links a {{
      display: inline-block;
      text-decoration: none;
      color: var(--accent);
      border: 1px solid rgba(56, 189, 248, 0.35);
      padding: 0.45rem 0.9rem;
      border-radius: 6px;
      font-size: 0.85rem;
      margin-left: 0.5rem;
    }}
    .links a:hover {{ background: rgba(56, 189, 248, 0.12); }}
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .stat-card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.25rem;
    }}
    .stat-label {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }}
    .stat-value {{ font-size: 2rem; font-weight: 700; margin-top: 0.25rem; }}
    .val-crit {{ color: var(--crit); }}
    .val-high {{ color: var(--high); }}
    .val-accent {{ color: var(--accent); }}
    .val-ok {{ color: var(--ok); }}
    .filter-bar {{
      display: flex;
      gap: 0.5rem;
      margin-bottom: 1.25rem;
      flex-wrap: wrap;
    }}
    .filter-btn {{
      background: var(--card);
      color: var(--text);
      border: 1px solid var(--border);
      padding: 0.4rem 0.9rem;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.85rem;
    }}
    .filter-btn.active {{ border-color: var(--accent); color: var(--accent); background: rgba(56, 189, 248, 0.1); }}
    .alert-card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-left: 4px solid var(--crit);
      border-radius: 10px;
      padding: 1.35rem;
      margin-bottom: 1.15rem;
    }}
    .alert-card[data-severity="HIGH"] {{ border-left-color: var(--high); }}
    .alert-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-bottom: 0.65rem;
    }}
    .rule-id {{ font-family: monospace; font-weight: 700; color: var(--accent); margin-right: 0.5rem; }}
    .badge {{
      font-size: 0.72rem;
      font-weight: 700;
      padding: 0.18rem 0.55rem;
      border-radius: 4px;
      text-transform: uppercase;
    }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4); }}
    .badge-high {{ background: rgba(245, 158, 11, 0.2); color: #fcd34d; border: 1px solid rgba(245, 158, 11, 0.4); }}
    .wazuh-tag {{
      font-size: 0.75rem;
      color: var(--muted);
      background: #1f2937;
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      margin-left: 0.4rem;
    }}
    .time-range {{ font-size: 0.8rem; color: var(--muted); font-family: monospace; }}
    h3 {{ font-size: 1.15rem; color: #fff; margin-bottom: 0.4rem; }}
    .desc {{ color: #d1d5db; font-size: 0.93rem; margin-bottom: 0.9rem; }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 0.5rem;
      background: rgba(15, 23, 42, 0.65);
      padding: 0.85rem;
      border-radius: 8px;
      font-size: 0.85rem;
      margin-bottom: 0.85rem;
    }}
    .span-2 {{ grid-column: 1 / -1; }}
    .mitre {{ color: #93c5fd; font-weight: 600; }}
    code {{ font-family: Consolas, monospace; color: #f3f4f6; background: rgba(255,255,255,0.06); padding: 0.1rem 0.35rem; border-radius: 4px; }}
    details summary {{
      cursor: pointer;
      color: var(--accent);
      font-size: 0.88rem;
      font-weight: 600;
      user-select: none;
    }}
    .details-body {{
      margin-top: 0.8rem;
      padding-top: 0.8rem;
      border-top: 1px solid var(--border);
      font-size: 0.85rem;
    }}
    .details-body h4 {{ color: #fff; margin: 0.5rem 0 0.35rem; }}
    .evidence-list, .rem-list {{ padding-left: 1.25rem; margin-bottom: 0.6rem; }}
    .evidence-list li {{ margin-bottom: 0.35rem; word-break: break-all; }}
    footer {{
      text-align: center;
      color: var(--muted);
      font-size: 0.85rem;
      margin-top: 2.5rem;
      padding-top: 1.5rem;
      border-top: 1px solid var(--border);
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>🔍 Log Sentinel v1.3.0</h1>
        <p class="subtitle">Zero-Dependency Python Threat Detection &amp; SOC L1/L2 Incident Triage Engine &bull; Case Study: <code>acme.skb</code> Compromise</p>
      </div>
      <div class="links">
        <a href="https://voobrazhenie21-lab.github.io/">🏠 Сайт-визитка / Portfolio</a>
        <a href="https://github.com/Voobrazhenie21-lab/log-sentinel">GitHub Repo</a>
        <a href="https://github.com/Voobrazhenie21-lab/blue-team-incident-investigation">Full DFIR Report</a>
      </div>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Normalized Events Parsed</div>
        <div class="stat-value val-accent">{len(events)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Correlated SOC Alerts</div>
        <div class="stat-value val-ok">{len(alerts)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Critical Severity</div>
        <div class="stat-value val-crit">{crit_count}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">High Severity</div>
        <div class="stat-value val-high">{high_count}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Monitored Hosts</div>
        <div class="stat-value" style="font-size:1.15rem; margin-top:0.65rem;">{html.escape(", ".join(hosts))}</div>
      </div>
    </div>

    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterAlerts('ALL', this)">All Alerts ({len(alerts)})</button>
      <button class="filter-btn" onclick="filterAlerts('CRITICAL', this)">Critical ({crit_count})</button>
      <button class="filter-btn" onclick="filterAlerts('HIGH', this)">High ({high_count})</button>
    </div>

    <div id="alerts-container">
      {cards_joined}
    </div>

    <footer>
      Built by <strong>Aleksei Zharkou</strong> &bull; Zero-Dependency Python Standard Library &bull; MITRE ATT&amp;CK &amp; Wazuh SIEM Mapped
    </footer>
  </div>
  <script>
    function filterAlerts(sev, btn) {{
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.alert-card').forEach(card => {{
        if (sev === 'ALL' || card.dataset.severity === sev) {{
          card.style.display = 'block';
        }} else {{
          card.style.display = 'none';
        }}
      }});
    }}
  </script>
</body>
</html>
"""
