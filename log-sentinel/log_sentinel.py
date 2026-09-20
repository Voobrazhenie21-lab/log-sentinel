#!/usr/bin/env python3
"""
Log Sentinel — детектор атак на учётные данные по логам.

Анализирует:
  • Linux auth.log   — SSH-брутфорс и успешный вход после брутфорса;
  • Windows Security — брутфорс и password spraying (событие 4625),
                       признаки Kerberoasting (событие 4769 с RC4).

Использование:
    python log_sentinel.py --auth-log samples/auth.log \
                           --win-events samples/security_events.csv \
                           --json report.json

Требования: Python 3.9+, только стандартная библиотека.
Автор: Aleksei Zharkou (github.com/Voobrazhenie21-lab)
"""

import argparse
import csv
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path

# --- Пороги детектов (можно крутить под свой стенд) ---
BRUTE_FORCE_THRESHOLD = 10      # неудачных попыток с одного IP
SPRAY_USER_THRESHOLD = 5        # разных учёток с одного IP (password spraying)
KERBEROAST_RC4 = "0x17"         # тип шифрования RC4-HMAC в событии 4769


@dataclass
class Alert:
    """Одно обнаруженное событие безопасности."""
    rule: str
    severity: str                 # LOW / MEDIUM / HIGH / CRITICAL
    title: str
    evidence: list = field(default=list)
    recommendation: str = ""

    def to_dict(self):
        return asdict(self)


# =====================================================================
# Linux auth.log
# =====================================================================

RE_SSH_FAILED = re.compile(
    r"(?P<ts>\w{3}\s+\d+ [\d:]+).*Failed password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
RE_SSH_ACCEPTED = re.compile(
    r"(?P<ts>\w{3}\s+\d+ [\d:]+).*Accepted password for (?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def analyze_auth_log(path: Path) -> list:
    """Ищет SSH-брутфорс и успешный вход с атакующего IP."""
    alerts = []
    failed_by_ip = defaultdict(list)   # ip -> [(ts, user), ...]
    accepted = []                      # [(ts, user, ip), ...]

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = RE_SSH_FAILED.search(line)
        if m:
            failed_by_ip[m["ip"]].append((m["ts"], m["user"]))
            continue
        m = RE_SSH_ACCEPTED.search(line)
        if m:
            accepted.append((m["ts"], m["user"], m["ip"]))

    for ip, attempts in failed_by_ip.items():
        if len(attempts) >= BRUTE_FORCE_THRESHOLD:
            users = sorted({u for _, u in attempts})
            alerts.append(Alert(
                rule="ssh-brute-force",
                severity="HIGH",
                title=f"SSH-брутфорс с {ip}: {len(attempts)} неудачных попыток",
                evidence=[f"{ts} — пользователь «{u}»" for ts, u in attempts[:10]],
                recommendation=("Заблокировать IP на фаерволе / в Fail2ban, "
                                "проверить отсутствие успешных входов с этого адреса."),
            ))

    attacking_ips = {ip for ip, a in failed_by_ip.items()
                     if len(a) >= BRUTE_FORCE_THRESHOLD}
    for ts, user, ip in accepted:
        if ip in attacking_ips:
            alerts.append(Alert(
                rule="ssh-brute-force-success",
                severity="CRITICAL",
                title=f"ВОЗМОЖНАЯ КОМПРОМЕТАЦИЯ: успешный вход «{user}» "
                      f"с атакующего {ip} ({ts})",
                evidence=[f"{ts} — Accepted password for {user} from {ip}"],
                recommendation=("Немедленно сбросить пароль учётной записи, "
                                "проверить сессии и следы постэксплуатации на хосте."),
            ))

    return alerts


# =====================================================================
# Windows Security (экспорт в CSV: EventID, TimeCreated, TargetUserName,
# IpAddress, ServiceName, TicketEncryptionType)
# =====================================================================

def analyze_windows_events(path: Path) -> list:
    """Ищет брутфорс, password spraying (4625) и Kerberoasting (4769)."""
    alerts = []
    fail_by_ip = defaultdict(set)        # ip -> {user, ...}
    fail_by_user = defaultdict(int)      # user -> count
    tgs_rc4 = []

    with path.open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            event_id = row.get("EventID", "").strip()
            if event_id == "4625":  # неудачный вход
                user = row.get("TargetUserName", "").strip()
                ip = row.get("IpAddress", "").strip() or "unknown"
                fail_by_ip[ip].add(user)
                fail_by_user[user] += 1
            elif event_id == "4769":  # запрос TGS
                if (row.get("TicketEncryptionType", "").strip() == KERBEROAST_RC4
                        and not row.get("ServiceName", "").strip().endswith("$")):
                    tgs_rc4.append(row)

    for ip, users in fail_by_ip.items():
        if len(users) >= SPRAY_USER_THRESHOLD:
            alerts.append(Alert(
                rule="password-spraying",
                severity="HIGH",
                title=f"Password spraying с {ip}: подбор к {len(users)} учётным записям",
                evidence=[f"Целевые учётки: {', '.join(sorted(users))}"],
                recommendation=("Проверить политику блокировки, расследовать источник, "
                                "принудительно сменить пароли затронутых учёток."),
            ))

    for user, count in fail_by_user.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alerts.append(Alert(
                rule="account-brute-force",
                severity="MEDIUM",
                title=f"Брутфорс учётной записи «{user}»: {count} неудачных входов (4625)",
                evidence=[f"EventID 4625 × {count}"],
                recommendation="Проверить блокировку учётной записи и источник попыток.",
            ))

    if tgs_rc4:
        services = sorted({r.get("ServiceName", "?") for r in tgs_rc4})
        alerts.append(Alert(
            rule="kerberoasting",
            severity="HIGH",
            title=f"Признаки Kerberoasting: {len(tgs_rc4)} TGS с RC4 (событие 4769)",
            evidence=[f"Сервисные учётки: {', '.join(services)}"],
            recommendation=("Проверить, кто запрашивал билеты; сменить пароли сервисных "
                            "учёток; перевести их на AES (msDS-SupportedEncryptionTypes)."),
        ))

    return alerts


# =====================================================================
# Отчёт
# =====================================================================

def print_report(alerts: list) -> None:
    if not alerts:
        print("\n[OK] Подозрительной активности не обнаружено.\n")
        return
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    alerts.sort(key=lambda a: order.get(a.severity, 9))
    print(f"\n{'=' * 64}\nОТЧЁТ LOG SENTINEL — обнаружено алертов: {len(alerts)}\n{'=' * 64}")
    for i, a in enumerate(alerts, 1):
        print(f"\n[{i}] ({a.severity}) {a.title}")
        print(f"    Правило: {a.rule}")
        for ev in a.evidence:
            print(f"    • {ev}")
        print(f"    Рекомендация: {a.recommendation}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Log Sentinel — детектор атак по логам")
    parser.add_argument("--auth-log", type=Path, help="Путь к Linux auth.log")
    parser.add_argument("--win-events", type=Path, help="CSV с событиями Windows Security")
    parser.add_argument("--json", type=Path, help="Сохранить отчёт в JSON")
    args = parser.parse_args()

    if not args.auth_log and not args.win_events:
        parser.error("укажите хотя бы один источник: --auth-log и/или --win-events")

    alerts = []
    if args.auth_log:
        alerts += analyze_auth_log(args.auth_log)
    if args.win_events:
        alerts += analyze_windows_events(args.win_events)

    print_report(alerts)

    if args.json:
        args.json.write_text(
            json.dumps([a.to_dict() for a in alerts], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"Отчёт сохранён: {args.json}")


if __name__ == "__main__":
    main()
