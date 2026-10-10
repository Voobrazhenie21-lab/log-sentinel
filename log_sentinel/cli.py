"""Command-Line Interface for Log Sentinel."""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .engine import DetectionEngine
from .parsers import load_events_from_path
from .reporter import (
    format_console_summary,
    generate_html_dashboard,
    generate_json_report,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-sentinel",
        description="Log Sentinel — Python Threat Detection & SOC L1/L2 Incident Triage CLI",
    )
    sub = parser.add_subparsers(dest="command")

    analyze_p = sub.add_parser("analyze", help="Analyze log files or directories")
    analyze_p.add_argument(
        "target",
        type=Path,
        help="Path to log file or directory containing Linux/Web/Windows logs",
    )
    analyze_p.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path to export structured JSON alert report",
    )
    analyze_p.add_argument(
        "--html-out",
        type=Path,
        default=None,
        help="Optional path to export interactive HTML SOC dashboard",
    )
    analyze_p.add_argument(
        "--ssh-threshold",
        type=int,
        default=4,
        help="Minimum failed SSH attempts to trigger brute-force alert (default: 4)",
    )
    analyze_p.add_argument(
        "--rdp-threshold",
        type=int,
        default=5,
        help="Minimum failed Windows 4625 attempts to trigger brute-force alert (default: 5)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "analyze":
        parser.print_help()
        return 0

    if not args.target.exists():
        print(f"[!] Error: Target path '{args.target}' does not exist.", file=sys.stderr)
        return 1

    events = load_events_from_path(args.target)
    engine = DetectionEngine(
        ssh_threshold=args.ssh_threshold,
        rdp_threshold=args.rdp_threshold,
    )
    alerts = engine.analyze(events)

    print(format_console_summary(events, alerts))

    if args.json_out:
        report_data = generate_json_report(events, alerts)
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(report_data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"[+] JSON report saved to: {args.json_out}")

    if args.html_out:
        html_doc = generate_html_dashboard(events, alerts)
        args.html_out.parent.mkdir(parents=True, exist_ok=True)
        args.html_out.write_text(html_doc, encoding="utf-8")
        print(f"[+] Interactive HTML dashboard saved to: {args.html_out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
