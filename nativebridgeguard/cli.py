from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .diffing import semantic_diff
from .monitor import _default_state_dir, run_monitor_cycle
from .report import render_diff, render_snapshot
from .scanner import scan
from .util import read_json, write_json


def _require_windows() -> None:
    if os.name != "nt":
        raise SystemExit("Live scan currently supports Windows only. Diff/report commands are cross-platform.")


def cmd_scan(args: argparse.Namespace) -> int:
    _require_windows()
    snap = scan().to_dict()
    if args.output:
        write_json(args.output, snap)
        print(f"Snapshot written: {args.output}")
    if args.report:
        Path(args.report).write_text(render_snapshot(snap), encoding="utf-8")
        print(f"Report written: {args.report}")
    if not args.output and not args.report:
        print(json.dumps(snap, ensure_ascii=False, indent=2))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    snap = read_json(args.snapshot)
    text = render_snapshot(snap)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    before = read_json(args.before)
    after = read_json(args.after)
    changes = semantic_diff(before, after)
    if args.json:
        text = json.dumps(changes, ensure_ascii=False, indent=2)
    else:
        text = render_diff(changes)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nativebridgeguard", description="Audit effective Chromium Native Messaging trust paths on Windows.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Collect a live Windows snapshot.")
    s.add_argument("--output", help="Write snapshot JSON.")
    s.add_argument("--report", help="Write Markdown report.")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("report", help="Render a Markdown report from a snapshot JSON file.")
    r.add_argument("snapshot")
    r.add_argument("--output")
    r.set_defaults(func=cmd_report)

    d = sub.add_parser("diff", help="Compare two snapshots using semantic trust-drift rules.")
    d.add_argument("before")
    d.add_argument("after")
    d.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")
    d.add_argument("--output")
    d.set_defaults(func=cmd_diff)

    m = sub.add_parser("monitor", help="Run one stateful trust-drift monitor cycle, then exit.")
    m.add_argument("--state-dir", default=None,
                   help="Monitor state directory (default: %%LOCALAPPDATA%%\\NativeBridgeGuard).")
    m.add_argument("--events", default=None, help="NDJSON events file (default: <state-dir>/events.ndjson).")
    m.add_argument("--alert-report", default=None, help="Markdown alert file (default: <state-dir>/alert.md).")
    m.set_defaults(func=cmd_monitor)
    return p


def cmd_monitor(args: argparse.Namespace) -> int:
    state_dir = args.state_dir or _default_state_dir()
    return run_monitor_cycle(state_dir, events_path=args.events, alert_path=args.alert_report)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
