from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .diffing import semantic_diff
from .events import changes_to_events
from .models import Event, Snapshot
from .report import render_events_md
from .scanner import scan
from .util import read_json, write_json

SNAPSHOT_NAME = "snapshot.json"
EVENTS_NAME = "events.ndjson"
ALERT_NAME = "alert.md"
META_NAME = "meta.json"

# Exit codes
RC_OK = 0
RC_DEGRADED = 2


def _default_state_dir() -> str:
    """Default monitor state location: %LOCALAPPDATA%\\NativeBridgeGuard."""
    local = os.environ.get("LOCALAPPDATA")
    if local:
        return str(Path(local) / "NativeBridgeGuard")
    return str(Path.home() / ".nbg")


def _read_initialized_at(meta_path: str) -> str | None:
    try:
        return read_json(meta_path).get("initialized_at")
    except Exception:
        return None


def _append_events(path: str, events: list[Event]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e.to_dict(), ensure_ascii=False) + "\n")


def _short_alert(now: str) -> str:
    return (
        "# NativeBridgeGuard Monitor\n\n"
        "No new trust-drift events in this cycle.\n\n"
        f"Generated: `{now}`\n"
    )


def _write_degraded_alert(alert_path: str, now: str, prev_exists: bool) -> None:
    preserved = "preserved" if prev_exists else "not yet initialised"
    msg = (
        "# NativeBridgeGuard Monitor\n\n"
        "Collection degraded this cycle: one or more collectors failed. "
        f"The good baseline was {preserved}. No security drift events were "
        "emitted, and the baseline was NOT overwritten with incomplete data.\n\n"
        f"Generated: `{now}`\n"
    )
    Path(alert_path).parent.mkdir(parents=True, exist_ok=True)
    Path(alert_path).write_text(msg, encoding="utf-8")


def _detect_correlations(changes: list[dict[str, Any]], timestamp: str) -> list[Event]:
    """NBG102: compound trust-boundary expansion.

    This is a *temporal* correlation: effective_registration_changed AND
    trust_surface_expanded for the same trust_key within the same monitor cycle.
    It is intentionally produced here (monitor/diff layer) rather than forced
    into the static rules engine, which only sees a single snapshot.
    """
    by_key: dict[str, set[str]] = {}
    for c in changes:
        by_key.setdefault(c.get("key", ""), set()).add(c.get("type"))

    out: list[Event] = []
    for key, types in by_key.items():
        if "effective_registration_changed" in types and "trust_surface_expanded" in types:
            out.append(Event(
                schema_version=1,
                timestamp=timestamp,
                event_type="compound_trust_boundary_expansion",
                severity="high",
                trust_key=key,
                summary=(
                    "Effective registration changed AND authorization surface expanded "
                    "in the same cycle (compound trust-boundary expansion, NBG102)."
                ),
                before=None,
                after=None,
                evidence=["effective_registration_changed", "trust_surface_expanded"],
            ))
    return out


def run_monitor_cycle(
    state_dir: str,
    events_path: str | None = None,
    alert_path: str | None = None,
    scan_fn: Callable[[], Snapshot] = scan,
) -> int:
    """Run exactly one monitor cycle, then exit.

    The monitor is intentionally NOT a long-running daemon. Windows Task
    Scheduler is responsible for invoking it on a schedule; each invocation
    performs a single scan -> diff -> emit cycle and returns.

    Drift-duplication guard: after every healthy cycle, the current snapshot
    replaces the previous one. A one-time drift is reported exactly once and a
    stable environment yields zero new events on subsequent runs.

    Degraded-collection guard: if the current scan reports collector failures
    (collection_errors is non-empty), the cycle is treated as incomplete. No
    semantic diff, no security drift events, and — critically — the good baseline
    is NOT overwritten with incomplete data, nor is a degraded scan initialised
    as the first baseline. This prevents "collector failed" from being silently
    interpreted as "no change" or from manufacturing false trust_path_removed
    events. The cycle returns RC_DEGRADED (2).
    """
    state_dir = str(state_dir)
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    events_path = events_path or str(Path(state_dir) / EVENTS_NAME)
    alert_path = alert_path or str(Path(state_dir) / ALERT_NAME)
    snapshot_path = str(Path(state_dir) / SNAPSHOT_NAME)
    meta_path = str(Path(state_dir) / META_NAME)

    current = scan_fn().to_dict()
    now = datetime.now(timezone.utc).isoformat()
    errors = current.get("collection_errors") or []
    degraded = bool(errors)
    prev_exists = os.path.exists(snapshot_path)

    if degraded:
        # Incomplete collection: preserve the good baseline, emit nothing.
        write_json(meta_path, {
            "initialized_at": _read_initialized_at(meta_path),
            "last_run": now,
            "last_event_count": 0,
            "degraded": True,
            "collection_errors_count": len(errors),
        })
        _write_degraded_alert(alert_path, now, prev_exists)
        print("collection_degraded")
        print(f"baseline_preserved={prev_exists}")
        print(f"collection_errors={len(errors)}")
        return RC_DEGRADED

    # --- Healthy cycle (collection complete) ---
    if not prev_exists:
        write_json(snapshot_path, current)
        write_json(meta_path, {"initialized_at": now, "last_run": now, "last_event_count": 0})
        print("baseline_initialized")
        print(f"state_dir={state_dir}")
        print(f"snapshot={snapshot_path}")
        return RC_OK

    previous = read_json(snapshot_path)
    changes = semantic_diff(previous, current)
    correlation_events = _detect_correlations(changes, now)

    if changes or correlation_events:
        events = changes_to_events(changes, now)
        events.extend(correlation_events)
        emitted = len(events)
        _append_events(events_path, events)
        Path(alert_path).write_text(
            render_events_md([e.to_dict() for e in events]), encoding="utf-8"
        )
        print("drift_detected")
        print(f"new_events={emitted}")
        print(f"events={events_path}")
        print(f"alert={alert_path}")
    else:
        print("no_drift")
        # Overwrite any stale drift alert with the current short status so the
        # old alarm is not mistaken for a current one.
        Path(alert_path).write_text(_short_alert(now), encoding="utf-8")
        emitted = 0

    # Current becomes the new baseline for the next cycle.
    write_json(snapshot_path, current)
    write_json(meta_path, {
        "initialized_at": _read_initialized_at(meta_path),
        "last_run": now,
        "last_event_count": emitted,
    })
    return RC_OK
