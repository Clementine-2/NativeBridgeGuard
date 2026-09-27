from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import Event

# Bump only on a breaking change to the Event wire format.
EVENT_SCHEMA_VERSION = 1

# Keys that are already represented by dedicated Event fields and must not be
# duplicated into the generic evidence list.
_STANDARD_KEYS = {"type", "severity", "key", "summary", "before", "after"}

# Stable event types emitted by the monitor. Semantic-diff change types map
# 1:1 onto these; correlation events add compound types below.
SEMENTIC_EVENT_TYPES = {
    "trust_path_added",
    "trust_path_removed",
    "effective_registration_changed",
    "trust_surface_expanded",
    "trust_surface_reduced",
    "binary_path_changed",
    "binary_identity_changed",
    "binary_signature_changed",
    "policy_effect_changed",
}

# Compound/temporal correlation event types (produced by the monitor, not the
# static rule engine).
CORRELATION_EVENT_TYPES = {
    "compound_trust_boundary_expansion",
}


def changes_to_events(changes: list[dict[str, Any]], timestamp: str | None = None) -> list[Event]:
    """Convert semantic-diff change dicts into stable Event objects.

    Every change dict carries type/severity/key/summary plus optional
    before/after and extra signal fields (e.g. added_extension_ids). The extra
    fields become the event's evidence list so the machine-readable stream keeps
    the detail that the human report would otherwise hide.
    """
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    events: list[Event] = []
    for c in changes:
        extra = {k: v for k, v in c.items() if k not in _STANDARD_KEYS}
        evidence = [f"{k}={v}" for k, v in sorted(extra.items())]
        events.append(Event(
            schema_version=EVENT_SCHEMA_VERSION,
            timestamp=ts,
            event_type=c.get("type", "unknown"),
            severity=c.get("severity", "info"),
            trust_key=c.get("key", ""),
            summary=c.get("summary", ""),
            before=c.get("before"),
            after=c.get("after"),
            evidence=evidence,
        ))
    return events
