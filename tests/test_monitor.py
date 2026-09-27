import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from nativebridgeguard.models import Snapshot
from nativebridgeguard.monitor import run_monitor_cycle


def _trust_path(browser, name, reg_key, man_path, binary_path, ids):
    return {
        "browser": browser,
        "host_name": name,
        "effective_registration": {
            "browser_family": "chrome",
            "scope": reg_key.split("\\")[0],
            "view": "64",
            "host_name": name,
            "registry_key": reg_key,
            "manifest_path": man_path,
        },
        "shadowed_registrations": [],
        "manifest": {
            "name": name,
            "description": None,
            "manifest_path": man_path,
            "binary_path": binary_path,
            "allowed_origins": [],
            "raw": {},
        },
        "binary": {
            "path": binary_path,
            "exists": True,
            "sha256": "AAA",
            "signature_status": "Valid",
            "signer": "Vendor",
            "owner": None,
            "acl": None,
            "parent_acl": None,
            "writable_hint_reason": None,
            "current_user_writable_hint": False,
            "under_user_profile": False,
        },
        "allowed_extension_ids": ids,
        "installed_allowed_extensions": [],
        "missing_allowed_extension_ids": [],
        "policy_status": "allowed",
        "policy_reason": None,
    }


def _snapshot(hosts, collection_errors=None):
    return Snapshot(
        schema_version=1,
        created_at="2026-09-26T00:00:00+00:00",
        host="LAB-PC",
        extensions=[],
        registrations=[],
        policies=[],
        trust_paths=hosts,
        findings=[],
        collection_errors=collection_errors or [],
    )


class MonitorTests(unittest.TestCase):
    def _events(self, state_dir):
        path = os.path.join(state_dir, "events.ndjson")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as f:
            return [l for l in f.read().splitlines() if l.strip()]

    def test_first_run_initializes_baseline(self):
        state = tempfile.mkdtemp()
        hosts = [_trust_path("edge", "com.x", "HKLM\\x", "x.json", "x.exe", ["aaaa"])]
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = run_monitor_cycle(state, scan_fn=lambda: _snapshot(hosts))
        self.assertEqual(rc, 0)
        self.assertIn("baseline_initialized", buf.getvalue())
        self.assertTrue(os.path.exists(os.path.join(state, "snapshot.json")))
        # No drift on a fresh baseline -> no events written.
        self.assertEqual(self._events(state), [])

    def test_second_unchanged_run_emits_no_drift(self):
        state = tempfile.mkdtemp()
        hosts = [_trust_path("edge", "com.x", "HKLM\\x", "x.json", "x.exe", ["aaaa"])]
        with redirect_stdout(io.StringIO()):
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(hosts))
            rc = run_monitor_cycle(state, scan_fn=lambda: _snapshot(hosts))
        self.assertEqual(rc, 0)
        self.assertEqual(self._events(state), [])

    def test_changed_state_emits_event(self):
        state = tempfile.mkdtemp()
        base = [_trust_path("edge", "com.x", "HKLM\\x", "x.json", "x.exe", ["aaaa"])]
        changed = [_trust_path("edge", "com.x", "HKLM\\x", "x.json", "x.exe", ["aaaa", "bbbb"])]
        with redirect_stdout(io.StringIO()):
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(base))
            rc = run_monitor_cycle(state, scan_fn=lambda: _snapshot(changed))
        self.assertEqual(rc, 0)
        events = self._events(state)
        self.assertEqual(len(events), 1)
        ev = json.loads(events[0])
        self.assertEqual(ev["event_type"], "trust_surface_expanded")

    def test_accepted_change_not_repeated(self):
        state = tempfile.mkdtemp()
        base = [_trust_path("edge", "com.x", "HKLM\\x", "x.json", "x.exe", ["aaaa"])]
        changed = [_trust_path("edge", "com.x", "HKLM\\x", "x.json", "x.exe", ["aaaa", "bbbb"])]
        with redirect_stdout(io.StringIO()):
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(base))
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(changed))
            # Environment now stable at the changed state.
            rc = run_monitor_cycle(state, scan_fn=lambda: _snapshot(changed))
        self.assertEqual(rc, 0)
        # The single drift is reported exactly once.
        self.assertEqual(len(self._events(state)), 1)

    def test_events_ndjson_is_valid_json_with_schema_fields(self):
        state = tempfile.mkdtemp()
        base = [_trust_path("edge", "com.x", "HKLM\\x", "x.json", "x.exe", ["aaaa"])]
        changed = [_trust_path("edge", "com.x", "HKLM\\x", "x.json", "x.exe", ["aaaa", "bbbb"])]
        with redirect_stdout(io.StringIO()):
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(base))
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(changed))
        required = {"schema_version", "timestamp", "event_type", "severity", "trust_key", "summary"}
        for line in self._events(state):
            ev = json.loads(line)  # must not raise
            self.assertTrue(required.issubset(ev.keys()), msg=f"missing fields in {ev}")

    def test_correlation_nbg102_emitted_on_coincident_change(self):
        state = tempfile.mkdtemp()
        base = [_trust_path("edge", "com.x", "HKCU\\x", "x_a.json", "x.exe", ["aaaa"])]
        # Same key: registration changed AND authorization surface expanded.
        changed = [_trust_path("edge", "com.x", "HKLM\\x", "x_b.json", "x.exe", ["aaaa", "bbbb"])]
        with redirect_stdout(io.StringIO()):
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(base))
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(changed))
        types = {json.loads(l)["event_type"] for l in self._events(state)}
        self.assertIn("effective_registration_changed", types)
        self.assertIn("trust_surface_expanded", types)
        self.assertIn("compound_trust_boundary_expansion", types)

    def test_first_run_degraded_creates_no_baseline_and_returns_rc2(self):
        state = tempfile.mkdtemp()
        # A degraded first scan must NOT seed a baseline from incomplete data.
        hosts = [_trust_path("edge", "com.x", "HKLM\\x", "x.json", "x.exe", ["aaaa"])]
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = run_monitor_cycle(
                state, scan_fn=lambda: _snapshot(hosts, collection_errors=["collect_registrations: boom"])
            )
        self.assertEqual(rc, 2)
        self.assertIn("collection_degraded", buf.getvalue())
        self.assertFalse(
            os.path.exists(os.path.join(state, "snapshot.json")),
            "degraded first run must not create a baseline",
        )
        self.assertEqual(self._events(state), [])

    def test_degraded_current_preserves_good_baseline_content(self):
        state = tempfile.mkdtemp()
        good = [_trust_path("edge", "com.x", "HKLM\\x", "x.json", "x.exe", ["aaaa"])]
        with redirect_stdout(io.StringIO()):
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(good))  # healthy baseline
        snapshot_path = os.path.join(state, "snapshot.json")
        with open(snapshot_path, encoding="utf-8") as f:
            before = f.read()
        # Now a degraded scan: incomplete collection, must not overwrite baseline.
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = run_monitor_cycle(
                state,
                scan_fn=lambda: _snapshot(
                    [_trust_path("edge", "com.x", "HKLM\\x", "x.json", "x.exe", ["aaaa"])],
                    collection_errors=["collect_policies: boom"],
                ),
            )
        self.assertEqual(rc, 2)
        self.assertIn("baseline_preserved=True", buf.getvalue())
        with open(snapshot_path, encoding="utf-8") as f:
            after = f.read()
        self.assertEqual(after, before, "good baseline content must be unchanged")

    def test_degraded_zero_paths_does_not_emit_removed(self):
        state = tempfile.mkdtemp()
        baseline = [
            _trust_path("edge", f"com.path{i}", "HKLM\\x", "x.json", "x.exe", ["aaaa"])
            for i in range(8)
        ]
        with redirect_stdout(io.StringIO()):
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(baseline))  # 8-path baseline
        # Collector fails -> 0 paths this cycle, but degraded so no diff/events.
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = run_monitor_cycle(
                state,
                scan_fn=lambda: _snapshot([], collection_errors=["collect_registrations: boom"]),
            )
        self.assertEqual(rc, 2)
        self.assertEqual(self._events(state), [], "no trust_path_removed events on degraded scan")
        # Baseline still has 8 paths.
        with open(os.path.join(state, "snapshot.json"), encoding="utf-8") as f:
            snap = json.load(f)
        self.assertEqual(len(snap["trust_paths"]), 8)

    def test_recovery_after_degraded_is_no_drift(self):
        state = tempfile.mkdtemp()
        good = [
            _trust_path("edge", f"com.path{i}", "HKLM\\x", "x.json", "x.exe", ["aaaa"])
            for i in range(8)
        ]
        with redirect_stdout(io.StringIO()):
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(good))
            run_monitor_cycle(
                state,
                scan_fn=lambda: _snapshot([], collection_errors=["collect_registrations: boom"]),
            )
            rc = run_monitor_cycle(state, scan_fn=lambda: _snapshot(good))  # recovered, identical
        self.assertEqual(rc, 0)
        self.assertEqual(self._events(state), [], "recovered stable state -> no new drift")

    def test_stale_alert_overwritten_on_no_drift(self):
        state = tempfile.mkdtemp()
        base = [_trust_path("edge", "com.x", "HKLM\\x", "x.json", "x.exe", ["aaaa"])]
        changed = [_trust_path("edge", "com.x", "HKLM\\x", "x.json", "x.exe", ["aaaa", "bbbb"])]
        alert_path = os.path.join(state, "alert.md")
        with redirect_stdout(io.StringIO()):
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(base))
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(changed))  # drift
        with open(alert_path, encoding="utf-8") as f:
            drift_alert = f.read()
        self.assertIn("trust_surface_expanded", drift_alert)
        with redirect_stdout(io.StringIO()):
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(changed))  # unchanged
        with open(alert_path, encoding="utf-8") as f:
            new_alert = f.read()
        self.assertNotIn("trust_surface_expanded", new_alert)
        self.assertIn("No new trust-drift events", new_alert)

    def test_meta_last_event_count_single_change_is_one(self):
        state = tempfile.mkdtemp()
        base = [_trust_path("edge", "com.x", "HKCU\\x", "x_a.json", "x.exe", ["aaaa"])]
        single = [_trust_path("edge", "com.x", "HKCU\\x", "x_a.json", "x.exe", ["aaaa", "bbbb"])]
        meta_path = os.path.join(state, "meta.json")
        with redirect_stdout(io.StringIO()):
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(base))
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(single))
        self.assertEqual(json.loads(Path(meta_path).read_text())["last_event_count"], 1)

    def test_meta_last_event_count_includes_correlation(self):
        state = tempfile.mkdtemp()
        # One cycle where registration AND authorization surface change together
        # for the same key -> 2 base changes + 1 compound correlation event = 3.
        base = [_trust_path("edge", "com.x", "HKCU\\x", "x_a.json", "x.exe", ["aaaa"])]
        coincident = [_trust_path("edge", "com.x", "HKLM\\x", "x_b.json", "x.exe", ["aaaa", "bbbb"])]
        meta_path = os.path.join(state, "meta.json")
        with redirect_stdout(io.StringIO()):
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(base))
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(coincident))
        self.assertEqual(json.loads(Path(meta_path).read_text())["last_event_count"], 3)

    def test_meta_no_drift_count_is_zero(self):
        state = tempfile.mkdtemp()
        base = [_trust_path("edge", "com.x", "HKLM\\x", "x.json", "x.exe", ["aaaa"])]
        meta_path = os.path.join(state, "meta.json")
        with redirect_stdout(io.StringIO()):
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(base))
            run_monitor_cycle(state, scan_fn=lambda: _snapshot(base))  # unchanged
        self.assertEqual(json.loads(Path(meta_path).read_text())["last_event_count"], 0)


if __name__ == "__main__":
    unittest.main()
