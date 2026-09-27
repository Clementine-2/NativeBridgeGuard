# Debugging Cases — NativeBridgeGuard v0.1.5

Two real development cases from this release. Both are recorded as engineering
facts: symptom, wrong assumption, evidence, root cause, fix, regression test,
and the boundary that remains. Neither is a success story — both are cases where
the first implementation was wrong and the correction is narrower than it looks.

---

## Case 1 — NBG006 false positive: `os.access` is not a Windows ACL judgement

### Symptom

`NBG006` ("current user writable hint") fired on a Chromium component binary
under `C:\Windows`. The implication of the finding — that an unprivileged user
could replace the binary backing a trust path — was false for a protected
operating-system location.

### Wrong assumption

That `os.access(path, os.W_OK)` answers "can the current user write this file?"
on Windows. It does not.

### Manual evidence

Reading the same file's security descriptor directly showed that the
unprivileged principals held only `ReadAndExecute, Synchronize`:

```text
BUILTIN\Users Allow  ReadAndExecute, Synchronize
NT AUTHORITY\SYSTEM Allow  FullControl
```

No `Allow` ACE granted `Write`, `Modify`, or `FullControl` to the current user or
to a broad unprivileged principal. The binary was not user-replaceable. The
tool's claim contradicted the ACL.

### Root cause

CPython's `os.access` on Windows is a POSIX-flavoured approximation. It does not
evaluate the security descriptor: it does not read the DACL, does not consider
group membership, does not apply `Deny` precedence, and is influenced by the
read-only file attribute. It is therefore **unsuitable as an NTFS effective-ACL
judgement**, and any finding built on it will produce both false positives and
false negatives on Windows.

### Regression tests added

`tests/test_windows_evidence.py`:

- `test_read_only_acl_does_not_mark_current_user_writable` — the exact case that
  was failing; a read-only ACL must not produce a writable hint.
- `test_current_user_fullcontrol_marks_writable` — the true-positive case.
- `test_builtin_users_allow_write_marks_writable` — broad principal case.
- `test_relevant_principal_deny_write_marks_not_writable` — `Deny` precedence.

### Fix

Replaced the `os.access` check with an ACL-derived heuristic that parses real
DACL text:

- Collect `Get-Acl … .AccessToString` for the **binary and its parent
  directory** (replacing a file requires directory write/delete rights, so the
  parent matters).
- Parse ACE lines with a regex anchored on the **standalone `Allow`/`Deny`
  token**, not on arbitrary whitespace, so identities containing spaces are
  matched correctly.
- Treat an entry as relevant if it names the current user
  (`USERDOMAIN\USERNAME`) or a broad unprivileged principal (`BUILTIN\Users`,
  `Authenticated Users`, `Everyone`).
- An `Allow` ACE carrying `Write`, `Modify`, or `FullControl` is a writable
  signal.
- A `Deny` ACE carrying write rights on a relevant principal **overrides** the
  `Allow`, matching Windows `Deny` precedence rather than ignoring it.
- Record the matched ACEs in `writable_hint_reason` so a human can audit why the
  hint fired.

### Real-machine retest

The false positives on the Chromium component binary and on the OS security
binaries under `C:\Windows` were gone. Genuine `FullControl` positives on
third-party hosts under the user profile were retained. The change removed
specific false claims without silencing real ones.

### Boundary — still not full AuthZ

This remains a **heuristic**, and the finding text says so explicitly. It does
not:

- resolve group membership (the user may be writable via a group not literally
  named in the ACE),
- resolve privileges (backup/restore, take-ownership),
- compute inheritance, `CREATOR OWNER`, or owner-rights semantics,
- call the Windows AuthZ effective-access API.

A "not writable" result from this heuristic is **not** proof that the path is
safe. NBG006 should be read as "the DACL contains an ACE worth reviewing", not
as an authorization verdict.

---

## Case 2 — Load-unpacked collector: green unit tests, broken production

### Symptom

During Block 1 acceptance, live scan on a real Windows machine did **not**
discover the two lab extensions that were loaded via Chrome's *Load unpacked*
flow. The collector responsible for them had passing unit tests.

### Wrong assumption

That the extension settings for unpacked extensions live in the profile's
`Preferences` JSON, and that a unit test exercising a `Preferences`-shaped tree
validates the production code path.

### Manual evidence

- The `extensions.settings` subtree in `Preferences` was **empty** for the
  profile that visibly had the unpacked extensions loaded.
- The same settings were present in **`Secure Preferences`**, including the
  `path` field pointing at the real on-disk unpacked directory.
- Modern Chrome/Edge move sensitive extension settings — unpacked-extension
  entries among them — out of `Preferences` into `Secure Preferences`.

### Root cause

`collect_unpacked_extensions()` read **only** `Preferences`. On any
current-version browser the data had moved, so the collector returned nothing.
The unit tests passed because they fed a **synthetic** `Preferences` tree: the
fixture shape was not the production shape. This is a test/production gap — the
tests validated the code against a structure the browser no longer writes, so
they could stay green indefinitely while the feature was dead in production.

### Fix

Targeted, in `collect_unpacked_extensions()`:

- Read **both** `Preferences` and `Secure Preferences` per profile.
- `Secure Preferences` takes priority: an ID present in both resolves to the
  Secure Preferences entry, and its `path` wins.
- A `Secure Preferences` entry missing a `path` does not erase a path-bearing
  `Preferences` entry — an entry is never downgraded to a weaker one.
- The two sources are **isolated**: a corrupt or missing `Preferences` is
  ignored while `Secure Preferences` still works, and vice versa, so one bad
  file cannot silently blank the whole collector.

### Regression tests added

Six tests in `tests/test_extensions.py`, each pinned to a real failure mode
rather than to the happy path:

- `test_unpacked_only_in_secure_preferences_detected` — the production bug.
- `test_unpacked_only_in_preferences_still_detected` — no regression for older
  layout.
- `test_same_id_in_both_preference_sources_single_entry` — no duplicates.
- `test_secure_preferences_path_wins_on_conflict` — precedence.
- `test_secure_preferences_malformed_preferences_fallback` — source isolation.
- `test_secure_preferences_native_messaging_permission_collected` — permission
  still parsed from the new source.

Automated suite went from 36 to **42 passing**.

### Live rescan

After the fix, both lab extensions were discovered from their **real** unpacked
paths, both carrying the `nativeMessaging` permission. `collection_errors`
showed no new entries, and the directory-installed extension counts were
unchanged — i.e. the fix added the missing unpacked records without perturbing
existing collection.

### Boundary

The collector depends on Chromium's on-disk preference layout, which is an
undocumented internal. If a future browser version moves these settings again,
the same failure mode returns. The mitigation is `collection_errors`, which
records collector failures so that "no findings" is distinguishable from
"collection failed" — but detection of the next layout change still depends on
someone looking at a real scan.
