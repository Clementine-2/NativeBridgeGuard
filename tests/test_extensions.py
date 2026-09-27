import json
import os
import tempfile
import unittest
from pathlib import Path

from nativebridgeguard.extensions import (
    collect_extensions,
    collect_unpacked_extensions,
    merge_extensions,
)
from nativebridgeguard.models import BrowserExtension


def _write(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, (dict, list)):
        path.write_text(json.dumps(data), encoding="utf-8")
    else:
        path.write_text(data, encoding="utf-8")


def _manifest(name, version, perms):
    return {
        "manifest_version": 3,
        "name": name,
        "version": version,
        "permissions": perms,
    }


class UnpackedExtensionCollectorTests(unittest.TestCase):
    def setUp(self):
        self._saved_local = os.environ.get("LOCALAPPDATA")
        self.root = Path(tempfile.mkdtemp())
        os.environ["LOCALAPPDATA"] = str(self.root)
        self.chrome_ud = self.root / "Google" / "Chrome" / "User Data"
        self.edge_ud = self.root / "Microsoft" / "Edge" / "User Data"

    def tearDown(self):
        if self._saved_local is None:
            os.environ.pop("LOCALAPPDATA", None)
        else:
            os.environ["LOCALAPPDATA"] = self._saved_local

    def _profile(self, browser, name="Default"):
        ud = self.chrome_ud if browser == "chrome" else self.edge_ud
        p = ud / name
        p.mkdir(parents=True, exist_ok=True)
        return p

    def _installed_ext(self, browser, ext_id, version="1.0.0", perms=None):
        p = self._profile(browser)
        mpath = p / "Extensions" / ext_id / version / "manifest.json"
        _write(mpath, _manifest("Installed", version, perms or []))
        return mpath

    def _prefs(self, browser, settings):
        p = self._profile(browser)
        _write(p / "Preferences", {"extensions": {"settings": settings}})

    def _secure_prefs(self, browser, settings):
        p = self._profile(browser)
        _write(p / "Secure Preferences", {"extensions": {"settings": settings}})

    def _unpacked_dir(self, ext_id, perms=None):
        d = self.root / "unpacked" / ext_id
        _write(d / "manifest.json", _manifest("Unpacked", "0.1.0", perms or []))
        return d

    # 1. Normal installed extension directory still collected.
    def test_installed_extension_directory_collected(self):
        self._installed_ext("chrome", "installedaaaaaaaaaaaaaaaaaaaaaaaaaa", perms=["nativeMessaging"])
        ids = {e.extension_id for e in collect_extensions()}
        self.assertIn("installedaaaaaaaaaaaaaaaaaaaaaaaaaa", ids)

    # 2. Preferences absolute unpacked path collected.
    def test_unpacked_preferences_path_collected(self):
        udir = self._unpacked_dir("unpackedaaaaaaaaaaaaaaaaaaaaaaaaa", perms=["nativeMessaging"])
        self._prefs("chrome", {"unpackedaaaaaaaaaaaaaaaaaaaaaaaaa": {"path": str(udir)}})
        ids = {e.extension_id for e in collect_unpacked_extensions(set())}
        self.assertIn("unpackedaaaaaaaaaaaaaaaaaaaaaaaaa", ids)

    # 3. Unpacked manifest nativeMessaging permission correctly collected.
    def test_unpacked_native_messaging_permission_collected(self):
        udir = self._unpacked_dir("unpackedaaaaaaaaaaaaaaaaaaaaaaaaa", perms=["nativeMessaging"])
        self._prefs("chrome", {"unpackedaaaaaaaaaaaaaaaaaaaaaaaaa": {"path": str(udir)}})
        ext = next(
            e for e in collect_unpacked_extensions(set())
            if e.extension_id == "unpackedaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        self.assertIn("nativeMessaging", ext.permissions)
        self.assertTrue(ext.has_native_messaging)

    # 4. directory + Preferences same ID not duplicated.
    def test_directory_and_preferences_same_id_no_duplicate(self):
        same_id = "dupaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        self._installed_ext("chrome", same_id, perms=["nativeMessaging"])
        udir = self._unpacked_dir(same_id, perms=["nativeMessaging"])
        self._prefs("chrome", {same_id: {"path": str(udir)}})

        dir_exts = collect_extensions()
        existing = {(e.browser, e.profile, e.extension_id) for e in dir_exts}
        unpacked = collect_unpacked_extensions(existing)  # should skip same_id
        self.assertFalse(any(e.extension_id == same_id for e in unpacked))

        merged = merge_extensions(dir_exts, unpacked)
        self.assertEqual(len([e for e in merged if e.extension_id == same_id]), 1)

        # Merge-level dedup also holds when both lists contain the same key.
        a = BrowserExtension(browser="chrome", profile="Default", extension_id="x",
                             name="n", version="1", manifest_path="p", permissions=[])
        self.assertEqual(len(merge_extensions([a], [a])), 1)

    # 5. Invalid / missing unpacked path safely ignored (no crash).
    def test_invalid_or_missing_unpacked_path_ignored(self):
        no_manifest_dir = self.root / "unpacked" / "nomanifestaaaaaaaaaaaaaaaaaaaaaa"
        no_manifest_dir.mkdir(parents=True, exist_ok=True)
        settings = {
            "missingaaaaaaaaaaaaaaaaaaaaaaaaa": {"path": str(self.root / "does-not-exist")},
            "nomanifestaaaaaaaaaaaaaaaaaaaaaa": {"path": str(no_manifest_dir)},
            "badentryaaaaaaaaaaaaaaaaaaaaaaaa": "not-a-dict",
        }
        self._prefs("chrome", settings)
        exts = collect_unpacked_extensions(set())  # must not raise
        self.assertEqual(exts, [])

    # 6. Chrome / Edge profile layout both reuse the same logic.
    def test_chrome_and_edge_share_layout_logic(self):
        cdir = self._unpacked_dir("chromeunpckaaaaaaaaaaaaaaaaaaaaa", perms=["nativeMessaging"])
        edir = self._unpacked_dir("edgeunpckaaaaaaaaaaaaaaaaaaaaaa", perms=["nativeMessaging"])
        self._prefs("chrome", {"chromeunpckaaaaaaaaaaaaaaaaaaaaa": {"path": str(cdir)}})
        self._prefs("edge", {"edgeunpckaaaaaaaaaaaaaaaaaaaaaa": {"path": str(edir)}})
        exts = collect_unpacked_extensions(set())
        by_browser = {e.browser for e in exts}
        self.assertIn("chrome", by_browser)
        self.assertIn("edge", by_browser)
        self.assertEqual(len(exts), 2)


    # 7. Secure Preferences only -> detected (the production bug fix).
    def test_unpacked_only_in_secure_preferences_detected(self):
        udir = self._unpacked_dir("secureonlyaaaaaaaaaaaaaaaaaaaaa", perms=["nativeMessaging"])
        self._secure_prefs("chrome", {"secureonlyaaaaaaaaaaaaaaaaaaaaa": {"path": str(udir)}})
        ids = {e.extension_id for e in collect_unpacked_extensions(set())}
        self.assertIn("secureonlyaaaaaaaaaaaaaaaaaaaaa", ids)

    # 8. Preferences only -> still detected (backward compatibility).
    def test_unpacked_only_in_preferences_still_detected(self):
        udir = self._unpacked_dir("prefsonlyaaaaaaaaaaaaaaaaaaaaa", perms=["nativeMessaging"])
        self._prefs("chrome", {"prefsonlyaaaaaaaaaaaaaaaaaaaaa": {"path": str(udir)}})
        ids = {e.extension_id for e in collect_unpacked_extensions(set())}
        self.assertIn("prefsonlyaaaaaaaaaaaaaaaaaaaaa", ids)

    # 9. Same ID in both preference sources -> a single BrowserExtension.
    def test_same_id_in_both_preference_sources_single_entry(self):
        udir = self._unpacked_dir("bothsrcaaaaaaaaaaaaaaaaaaaaa", perms=["nativeMessaging"])
        self._prefs("chrome", {"bothsrcaaaaaaaaaaaaaaaaaaaaa": {"path": str(udir)}})
        self._secure_prefs("chrome", {"bothsrcaaaaaaaaaaaaaaaaaaaaa": {"path": str(udir)}})
        exts = [e for e in collect_unpacked_extensions(set())
                if e.extension_id == "bothsrcaaaaaaaaaaaaaaaaaaaaa"]
        self.assertEqual(len(exts), 1)

    # 10. Conflicting paths for the same ID -> Secure Preferences path wins.
    def test_secure_preferences_path_wins_on_conflict(self):
        secure_dir = self._unpacked_dir("confsecaaaaaaaaaaaaaaaaaaaaa", perms=["nativeMessaging"])
        prefs_dir = self._unpacked_dir("confprefaaaaaaaaaaaaaaaaaaaaa", perms=["nativeMessaging"])
        self._prefs("chrome", {"conflictidaaaaaaaaaaaaaaaaaaaaa": {"path": str(prefs_dir)}})
        self._secure_prefs("chrome", {"conflictidaaaaaaaaaaaaaaaaaaaaa": {"path": str(secure_dir)}})
        ext = next(e for e in collect_unpacked_extensions(set())
                   if e.extension_id == "conflictidaaaaaaaaaaaaaaaaaaaaa")
        self.assertEqual(ext.manifest_path, str(secure_dir / "manifest.json"))

    # 11. Secure Preferences malformed -> Preferences fallback still works.
    def test_secure_preferences_malformed_preferences_fallback(self):
        udir = self._unpacked_dir("fallbackaaaaaaaaaaaaaaaaaaaaa", perms=["nativeMessaging"])
        p = self._profile("chrome")
        (p / "Secure Preferences").write_text("{not valid json", encoding="utf-8")
        self._prefs("chrome", {"fallbackaaaaaaaaaaaaaaaaaaaaa": {"path": str(udir)}})
        exts = [e for e in collect_unpacked_extensions(set())
                if e.extension_id == "fallbackaaaaaaaaaaaaaaaaaaaaa"]
        self.assertEqual(len(exts), 1)
        self.assertIn("nativeMessaging", exts[0].permissions)

    # 12. Secure Preferences nativeMessaging permission correctly collected.
    def test_secure_preferences_native_messaging_permission_collected(self):
        udir = self._unpacked_dir("secnmessaaaaaaaaaaaaaaaaaaaaa", perms=["nativeMessaging"])
        self._secure_prefs("chrome", {"secnmessaaaaaaaaaaaaaaaaaaaaa": {"path": str(udir)}})
        ext = next(e for e in collect_unpacked_extensions(set())
                   if e.extension_id == "secnmessaaaaaaaaaaaaaaaaaaaaa")
        self.assertIn("nativeMessaging", ext.permissions)
        self.assertTrue(ext.has_native_messaging)


if __name__ == "__main__":
    unittest.main()
