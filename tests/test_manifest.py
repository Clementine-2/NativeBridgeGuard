import json
import tempfile
import unittest
from pathlib import Path

from nativebridgeguard.manifest import parse_host_manifest


class ManifestBomCompatTests(unittest.TestCase):
    def _write(self, path: Path, text: str, bom: bool):
        data = text.encode("utf-8")
        if bom:
            data = b"\xef\xbb\xbf" + data  # UTF-8 BOM
        path.write_bytes(data)

    def _manifest_text(self, name, binary, origins):
        # Build with json.dumps so backslashes in platform paths are escaped
        # correctly (Windows paths like C:\Users\... would otherwise be invalid
        # JSON).
        return json.dumps({
            "name": name,
            "description": None,
            "path": binary,
            "type": "stdio",
            "allowed_origins": origins,
        })

    def test_parse_normal_utf8_no_bom(self):
        d = Path(tempfile.mkdtemp())
        p = d / "m.json"
        self._write(
            p,
            self._manifest_text("host", str(d / "h.exe"), ["chrome-extension://abc/"]),
            bom=False,
        )
        m = parse_host_manifest(str(p), "fallback")
        self.assertIsNotNone(m)
        self.assertEqual(m.name, "host")
        self.assertEqual(m.allowed_origins, ["chrome-extension://abc/"])
        self.assertTrue(m.binary_path.endswith("h.exe"))

    def test_parse_utf8_with_bom(self):
        d = Path(tempfile.mkdtemp())
        p = d / "m.json"
        self._write(
            p,
            self._manifest_text("host", str(d / "h.exe"), ["chrome-extension://abc/"]),
            bom=True,
        )
        m = parse_host_manifest(str(p), "fallback")
        self.assertIsNotNone(m)
        self.assertEqual(m.name, "host")
        self.assertEqual(m.allowed_origins, ["chrome-extension://abc/"])
        self.assertTrue(m.binary_path.endswith("h.exe"))


if __name__ == "__main__":
    unittest.main()
