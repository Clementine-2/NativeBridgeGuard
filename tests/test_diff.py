import unittest

from nativebridgeguard.diffing import semantic_diff


class DiffTests(unittest.TestCase):
    def test_detects_surface_and_binary_changes(self):
        base_path = {
            "browser":"edge", "host_name":"com.x",
            "effective_registration":{"registry_key":"HKLM\\x","manifest_path":"x.json"},
            "allowed_extension_ids":["aaa"],
            "binary":{"path":"x.exe","sha256":"111","signature_status":"Valid","signer":"Vendor"},
            "policy_status":"allowed", "policy_reason":None,
        }
        before = {"trust_paths":[base_path]}
        changed = dict(base_path)
        changed["allowed_extension_ids"] = ["aaa", "bbb"]
        changed["binary"] = {"path":"x.exe","sha256":"222","signature_status":"NotSigned","signer":None}
        after = {"trust_paths":[changed]}
        types = {x["type"] for x in semantic_diff(before, after)}
        self.assertIn("trust_surface_expanded", types)
        self.assertIn("binary_identity_changed", types)
        self.assertIn("binary_signature_changed", types)

    def test_detects_effective_registration_change(self):
        base_path = {
            "browser": "edge", "host_name": "com.y",
            "effective_registration": {
                "registry_key": "HKLM\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.y",
                "manifest_path": "C:\\Program Files\\y.json",
            },
            "allowed_extension_ids": ["aaa"],
            "binary": {"path": "y.exe", "sha256": "111", "signature_status": "Valid", "signer": "Vendor"},
            "policy_status": "allowed", "policy_reason": None,
        }
        changed = dict(base_path)
        changed["effective_registration"] = {
            "registry_key": "HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.y",
            "manifest_path": "C:\\Users\\u\\y.json",
        }
        before = {"trust_paths": [base_path]}
        after = {"trust_paths": [changed]}
        types = {x["type"] for x in semantic_diff(before, after)}
        self.assertIn("effective_registration_changed", types)


if __name__ == "__main__":
    unittest.main()
