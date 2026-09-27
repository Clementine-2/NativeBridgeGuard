import os
import unittest
from unittest.mock import patch

from nativebridgeguard.models import BinaryEvidence, NativeHostManifest, RegistryHost, TrustPath
from nativebridgeguard.rules import evaluate


class RuleTests(unittest.TestCase):
    @patch.dict(os.environ, {"USERPROFILE": r"C:\\Users\\Alice"})
    def test_machine_registration_to_user_binary(self):
        tp = TrustPath(
            browser="edge",
            host_name="com.x",
            effective_registration=RegistryHost("edge","HKLM","64","com.x",r"HKLM\\...",r"C:\\Program Files\\x.json"),
            shadowed_registrations=[],
            manifest=NativeHostManifest("com.x",None,r"C:\\Program Files\\x.json",r"C:\\Users\\Alice\\AppData\\x.exe",["chrome-extension://abc/"],{}),
            binary=BinaryEvidence(r"C:\\Users\\Alice\\AppData\\x.exe",True,under_user_profile=True),
            allowed_extension_ids=["abc"],
            installed_allowed_extensions=[],
            missing_allowed_extension_ids=["abc"],
            policy_status="allowed",
            policy_reason=None,
        )
        ids = {f.rule_id for f in evaluate(tp)}
        self.assertIn("NBG004", ids)
        self.assertIn("NBG007", ids)


if __name__ == "__main__":
    unittest.main()
