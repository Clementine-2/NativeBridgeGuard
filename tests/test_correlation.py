import os
import unittest
from unittest.mock import patch

from nativebridgeguard.models import (
    BinaryEvidence,
    NativeHostManifest,
    RegistryHost,
    TrustPath,
)
from nativebridgeguard.rules import evaluate


def _tp(scope, under_user, writable, signature_status):
    reg = RegistryHost(
        "chrome", scope, "64", "com.nativebridgeguard.lab",
        f"{scope}\\Software\\Google\\Chrome\\NativeMessagingHosts\\com.nativebridgeguard.lab",
        r"C:\Users\u\lab\host.json",
    )
    man = NativeHostManifest(
        "com.nativebridgeguard.lab", None,
        r"C:\Users\u\lab\host.json",
        r"C:\Users\u\lab\host.exe", [], {},
    )
    binary = BinaryEvidence(
        r"C:\Users\u\lab\host.exe", True,
        signature_status=signature_status,
        under_user_profile=under_user,
        current_user_writable_hint=writable,
    )
    return TrustPath(
        browser="chrome",
        host_name="com.nativebridgeguard.lab",
        effective_registration=reg,
        shadowed_registrations=[],
        manifest=man,
        binary=binary,
        allowed_extension_ids=[],
        installed_allowed_extensions=[],
        missing_allowed_extension_ids=[],
        policy_status="allowed",
        policy_reason=None,
    )


class CorrelationTests(unittest.TestCase):
    @patch.dict(os.environ, {"USERPROFILE": r"C:\Users\u"})
    def test_nbg101_all_conditions_trigger(self):
        tp = _tp("HKCU", under_user=True, writable=True, signature_status="NotSigned")
        ids = {f.rule_id for f in evaluate(tp)}
        self.assertIn("NBG101", ids)

    @patch.dict(os.environ, {"USERPROFILE": r"C:\Users\u"})
    def test_nbg101_missing_writable_hint_does_not_trigger(self):
        tp = _tp("HKCU", under_user=True, writable=False, signature_status="NotSigned")
        ids = {f.rule_id for f in evaluate(tp)}
        self.assertNotIn("NBG101", ids)

    @patch.dict(os.environ, {"USERPROFILE": r"C:\Users\u"})
    def test_nbg101_valid_signature_does_not_trigger(self):
        tp = _tp("HKCU", under_user=True, writable=True, signature_status="Valid")
        ids = {f.rule_id for f in evaluate(tp)}
        self.assertNotIn("NBG101", ids)

    @patch.dict(os.environ, {"USERPROFILE": r"C:\Users\u"})
    def test_nbg101_machine_scope_does_not_trigger(self):
        tp = _tp("HKLM", under_user=True, writable=True, signature_status="NotSigned")
        ids = {f.rule_id for f in evaluate(tp)}
        self.assertNotIn("NBG101", ids)


if __name__ == "__main__":
    unittest.main()
