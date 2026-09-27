import os
import unittest
from unittest.mock import patch

from nativebridgeguard.windows_evidence import collect_binary_evidence


class WindowsEvidenceTests(unittest.TestCase):

    def test_read_only_acl_does_not_mark_current_user_writable(self):
        readonly_acl = (
            "NT AUTHORITY\\SYSTEM Allow ReadAndExecute, Synchronize\n"
            "BUILTIN\\Administrators Allow ReadAndExecute, Synchronize\n"
            "BUILTIN\\Users Allow ReadAndExecute, Synchronize\n"
            "NT SERVICE\\TrustedInstaller Allow FullControl"
        )

        with (
            patch(
                "nativebridgeguard.windows_evidence.Path.is_file",
                return_value=True,
            ),
            patch(
                "nativebridgeguard.windows_evidence.sha256_file",
                return_value="fakehash",
            ),
            patch(
                "nativebridgeguard.windows_evidence._powershell_json"
            ) as powershell_json,
            patch.dict(
                os.environ,
                {
                    "USERDOMAIN": "TESTHOST",
                    "USERNAME": "testuser",
                    "USERPROFILE": r"C:\Users\testuser",
                },
            ),
        ):
            powershell_json.side_effect = [
                {
                    "status": "Valid",
                    "signer": "CN=Microsoft Windows",
                },
                {
                    "owner": r"NT SERVICE\TrustedInstaller",
                    "acl": readonly_acl,
                },
            ]

            evidence = collect_binary_evidence(
                r"C:\Windows\VendorComponent\component.exe"
            )

        self.assertFalse(evidence.current_user_writable_hint)


    def test_current_user_fullcontrol_marks_writable(self):
        acl = (
            "NT AUTHORITY\\SYSTEM Allow FullControl\n"
            "BUILTIN\\Administrators Allow FullControl\n"
            "TESTHOST\\testuser Allow FullControl\n"
            "BUILTIN\\Users Allow ReadAndExecute, Synchronize\n"
        )
        with (
            patch(
                "nativebridgeguard.windows_evidence.Path.is_file",
                return_value=True,
            ),
            patch(
                "nativebridgeguard.windows_evidence.sha256_file",
                return_value="fakehash",
            ),
            patch(
                "nativebridgeguard.windows_evidence._powershell_json"
            ) as powershell_json,
            patch.dict(
                os.environ,
                {
                    "USERDOMAIN": "TESTHOST",
                    "USERNAME": "testuser",
                    "USERPROFILE": r"C:\Users\testuser",
                },
            ),
        ):
            powershell_json.side_effect = [
                {"status": "Valid", "signer": "CN=Microsoft Windows"},
                {"owner": r"TESTHOST\testuser", "acl": acl, "parent_acl": None},
            ]
            evidence = collect_binary_evidence(r"C:\Program Files\App\bin.exe")

        self.assertTrue(evidence.current_user_writable_hint)
        self.assertIn("Allow(TESTHOST\\testuser: FullControl)", evidence.writable_hint_reason or "")


    def test_builtin_users_allow_write_marks_writable(self):
        acl = (
            "NT AUTHORITY\\SYSTEM Allow FullControl\n"
            "BUILTIN\\Users Allow Write, Synchronize\n"
        )
        with (
            patch("nativebridgeguard.windows_evidence.Path.is_file", return_value=True),
            patch("nativebridgeguard.windows_evidence.sha256_file", return_value="fakehash"),
            patch("nativebridgeguard.windows_evidence._powershell_json") as powershell_json,
            patch.dict(
                os.environ,
                {"USERDOMAIN": "TESTHOST", "USERNAME": "testuser", "USERPROFILE": r"C:\Users\testuser"},
            ),
        ):
            powershell_json.side_effect = [
                {"status": "Valid", "signer": "CN=Microsoft Windows"},
                {"owner": r"TESTHOST\testuser", "acl": acl, "parent_acl": None},
            ]
            evidence = collect_binary_evidence(r"C:\Program Files\App\bin.exe")
        self.assertTrue(evidence.current_user_writable_hint)

    def test_relevant_principal_deny_write_marks_not_writable(self):
        acl = (
            "BUILTIN\\Users Allow Write, Synchronize\n"
            "BUILTIN\\Users Deny Write\n"
        )
        with (
            patch("nativebridgeguard.windows_evidence.Path.is_file", return_value=True),
            patch("nativebridgeguard.windows_evidence.sha256_file", return_value="fakehash"),
            patch("nativebridgeguard.windows_evidence._powershell_json") as powershell_json,
            patch.dict(
                os.environ,
                {"USERDOMAIN": "TESTHOST", "USERNAME": "testuser", "USERPROFILE": r"C:\Users\testuser"},
            ),
        ):
            powershell_json.side_effect = [
                {"status": "Valid", "signer": "CN=Microsoft Windows"},
                {"owner": r"TESTHOST\testuser", "acl": acl, "parent_acl": None},
            ]
            evidence = collect_binary_evidence(r"C:\Program Files\App\bin.exe")
        self.assertFalse(evidence.current_user_writable_hint)

    def test_readonly_file_but_parent_current_user_modify_marks_writable(self):
        file_acl = (
            "NT AUTHORITY\\SYSTEM Allow FullControl\n"
            "BUILTIN\\Users Allow ReadAndExecute, Synchronize\n"
        )
        parent_acl = "TESTHOST\\testuser Allow Modify, Synchronize"
        with (
            patch("nativebridgeguard.windows_evidence.Path.is_file", return_value=True),
            patch("nativebridgeguard.windows_evidence.sha256_file", return_value="fakehash"),
            patch("nativebridgeguard.windows_evidence._powershell_json") as powershell_json,
            patch.dict(
                os.environ,
                {"USERDOMAIN": "TESTHOST", "USERNAME": "testuser", "USERPROFILE": r"C:\Users\testuser"},
            ),
        ):
            powershell_json.side_effect = [
                {"status": "Valid", "signer": "CN=Microsoft Windows"},
                {"owner": r"TESTHOST\testuser", "acl": file_acl, "parent_acl": parent_acl},
            ]
            evidence = collect_binary_evidence(r"C:\Program Files\App\bin.exe")
        self.assertTrue(evidence.current_user_writable_hint)


if __name__ == "__main__":
    unittest.main()