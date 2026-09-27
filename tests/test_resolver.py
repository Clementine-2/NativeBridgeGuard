import unittest

from nativebridgeguard.models import RegistryHost
from nativebridgeguard.resolver import resolve_effective


class ResolverTests(unittest.TestCase):
    def test_edge_hkcu_shadows_machine(self):
        regs = [
            RegistryHost("edge", "HKLM", "64", "com.x", "HKLM\\edge\\com.x", r"C:\\Program Files\\x.json"),
            RegistryHost("edge", "HKCU", "64", "com.x", "HKCU\\edge\\com.x", r"C:\\Users\\u\\x.json"),
        ]
        eff, shadowed = resolve_effective("edge", regs)["com.x"]
        self.assertEqual(eff.scope, "HKCU")
        self.assertEqual(len(shadowed), 1)

    def test_edge_family_fallback_order(self):
        regs = [
            RegistryHost("chrome", "HKCU", "64", "com.x", "HKCU\\chrome\\com.x", "a.json"),
            RegistryHost("chromium", "HKCU", "64", "com.x", "HKCU\\chromium\\com.x", "b.json"),
        ]
        eff, _ = resolve_effective("edge", regs)["com.x"]
        self.assertEqual(eff.browser_family, "chromium")


if __name__ == "__main__":
    unittest.main()
