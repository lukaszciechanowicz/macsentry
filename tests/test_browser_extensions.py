import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills/macsentry/scripts"))
import browser_extensions


class BrowserExtensionTests(unittest.TestCase):
    def test_chrome_profiles_preserve_state_and_report_bad_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            default = root / "Default"
            default.mkdir()
            (default / "Secure Preferences").write_text(json.dumps({"extensions": {"settings": {
                "example": {"manifest": {"name": "Example", "version": "1.2",
                                          "host_permissions": ["<all_urls>"]},
                            "path": "example/1.2_0", "disable_reasons": [1]}
            }}}))
            broken = root / "Profile 1"
            broken.mkdir()
            (broken / "Preferences").write_text("{")
            result = browser_extensions.chrome(root)
            extension = result["profiles"][0]["extensions"][0]
            self.assertEqual(extension["version"], "1.2")
            self.assertEqual(extension["disable_reasons"], [1])
            self.assertEqual(extension["host_permissions"], ["<all_urls>"])
            self.assertEqual(extension["path"], str(default / "Extensions/example/1.2_0"))
            self.assertTrue(result["profiles"][1]["errors"])

    def test_firefox_registered_profiles_and_disabled_addons(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "Profiles/first"
            profile.mkdir(parents=True)
            (root / "profiles.ini").write_text("[Profile0]\nIsRelative=1\nPath=Profiles/first\n"
                                                "[Profile1]\nIsRelative=1\nPath=Profiles/missing\n")
            (profile / "extensions.json").write_text(json.dumps({"addons": [
                {"id": "x@example", "type": "extension", "version": "2", "active": False,
                 "userDisabled": True, "defaultLocale": {"name": "Example"}},
                {"id": "theme", "type": "theme"}
            ]}))
            profiles = browser_extensions.firefox(root)["profiles"]
            extension = profiles[0]["extensions"][0]
            self.assertEqual(extension["id"], "x@example")
            self.assertFalse(extension["active"])
            self.assertTrue(extension["user_disabled"])
            self.assertEqual(len(profiles[0]["extensions"]), 1)
            self.assertTrue(profiles[1]["errors"])


if __name__ == "__main__":
    unittest.main()
