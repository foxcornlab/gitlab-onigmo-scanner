import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gitlab_onigmo_scanner import grade_instance, parse_version, read_inventory


class TestVersionParsing(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(parse_version("19.4.3"), (19, 4, 3))

    def test_ee_suffix(self):
        self.assertEqual(parse_version("19.4.3-ee.0"), (19, 4, 3))

    def test_v_prefix(self):
        self.assertEqual(parse_version("v19.4.1"), (19, 4, 1))

    def test_garbage(self):
        self.assertIsNone(parse_version("not-a-version"))
        self.assertIsNone(parse_version("19"))


class TestCveGrades(unittest.TestCase):
    def test_unpatched_1941(self):
        r = grade_instance("x", "19.4.1")
        self.assertEqual(r["cve-2026-97229"], "VULNERABLE")
        self.assertEqual(r["cve-2026-110264"], "VULNERABLE")
        self.assertEqual(r["verdict"], "VULNERABLE")

    def test_oct12_patch_trap_1942(self):
        # The case that matters: fixed for 97229, still open for 110264.
        r = grade_instance("x", "19.4.2")
        self.assertEqual(r["cve-2026-97229"], "FIXED")
        self.assertEqual(r["cve-2026-110264"], "VULNERABLE")
        self.assertEqual(r["verdict"], "VULNERABLE")

    def test_oct12_patch_trap_1935(self):
        r = grade_instance("x", "19.3.5")
        self.assertEqual(r["cve-2026-97229"], "FIXED")
        self.assertEqual(r["cve-2026-110264"], "VULNERABLE")

    def test_oct12_patch_trap_1928(self):
        r = grade_instance("x", "19.2.8")
        self.assertEqual(r["cve-2026-97229"], "FIXED")
        self.assertEqual(r["cve-2026-110264"], "VULNERABLE")

    def test_fixed_branches(self):
        for version in ("19.4.3", "19.3.6", "19.2.9", "19.5.1", "19.1.9", "19.0.10", "18.11.13"):
            with self.subTest(version=version):
                self.assertEqual(grade_instance("x", version)["verdict"], "FIXED", version)

    def test_1950_vulnerable_only_to_110264(self):
        r = grade_instance("x", "19.5.0")
        self.assertEqual(r["cve-2026-97229"], "NOT_AFFECTED")
        self.assertEqual(r["cve-2026-110264"], "VULNERABLE")

    def test_1934_follows_advisory_not_lab_claim(self):
        # Advisory says 19.3 before 19.3.5 is affected; one exploit lab
        # claims 19.3.4 was not weaponizable. Follow the advisory.
        r = grade_instance("x", "19.3.4")
        self.assertEqual(r["cve-2026-97229"], "VULNERABLE")
        self.assertEqual(r["cve-2026-110264"], "VULNERABLE")

    def test_old_branch_no_fix(self):
        r = grade_instance("x", "18.10.5")
        self.assertEqual(r["cve-2026-110264"], "EOL_NO_FIX")
        self.assertEqual(r["verdict"], "EOL_NO_FIX")

    def test_181112_vulnerable(self):
        r = grade_instance("x", "18.11.12")
        self.assertEqual(r["cve-2026-97229"], "NOT_AFFECTED")
        self.assertEqual(r["cve-2026-110264"], "VULNERABLE")


class TestRubyTrap(unittest.TestCase):
    def test_official_needs_no_ruby(self):
        r = grade_instance("x", "19.4.3", install_type="official")
        self.assertEqual(r["verdict"], "FIXED")

    def test_source_old_ruby_overrides_clean_gitlab(self):
        r = grade_instance("x", "19.4.3", ruby_version="3.4.11", install_type="source")
        self.assertEqual(r["ruby"], "VULNERABLE")
        self.assertEqual(r["verdict"], "VULNERABLE")

    def test_source_fixed_ruby(self):
        r = grade_instance("x", "19.4.3", ruby_version="3.4.12", install_type="source")
        self.assertEqual(r["verdict"], "FIXED")

    def test_ruby_408_misses_110264_fix(self):
        r = grade_instance("x", "19.4.3", ruby_version="4.0.8", install_type="custom")
        self.assertEqual(r["ruby"], "VULNERABLE")

    def test_ruby_409_clean(self):
        r = grade_instance("x", "19.4.3", ruby_version="4.0.9", install_type="custom")
        self.assertEqual(r["verdict"], "FIXED")

    def test_ruby_3313_clean(self):
        r = grade_instance("x", "19.3.6", ruby_version="3.3.13", install_type="source")
        self.assertEqual(r["verdict"], "FIXED")

    def test_source_missing_ruby_is_unknown_not_clean(self):
        r = grade_instance("x", "19.4.3", install_type="source")
        self.assertEqual(r["ruby"], "UNKNOWN")
        self.assertEqual(r["verdict"], "UNKNOWN")

    def test_ruby_eol(self):
        r = grade_instance("x", "19.4.3", ruby_version="3.2.11", install_type="source")
        self.assertEqual(r["ruby"], "EOL_NO_FIX")
        self.assertEqual(r["verdict"], "EOL_NO_FIX")

    def test_saas_patched(self):
        r = grade_instance("x", "19.4.1", hosting="gitlab-com")
        self.assertEqual(r["verdict"], "FIXED")


class TestInventoryFile(unittest.TestCase):
    def test_csv_with_header(self):
        path = os.path.join(os.path.dirname(__file__), "sample_inventory.csv")
        rows = read_inventory(path)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0][0], "prod")
        results = [grade_instance(*row) for row in rows]
        self.assertEqual(results[0]["verdict"], "VULNERABLE")
        self.assertEqual(results[1]["verdict"], "FIXED")
        self.assertEqual(results[2]["verdict"], "VULNERABLE")


if __name__ == "__main__":
    unittest.main()
