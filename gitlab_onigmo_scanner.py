#!/usr/bin/env python3
"""Detection-only triage for GitLab Onigmo regex RCEs.

Grades a self-managed GitLab CE/EE version against two CVSS 10.0 flaws,
plus the Ruby trap that caught Alpine Linux:

  * CVE-2026-97229 -- integer overflow in the CI/CD regex compiler,
    fixed 2026-10-12. Affected: 19.2 before 19.2.8, 19.3 before 19.3.5,
    19.4 before 19.4.2. Added to CISA KEV 2026-10-29.
  * CVE-2026-110264 -- integer overflow in the regex compiler,
    fixed 2026-10-21. Affected: every self-managed release from 7.0
    before 18.11.13, 19.0.10, 19.1.9, 19.2.9, 19.3.6, 19.4.3, 19.5.1
    (one per branch). No fixed release below 18.11.

Why both: the October 12 patch (19.4.2 / 19.3.5 / 19.2.8) is still
inside the October 21 affected range. A scanner that only checks
CVE-2026-97229 marks those builds clean. They are not.

Why Ruby: GitLab's fix is a patch to the Ruby it bundles in its
official packages and images. A source install, or a custom image
that installs Ruby separately, does NOT get that patch from a GitLab
upgrade. Alpine Linux upgraded to GitLab 19.3.6 and stayed vulnerable
until it moved to Ruby 3.3.13. Ruby's own fixed releases are 3.3.13,
3.4.12 and 4.0.9 (all three Onigmo fixes). Note 4.0.8 fixes the
CVE-2026-97229 bug but NOT CVE-2026-110264, so 4.0.8 is not safe.
Ruby 3.2 and earlier are end of life and get no fix.

This tool never touches the network, never sends a payload, never
hits a CI lint endpoint, and never compiles a crafted regex. It
grades version strings you supply from your own instance (Admin
Area, `gitlab-rake gitlab:env:info`, or your image tag). A version
in range is triage, not proof of exploitability, and a clean grade
is only as good as the version string you fed it.

Exit codes: 0 = nothing vulnerable found, 2 = vulnerable or
end-of-life finding, 1 = scan error. UNKNOWN does not change the
exit code, but it is not clean.
"""

import argparse
import csv
import json
import re
import sys

CVE_97229_FIXED = {
    (19, 2): (19, 2, 8),
    (19, 3): (19, 3, 5),
    (19, 4): (19, 4, 2),
}

CVE_110264_FIXED = {
    (18, 11): (18, 11, 13),
    (19, 0): (19, 0, 10),
    (19, 1): (19, 1, 9),
    (19, 2): (19, 2, 9),
    (19, 3): (19, 3, 6),
    (19, 4): (19, 4, 3),
    (19, 5): (19, 5, 1),
}

RUBY_FIXED = {
    (3, 3): (3, 3, 13),
    (3, 4): (3, 4, 12),
    (4, 0): (4, 0, 9),
}

VULNERABLE = "VULNERABLE"
FIXED = "FIXED"
NOT_AFFECTED = "NOT_AFFECTED"
NO_FIX = "EOL_NO_FIX"
UNKNOWN = "UNKNOWN"


def parse_version(raw):
    """Parse '19.4.3', '19.4.3-ee.0', 'v19.4.1' -> (19, 4, 3) or None."""
    if raw is None:
        return None
    text = str(raw).strip().lstrip("vV")
    # Drop build suffixes: -ee.0, -ce.0, -rc1, +anything.
    text = re.split(r"[-+]", text, maxsplit=1)[0].strip()
    parts = text.split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    nums = tuple(int(p) for p in parts)
    if len(nums) < 2:
        return None
    while len(nums) < 3:
        nums = nums + (0,)
    return nums[:3]


def branch(version):
    return version[:2]


def grade_97229(version):
    """Return (verdict, detail) for CVE-2026-97229."""
    if version is None:
        return UNKNOWN, "unparseable GitLab version"
    b = branch(version)
    if b in CVE_97229_FIXED:
        fixed = CVE_97229_FIXED[b]
        if version < fixed:
            return VULNERABLE, f"{fmt(version)} < fixed {fmt(fixed)}"
        return FIXED, f"{fmt(version)} >= fixed {fmt(fixed)}"
    if b == (19, 5):
        return NOT_AFFECTED, "19.5 branch not listed as affected by CVE-2026-97229"
    if version < (19, 2, 0):
        return NOT_AFFECTED, "CVE-2026-97229 affected range starts at 19.2"
    # Newer than the data this tool ships (2026-10-30): do not guess clean.
    return UNKNOWN, "branch newer than this tool's CVE-2026-97229 data, verify against GitLab's advisory"


def grade_110264(version):
    """Return (verdict, detail) for CVE-2026-110264."""
    if version is None:
        return UNKNOWN, "unparseable GitLab version"
    if version < (7, 0, 0):
        return UNKNOWN, "version predates the CVE-2026-110264 affected range start (7.0), verify manually"
    b = branch(version)
    if b in CVE_110264_FIXED:
        fixed = CVE_110264_FIXED[b]
        if version < fixed:
            return VULNERABLE, f"{fmt(version)} < fixed {fmt(fixed)}"
        return FIXED, f"{fmt(version)} >= fixed {fmt(fixed)}"
    if version < (18, 11, 0):
        return NO_FIX, "no fixed release below 18.11, upgrade to 18.11.13 or later"
    # Newer than the data this tool ships (2026-10-30): do not guess clean.
    return UNKNOWN, "branch newer than this tool's CVE-2026-110264 data, verify against GitLab's advisory"


def grade_ruby(ruby_version):
    """Return (verdict, detail) for the bundled-Ruby trap."""
    if ruby_version is None:
        return UNKNOWN, "Ruby version unknown, cannot clear a source/custom install"
    b = branch(ruby_version)
    if b in RUBY_FIXED:
        fixed = RUBY_FIXED[b]
        if ruby_version < fixed:
            return VULNERABLE, f"Ruby {fmt(ruby_version)} < fixed {fmt(fixed)}"
        return FIXED, f"Ruby {fmt(ruby_version)} >= fixed {fmt(fixed)}"
    if ruby_version < (3, 3, 0):
        return NO_FIX, "Ruby 3.2 and earlier are end of life, no Onigmo fix, move to 3.4 or 4.0"
    return UNKNOWN, "Ruby branch newer than this tool's data, verify against Ruby's advisory"


def fmt(version):
    return ".".join(str(n) for n in version)


def grade_instance(name, gitlab_version, ruby_version=None,
                   install_type="official", hosting="self-managed"):
    """Grade one instance. Returns a dict with verdicts and notes."""
    notes = []
    if hosting in ("gitlab-com", "dedicated"):
        return {
            "name": name,
            "gitlab_version": gitlab_version,
            "ruby_version": ruby_version,
            "install_type": install_type,
            "hosting": hosting,
            "cve-2026-97229": NOT_AFFECTED,
            "cve-2026-110264": NOT_AFFECTED,
            "ruby": NOT_AFFECTED,
            "verdict": FIXED,
            "notes": [f"{hosting} is patched by GitLab, no action needed"],
        }

    parsed = parse_version(gitlab_version)
    v97229, d97229 = grade_97229(parsed)
    v110264, d110264 = grade_110264(parsed)

    if parsed is None:
        ruby_verdict, ruby_detail = UNKNOWN, "GitLab version unparseable"
    elif install_type in ("source", "custom"):
        if ruby_version is None:
            ruby_verdict, ruby_detail = UNKNOWN, (
                "source/custom install with no Ruby version supplied: "
                "a GitLab upgrade alone does not fix this install "
                "(see Alpine Linux, 2026-10-28)"
            )
        else:
            ruby_parsed = parse_version(ruby_version)
            ruby_verdict, ruby_detail = grade_ruby(ruby_parsed)
    else:
        ruby_verdict = NOT_AFFECTED
        ruby_detail = "official package/image: Ruby is bundled and patched with the GitLab release"

    verdicts = [v97229, v110264, ruby_verdict]
    if NO_FIX in verdicts:
        overall = NO_FIX
    elif VULNERABLE in verdicts:
        overall = VULNERABLE
    elif UNKNOWN in verdicts:
        overall = UNKNOWN
    else:
        overall = FIXED

    if v97229 == FIXED and v110264 == VULNERABLE:
        notes.append("October 12 patch trap: fixed for CVE-2026-97229 but still vulnerable to CVE-2026-110264, go one patch higher")
    if ruby_verdict == VULNERABLE and v97229 == FIXED and v110264 == FIXED:
        notes.append("Ruby trap: GitLab version looks fixed but the install's own Ruby is still vulnerable")
    if install_type == "custom":
        notes.append("custom image: re-pull after 2026-10-27, images built before then may carry unpatched Ruby even at a fixed GitLab version")
    if parsed is not None and parsed < (19, 2, 0) and v110264 == VULNERABLE:
        notes.append("older branch: the October 21 fix is a backport, stay on your branch's fixed patch, no extra upgrade stops needed for a patch bump")

    return {
        "name": name,
        "gitlab_version": gitlab_version,
        "ruby_version": ruby_version,
        "install_type": install_type,
        "hosting": hosting,
        "cve-2026-97229": v97229,
        "cve-2026-97229_detail": d97229,
        "cve-2026-110264": v110264,
        "cve-2026-110264_detail": d110264,
        "ruby": ruby_verdict,
        "ruby_detail": ruby_detail,
        "verdict": overall,
        "notes": notes,
    }


def read_inventory(path):
    """Read a CSV inventory. Columns: name,gitlab_version,ruby_version,install_type,hosting.

    A header row is detected and skipped. Empty fields are None.
    """
    rows = []
    with open(path, newline="") as handle:
        reader = csv.reader(handle)
        for fields in reader:
            fields = [f.strip() for f in fields]
            if not fields or not any(fields):
                continue
            if fields[0].lower() == "name" and len(fields) > 1 and "gitlab" in fields[1].lower():
                continue
            name = fields[0] or "unnamed"
            gitlab_version = fields[1] if len(fields) > 1 and fields[1] else None
            ruby_version = fields[2] if len(fields) > 2 and fields[2] else None
            install_type = fields[3] if len(fields) > 3 and fields[3] else "official"
            hosting = fields[4] if len(fields) > 4 and fields[4] else "self-managed"
            rows.append((name, gitlab_version, ruby_version, install_type, hosting))
    return rows


def render_text(results):
    lines = []
    for r in results:
        lines.append(f"{r['name']}: {r['verdict']} (GitLab {r['gitlab_version']})")
        lines.append(f"  CVE-2026-97229:  {r['cve-2026-97229']} ({r.get('cve-2026-97229_detail', '')})")
        lines.append(f"  CVE-2026-110264: {r['cve-2026-110264']} ({r.get('cve-2026-110264_detail', '')})")
        lines.append(f"  Ruby:           {r['ruby']} ({r.get('ruby_detail', '')})")
        for note in r["notes"]:
            lines.append(f"  Note: {note}")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Detection-only GitLab Onigmo triage (CVE-2026-97229, CVE-2026-110264).")
    parser.add_argument("--version", help="GitLab version, e.g. 19.4.1")
    parser.add_argument("--name", default="instance", help="Label for a single --version check")
    parser.add_argument("--ruby-version", default=None, help="Ruby version for source/custom installs, e.g. 3.4.11")
    parser.add_argument("--install-type", default="official",
                        choices=["official", "source", "custom"],
                        help="official = Linux package / official image (bundled Ruby); source/custom = own Ruby")
    parser.add_argument("--hosting", default="self-managed",
                        choices=["self-managed", "gitlab-com", "dedicated"],
                        help="gitlab-com / dedicated are patched by GitLab")
    parser.add_argument("--list", dest="inventory", default=None, help="CSV inventory file (name,gitlab_version,ruby_version,install_type,hosting)")
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    args = parser.parse_args(argv)

    results = []
    if args.inventory:
        try:
            rows = read_inventory(args.inventory)
        except OSError as exc:
            print(f"error: cannot read inventory: {exc}", file=sys.stderr)
            return 1
        if not rows:
            print("error: inventory file is empty", file=sys.stderr)
            return 1
        for row in rows:
            results.append(grade_instance(*row))
    elif args.version:
        results.append(grade_instance(args.name, args.version, args.ruby_version,
                                      args.install_type, args.hosting))
    else:
        parser.print_usage(sys.stderr)
        print("error: pass --version or --list", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(render_text(results))

    if any(r["verdict"] in (VULNERABLE, NO_FIX) for r in results):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
