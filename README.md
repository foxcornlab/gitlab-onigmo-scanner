# `gitlab-onigmo-scanner`

Version triage for the two `CVSS 10.0` `GitLab` regex flaws, `CVE-2026-97229` and `CVE-2026-110264`. Give it a `GitLab` version you own, it tells you whether that build is still open, and it catches the two traps that are already catching people. It never touches the network, never sends a payload, never hits a `CI` lint endpoint, never compiles a crafted regex.

## `The flaw`

| `Detail` | `Value` |
| --- | --- |
| `CVE` | `CVE-2026-97229`, plus `CVE-2026-110264` graded alongside it |
| `Bug` | `Integer overflow` (`CWE-190`) in `Onigmo`, the regex engine built into `Ruby`, when `GitLab` compiles a user-supplied regular expression |
| `Impact` | `Unauthenticated remote code execution` on a self-managed `GitLab` server, under certain conditions |
| `Severity` | `10.0` critical for both, scored by `GitLab` as `CNA` |
| `Exploitation` | `CVE-2026-97229` added to `CISA KEV` on `2026-10-29`, federal due date `2026-11-01`. `CVE-2026-110264` has no `KEV` listing as of this writing, and `GitLab` reports no sign it has been used in attacks |

`CVE-2026-97229` is the `CI/CD` regex flaw: a specially crafted regular expression in a `CI/CD` configuration, insufficient regex validation, fixed `2026-10-12`. `CVE-2026-110264` is a second, wider regex flaw fixed `2026-10-21`, reaching every self-managed release back to `7.0`. Same engine, same score, different bug, and that is exactly why one check is not enough.

## `Fixed versions`

### `CVE-2026-97229` (fixed `2026-10-12`)

| `Line` | `Fixed in` |
| --- | --- |
| `GitLab 19.2` | `19.2.8` |
| `GitLab 19.3` | `19.3.5` |
| `GitLab 19.4` | `19.4.2` |
| `GitLab 19.5`, older than `19.2` | `Not listed as affected by this CVE` |

### `CVE-2026-110264` (fixed `2026-10-21`)

| `Line` | `Fixed in` |
| --- | --- |
| `GitLab 19.5` | `19.5.1` |
| `GitLab 19.4` | `19.4.3` |
| `GitLab 19.3` | `19.3.6` |
| `GitLab 19.2` | `19.2.9` |
| `GitLab 19.1` | `19.1.9` |
| `GitLab 19.0` | `19.0.10` |
| `GitLab 18.11` | `18.11.13` |
| `GitLab 18.10` and older | `No fixed release`, upgrade to `18.11.13` or later |

### `Ruby`, for source and custom-image installs

| `Line` | `Fixed in` |
| --- | --- |
| `Ruby 3.3` | `3.3.13` |
| `Ruby 3.4` | `3.4.12` |
| `Ruby 4.0` | `4.0.9` |
| `Ruby 3.2` and older | `No fix`, end of life, move to `3.4` or `4.0` |

## `Trap 1: the October 12 patch does not cover October 21`

`19.4.2`, `19.3.5` and `19.2.8` fixed `CVE-2026-97229`. Every one of them sits below the `CVE-2026-110264` fix for its branch (`19.4.3`, `19.3.6`, `19.2.9`). If you patched on `October 12` and stopped, you are still vulnerable, and a scanner that only knows the first CVE will call you clean. This tool grades both, and it names the trap in its output when it sees it.

## `Trap 2: upgrading GitLab does not fix your own Ruby`

`GitLab`'s fix is a patch to the `Ruby` it bundles in its official packages and images. A source install, or a custom image that installs `Ruby` separately, does not get that patch from a `GitLab` upgrade. `Alpine Linux` lived this one: it upgraded to `GitLab 19.3.6` on `2026-10-22` and stayed vulnerable, because its image used standard `Ruby`. An attacker probed its server on `2026-10-20` and `21`, crashed workers eight times, got partway through the exploit in four of them, and came back on `25` and `26`. `Alpine` found no proof the exploit succeeded, could not rule it out, rebuilt the instance from scratch, replaced its secret keys and reset every password. Its fixed image, re-pulled after `2026-10-27`, carries `Ruby 3.3.13`.

So: `--install-type official` grades the `GitLab` version alone, because the `Ruby` rides with it. `--install-type source` or `custom` also grades the `Ruby` you supply with `--ruby-version`, and a missing `Ruby` version grades `UNKNOWN`, not clean. `Ruby 4.0.8` is a special case worth knowing: it fixes the `CVE-2026-97229` bug but not `CVE-2026-110264`, so it grades `VULNERABLE` here. `Ruby` has requested no `CVE` identifiers of its own for these fixes, which is why a scanner matching `CVE` records against installed packages finds no vulnerable `Ruby` anywhere. This tool checks the `Ruby` version directly instead.

## `What it checks`

- One `GitLab` version: `CVE-2026-97229` and `CVE-2026-110264` separately, then one overall verdict
- A `CSV` inventory of many instances: `name,gitlab_version,ruby_version,install_type,hosting`
- The `Ruby` trap, when you say the install is `source` or `custom`
- `GitLab.com` and `Dedicated` as already patched, no action needed

Each finding gets a verdict: `VULNERABLE`, `FIXED`, `EOL_NO_FIX`, `UNKNOWN`, or `NOT_AFFECTED` for a single `CVE` on a branch it does not touch. `EOL_NO_FIX` counts as vulnerable: there is no patch coming for that line.

## `What it never does`

No network requests. No probing of remote servers. No crafted regex, no `CI` lint request, no exploit traffic, no `PoC` code. It reads version strings you supply and stops. That is deliberate: the public `PoCs` for `CVE-2026-97229` already exist, and reproducing one here would add nothing defensive.

## `Why this, when PoCs and version counters already exist`

The public material for `CVE-2026-97229` is mostly offensive: `PoCs` that run code as the `git` user, and labs that map which builds are weaponizable. `Censys` counts exposed hosts by version. `GitLab` published `Sigma` rules for spotting exploitation attempts in logs. None of that is a standalone defensive triage tool that grades both October `CVSS 10.0` flaws together and checks the `Ruby` underneath a source or custom install. That gap is this repo: one command, both `CVEs`, both traps, no payload. Use it alongside `GitLab`'s `Sigma` rules, not instead of them. If an instance was probed, version triage is not compromise triage: check worker crash logs and `Onigmo` crash reports, and follow `Alpine`'s example if you cannot rule an attempt out.

## `Grading`

| `Finding` | `Severity` |
| --- | --- |
| `GitLab` below its branch's fix for either `CVE` | `VULNERABLE` |
| `GitLab` on `18.10` or older, or `Ruby 3.2` or older on a source/custom install | `EOL_NO_FIX`, counts as vulnerable |
| `GitLab` at or past both fixes, and a fixed `Ruby` where one applies | `FIXED` |
| `Source/custom` install with no `Ruby` version, or a branch newer than this tool's data (`2026-10-30`) | `UNKNOWN`, not clean |
| `GitLab.com` / `Dedicated` | `FIXED`, patched by `GitLab` |

## `Usage`

```
# One instance, official package or image
python3 gitlab_onigmo_scanner.py --version 19.4.2

# One instance, source install with its own Ruby
python3 gitlab_onigmo_scanner.py --version 19.4.3 --ruby-version 3.4.11 --install-type source

# A whole estate, machine-readable output
python3 gitlab_onigmo_scanner.py --list inventory.csv --json

# Tests (version tables only, no network)
python3 -m unittest discover -s tests -v
```

`inventory.csv` format, header row optional:

```
name,gitlab_version,ruby_version,install_type,hosting
prod,19.4.1,,official,self-managed
staging,19.4.3,,official,self-managed
legacy-source,19.4.3,3.4.11,source,self-managed
```

Exit codes: `0` = nothing vulnerable found, `2` = vulnerable or end-of-life finding, `1` = scan error. `UNKNOWN` does not change the exit code, but it is not clean. Confirm those items another way before closing them.

## `Source disagreements, and what this tool follows`

- On `19.3.4`: `GitLab`'s advisory lists `19.3` before `19.3.5` as affected, so `19.3.4` grades `VULNERABLE` here. One exploit lab reports it could not weaponize `19.3.4` because its bundled `libruby` never enters the vulnerable path. This tool follows the advisory, conservatively: a build the vendor calls affected is not cleared by one lab's negative result.
- On prerequisites for `CVE-2026-97229`: `GitLab` scores it `PR:N`, unauthenticated. `Rapid7`'s reproduced route needed attacker-controlled content pushed to a public project first, with only the final `CI` lint request unauthenticated. This tool does not settle that argument, because version triage does not depend on it: a version in range is flagged either way, and a version out of range is flagged by neither route.
- On `CVE-2026-110264` exploitation: `GitLab` reports no sign of use in attacks, and it is not in `CISA KEV`. This tool does not claim otherwise. The `KEV` listing, the due date and the attack story in this `README` belong to `CVE-2026-97229` only.
- On scope: this tool grades the two October `CVSS 10.0` flaws only. It does not grade the September regex `CVEs` (`CVE-2026-89078`, `CVE-2026-93577`, both `9.9`, authenticated) separately. Any version failing the October checks is already critical, and every October fixed version sits above the September fixes for its branch, but this is not a full `GitLab` audit. Do not present a `FIXED` grade here as proof against every other `GitLab` flaw.

## `Honest caveats`

- A version in range is triage, not proof of exploitability. Reachability depends on your configuration and exposure, and `GitLab` has not published the full preconditions for either flaw.
- A clean grade is only as good as the version string you fed it. An image tag is not a running version: rebuild with a fresh pull, then verify the running build.
- `GitLab` versions with suffixes (`19.4.3-ee.0`) parse on their numeric part. Internal builds (`-internal0`) used by `Dedicated` are handled by the `--hosting dedicated` flag, not by suffix parsing.
- Branches newer than this tool's data grade `UNKNOWN`. Re-check `GitLab`'s advisory before calling a future release clean.
- No exploit code is included, linked, or reproduced here.

## `References`

- `GitLab` critical patch release `19.4.2` / `19.3.5` / `19.2.8` (`CVE-2026-97229`, `CVSS 10.0`, `2026-10-12`)
- `GitLab` critical patch release `19.5.1` (`CVE-2026-110264`, `CVSS 10.0`, `2026-10-21`, backports to `18.11.13`)
- `CISA KEV` entry for `CVE-2026-97229` (added `2026-10-29`, due `2026-11-01`)
- `Alpine Linux` incident disclosure (`2026-10-28`): attack `2026-10-20` to `26`, rebuild and password reset, `Ruby 3.3.13` fix for custom images
- `Ruby` regexp fixes advisory (`2026-10-23`): `Ruby 4.0.9`, `3.4.12`, `3.3.13`, and the `4.0.8` gap for `CVE-2026-110264`
- `Rapid7` technical analysis of `CVE-2026-97229` (route prerequisites, inline-comment quantifier bypass)
- `GitLab` detection rules for self-managed servers (`Sigma` format, `Onigmo` worker crash and `CI` lint patterns)

## `Thanks to`

- `joaxcar` for reporting both flaws through `GitLab`'s `HackerOne` program
- The `GitLab` security team for the advisories, the backports, and the detection rules
- The `Ruby` team for the `Onigmo` fixes and the unusually clear advisory table
- `Alpine Linux` for publishing the incident that made the `Ruby` trap concrete
- `Rapid7`, `Censys` and everyone publishing `GitLab` detection research

## `Disclaimer`

Built for defensive triage and authorized testing only. Scan only systems you own or are authorized to test. The authors are not responsible for misuse.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
