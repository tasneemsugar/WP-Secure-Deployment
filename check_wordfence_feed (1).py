#!/usr/bin/env python3
"""
Checks plugin-list.csv (from `wp plugin list --format=csv`) against the
Wordfence Intelligence vulnerability feed, v3 API.

v2 of this feed is deprecated — as of March 2026, Wordfence requires a
free account + API key to use v3. Generate a key from your Wordfence
account dashboard under "Integrations", then store it as a GitHub repo
secret named WORDFENCE_API_KEY.

Docs: https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/

Also note: v3 defaults to a rate limit of 1 request per 30 minutes.
Don't re-run this script (or the CI job that calls it) more often than
that, or you'll get throttled.
"""
import csv
import json
import os
import sys
import urllib.request
import urllib.error
from packaging.version import Version, InvalidVersion

FEED_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"


def version_in_range(installed: str, from_v: str, from_incl: bool, to_v: str, to_incl: bool) -> bool:
    try:
        v = Version(installed)
        lo = Version(from_v) if from_v else None
        hi = Version(to_v) if to_v else None
    except InvalidVersion:
        return False  # can't compare, skip rather than false-positive

    if lo is not None:
        if from_incl and v < lo:
            return False
        if not from_incl and v <= lo:
            return False
    if hi is not None:
        if to_incl and v > hi:
            return False
        if not to_incl and v >= hi:
            return False
    return True


def main():
    if len(sys.argv) != 2:
        print("Usage: check_wordfence_feed.py <plugin-list.csv>")
        sys.exit(1)

    api_key = os.environ.get("WORDFENCE_API_KEY")
    if not api_key:
        print("WORDFENCE_API_KEY environment variable not set — skipping feed check.")
        sys.exit(0)

    print("Downloading Wordfence Intelligence v3 production feed (this can take a moment)...")
    req = urllib.request.Request(FEED_URL, headers={"Authorization": f"Bearer {api_key}"})
    try:
        with urllib.request.urlopen(req) as resp:
            feed = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("401 Unauthorized — check WORDFENCE_API_KEY is set correctly.")
        elif e.code == 429:
            print("429 Rate limited — v3 defaults to 1 request per 30 minutes.")
        raise

    # Index feed by plugin slug for fast lookup, since the feed is one
    # big dict keyed by vulnerability UUID rather than by plugin.
    by_slug = {}
    for record in feed.values():
        for sw in record.get("software", []):
            if sw.get("type") == "plugin":
                by_slug.setdefault(sw["slug"], []).append((record, sw))

    findings = []
    with open(sys.argv[1], newline="") as f:
        for row in csv.DictReader(f):
            slug = row["name"]
            installed = row["version"]
            for record, sw in by_slug.get(slug, []):
                for _, rng in sw.get("affected_versions", {}).items():
                    if version_in_range(
                        installed,
                        rng.get("from_version", ""),
                        rng.get("from_inclusive", True),
                        rng.get("to_version", ""),
                        rng.get("to_inclusive", True),
                    ):
                        findings.append({
                            "slug": slug,
                            "installed": installed,
                            "title": record.get("title", "Untitled vulnerability"),
                            "cve": record.get("cve") or "No CVE assigned",
                            "cvss": record.get("cvss", {}).get("score", "N/A"),
                            # patched_version tells you what to actually upgrade
                            # to — this is the field that turns "you're vulnerable"
                            # into "here's the fix", which is the more useful signal.
                            "patched_version": sw.get("patched_version") or "Not specified in feed",
                        })

    if findings:
        print(f"\n{len(findings)} matching known vulnerabilities found:\n")
        for f_ in findings:
            print(
                f"::warning::{f_['slug']} {f_['installed']} — {f_['title']} "
                f"(CVE: {f_['cve']}, CVSS: {f_['cvss']}) — "
                f"upgrade to {f_['patched_version']} to fix"
            )
        sys.exit(1)  # non-zero so this can gate the build once you're ready
    else:
        print("\nNo matches found in the Wordfence Intelligence feed for installed plugin versions.")


if __name__ == "__main__":
    main()
