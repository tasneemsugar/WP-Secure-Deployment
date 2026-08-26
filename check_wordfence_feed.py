#!/usr/bin/env python3
"""
Checks plugin-list.csv (from `wp plugin list --format=csv`) against the
Wordfence Intelligence v3 vulnerability feed using API key authentication.
"""
import csv
import json
import os
import sys
import urllib.request
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

    api_key = os.getenv("WORDFENCE_API_KEY")
    if not api_key:
        print("Error: WORDFENCE_API_KEY environment variable is missing.")
        sys.exit(1)

    print("Downloading Wordfence Intelligence v3 production feed...")
    
    req = urllib.request.Request(
        FEED_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "Python-Wordfence-Checker/3.0"
        }
    )

    try:
        with urllib.request.urlopen(req) as resp:
            feed = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"HTTP Error fetching feed: {e.code} {e.reason}")
        sys.exit(1)

    # Index feed by plugin slug for fast lookup
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
                        findings.append((slug, installed, record.get("title", "Untitled vulnerability")))

    if findings:
        print(f"\n{len(findings)} matching known vulnerabilities found:\n")
        for slug, installed, title in findings:
            print(f"::warning::{slug} {installed} — {title}")
        sys.exit(1)
    else:
        print("\nNo matches found in the Wordfence Intelligence feed for installed plugin versions.")


if __name__ == "__main__":
    main()
