#!/usr/bin/env python3
"""
Aggregates findings from the security pipeline's JSON artifacts into a
single markdown summary, suitable for posting as a PR comment.

Usage:
    python3 build_summary.py <reports_dir>

Expects <reports_dir> to contain subfolders as produced by
`actions/download-artifact@v4` with no name filter — one folder per
artifact, named after the artifact.
"""
import glob
import json
import os
import sys

MARKER = "<!-- security-pipeline-summary -->"


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def trivy_config_section(reports_dir):
    path = os.path.join(reports_dir, "trivy-config-report", "trivy-config-report.json")
    data = load_json(path)
    if not data:
        return "### IaC config (Trivy)\n\n_No report found or nothing to parse._\n"

    rows = []
    for result in data.get("Results", []) or []:
        for mc in result.get("Misconfigurations", []) or []:
            rows.append((mc.get("Severity", "?"), mc.get("ID", "?"), mc.get("Title", "?")))

    if not rows:
        return "### IaC config (Trivy)\n\n✅ No CRITICAL/HIGH misconfigurations found.\n"

    lines = ["### IaC config (Trivy)\n", "| Severity | ID | Title |", "|---|---|---|"]
    for sev, id_, title in rows:
        lines.append(f"| {sev} | {id_} | {title} |")
    return "\n".join(lines) + "\n"


def trivy_image_section(reports_dir):
    folders = sorted(glob.glob(os.path.join(reports_dir, "trivy-image-report-*")))
    if not folders:
        return "### Container images (Trivy)\n\n_No reports found._\n"

    lines = ["### Container images (Trivy)\n"]
    any_findings = False
    for folder in folders:
        image_name = os.path.basename(folder).replace("trivy-image-report-", "")
        json_files = glob.glob(os.path.join(folder, "*.json"))
        if not json_files:
            continue
        data = load_json(json_files[0])
        if not data:
            continue

        rows = []
        for result in data.get("Results", []) or []:
            for vuln in result.get("Vulnerabilities", []) or []:
                rows.append((
                    vuln.get("Severity", "?"),
                    vuln.get("VulnerabilityID", "?"),
                    vuln.get("PkgName", "?"),
                    vuln.get("InstalledVersion", "?"),
                    vuln.get("FixedVersion") or "not fixed upstream yet",
                ))

        lines.append(f"**`{image_name}`**\n")
        if not rows:
            lines.append("✅ No CRITICAL/HIGH vulnerabilities found.\n")
            continue

        any_findings = True
        lines.append("| Severity | CVE | Package | Installed | Fix |")
        lines.append("|---|---|---|---|---|")
        for sev, cve, pkg, installed, fix in rows:
            lines.append(f"| {sev} | {cve} | {pkg} | {installed} | {fix} |")
        lines.append("")

    return "\n".join(lines) + "\n"


def wordfence_section(reports_dir):
    path = os.path.join(reports_dir, "wp-security-audit-lists", "wordfence-findings.json")
    data = load_json(path)
    if data is None:
        return "### WordPress plugins (Wordfence Intelligence)\n\n_No report found._\n"

    if not data:
        return "### WordPress plugins (Wordfence Intelligence)\n\n✅ No known CVEs matched installed plugin versions.\n"

    lines = [
        "### WordPress plugins (Wordfence Intelligence)\n",
        "| Plugin | Installed | CVE | CVSS | Fix |",
        "|---|---|---|---|---|",
    ]
    for f in data:
        lines.append(
            f"| {f.get('slug')} | {f.get('installed')} | {f.get('cve')} | "
            f"{f.get('cvss')} | upgrade to {f.get('patched_version')} |"
        )
    return "\n".join(lines) + "\n"


def other_checks_section():
    # ZAP (HTML report) and Semgrep aren't parsed into structured findings
    # yet — this just points at where to look, rather than guessing at
    # their content. Worth expanding later if these become high-traffic
    # enough to be worth structured parsing too.
    return (
        "### Other checks\n\n"
        "- **ZAP baseline (DAST)**: see the `zap-report` artifact for full details.\n"
        "- **Semgrep (SAST)**: see the `semgrep` job's own output/annotations.\n"
    )


def main():
    if len(sys.argv) != 2:
        print("Usage: build_summary.py <reports_dir>", file=sys.stderr)
        sys.exit(1)

    reports_dir = sys.argv[1]

    sections = [
        trivy_config_section(reports_dir),
        trivy_image_section(reports_dir),
        wordfence_section(reports_dir),
        other_checks_section(),
    ]

    print(MARKER)
    print("## 🔒 Security Pipeline Summary\n")
    print("\n".join(sections))


if __name__ == "__main__":
    main()
