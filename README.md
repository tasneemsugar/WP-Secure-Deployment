# WP-Secure-Deployment

A vulnerable WordPress instance (Docker Compose, Ubuntu VM) wrapped in a
CI/CD security pipeline: secrets scanning, dependency/CVE scanning, SAST,
IaC scanning, container image scanning, and DAST — all gating a real
dev → PR → merge → deploy flow.

## Why this exists

This started as a practice project for hands-on DevSecOps: not just running
security tools once, but building the pipeline architecture around them.

## Architecture

Two separate Docker Compose stacks live in this repo, deliberately kept apart:

| | `docker-compose.ci.yml` | `docker-compose.prod.yml` |
|---|---|---|
| Purpose | Ephemeral test target for CI | The real, persistent site |
| Project name | `wp-ci-<github.run_id>` (unique per run) | `wp-prod` |
| Lifecycle | Built fresh and destroyed every pipeline run | Long-running, never torn down by automation |
| Data | Throwaway | Persistent, meant to survive indefinitely |
| Port | Dynamically resolved via `docker compose port` | Fixed, `127.0.0.1:8080` |

CI's project name includes `${{ github.run_id }}`, so concurrent runs never
collide with each other, not just with production — this matters since
multiple pushes/PRs can trigger overlapping runs on the same self-hosted
runner.

## The pipeline (`.github/workflows/security-pipeline.yml`)

Triggered on:
- **Push to `dev`** — early feedback while still working on a change
- **Pull request into `main`** — the real gate, before anything merges
- **Push to `main`** — triggers deployment (see below), since a direct push
  to `main` should only ever be a PR merge that already passed every gate

| Job | What it checks |
|---|---|
| `build-and-verify` | The stack actually builds and responds |
| `secrets-scan` | gitleaks — no committed credentials/keys |
| `wp-security-audit` | Installed plugin versions vs. the Wordfence Intelligence CVE feed, plus registered-username enumeration via `wp-cli` |
| `semgrep` | Static analysis on any custom PHP |
| `checkov-config` | Misconfiguration scan on `docker-compose.ci.yml` (via Checkov's `yaml` framework — Trivy doesn't support Compose files at all, and Checkov has no dedicated `docker_compose` framework either, despite some docs suggesting otherwise) |
| `detect-images` / `verify-detected-images` | Dynamically resolves which images to scan from the compose file itself, so this can't drift out of sync with a hardcoded list; the verify job is a permanent sanity check, not leftover debugging — this exact data has broken silently before |
| `trivy-image` | Known CVEs in each detected image (matrix job, one scan per image, `ignore-unfixed: true` so it only blocks on issues with an actual available fix) |
| `zap-baseline` | OWASP ZAP dynamic scan against the live test instance |
| `security-summary` | Aggregates findings from the above into one report — posted as a PR comment on `pull_request` runs, or to the run's own Step Summary otherwise |
| `deploy` | Applies a merged `main` to the production stack (see CD below) |

Most security jobs are **blocking** — a real finding fails the job. With
branch protection enabled, that would block merging; on this repo's current
plan (private, free tier), branch protection isn't enforced, so this is
currently self-discipline rather than an automated hard stop.

### Why WPScan isn't used

WPScan's vulnerability-lookup flags (`vp`/`vt`) require a paid-tier-adjacent
API token even at low volume, and its free enumeration mode doesn't include
CVE data at all. Wordfence Intelligence's v3 feed provides the same
CVE/CVSS/patched-version data with a free account and API key, so the
pipeline uses that instead, via `check_wordfence_feed.py`, fed from
`wp-cli`'s own plugin list rather than a separate scanner.

### CD: how a merge actually reaches production

The `deploy` job only runs on a direct push to `main`. Because the
self-hosted GitHub Actions runner lives on the same VM as the production
site, "deploying" here is: authenticate a `git fetch` inline using the
workflow's own short-lived `GITHUB_TOKEN` (no stored credentials on the
runner), `reset --hard` the production checkout to mirror `main` exactly,
then `docker compose -f docker-compose.prod.yml -p wp-prod up -d`. This is a
simplified version of real-world CD — most setups have CI infrastructure
and production on separate machines, requiring SSH, orchestration tooling,
or a cloud provider's deploy API instead.

The runner executes as a dedicated low-privilege service account, separate
from the account that owns the production directory — the service account
was granted group-level read/write access to that directory.

One extra wrinkle worth calling out: git checks actual Unix file ownership,
not GitHub permissions. Since the runner's service account doesn't own the
production repo's files, git refuses to operate on it at all by default —
this is a real security protection, meant to stop a malicious repo owned by
another user on a shared machine from executing code as you via its config
or hooks. The fix is an explicit `git config --global --add safe.directory
<path>` exception, which could have been run once by hand on the VM — but
that kind of fix lives invisibly in local disk state, easy to lose if the
runner's home directory is ever rebuilt (which has actually happened during
this project). Instead, that same command runs as a line inside the
workflow itself, every deploy — so the fix is version-controlled and
self-healing rather than a one-off manual step someone has to remember.

## Required repo secrets

| Secret | Used by |
|---|---|
| `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_ROOT_PASSWORD` | Building the `.env` file each run |
| `CI_WP_ADMIN_PASSWORD` | Bootstrapping the throwaway test instance's admin account |
| `WORDFENCE_API_KEY` | The plugin CVE check |

`GITHUB_TOKEN` is not a repo secret you set — it's auto-provided by Actions
for every run and used by both `secrets-scan`, `security-summary`, and
`deploy`.

## Note on the vulnerable plugin fixture

Earlier iterations of this pipeline installed a deliberately outdated
plugin (File Manager 6.0, CVE-2020-25213) into the CI test instance,
specifically to give `wp-security-audit`'s Wordfence CVE check and
watchlist comparison something real to detect — proof the detection logic
actually works, not just that it runs without erroring. Once that was
confirmed (see project history/screenshots), the fixture was intentionally
removed rather than left permanently installed.

Practical effect: `wp-security-audit` currently passes clean because
there's nothing vulnerable installed to find, not because it was re-verified
against a live case. If you want to re-validate this check after future
changes (e.g. a Wordfence API change, a script refactor), temporarily
re-adding a `wp plugin install <slug> --version=<old>` step is the fastest
way to confirm detection still works end-to-end.

## Troubleshooting history

Building this pipeline surfaced a fair number of real infrastructure
problems along the way — permission mismatches, an API deprecation
mid-project, a silently-frozen matrix job, credential scoping gaps. Each
one and how it got fixed is documented in
[`TROUBLESHOOTING.md`](./TROUBLESHOOTING.md).
