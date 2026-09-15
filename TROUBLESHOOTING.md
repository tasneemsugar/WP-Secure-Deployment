# Troubleshooting history

Real problems hit while building this pipeline, and how each got resolved.
Kept separate from the main README so that file stays focused on
architecture, while this stays available for anyone who wants the deeper
debugging story.

- **`wp-cli` isn't included in the official `wordpress` image** — needed a
  dedicated `wpcli` sidecar container sharing the same volume. This broke
  twice: once initially, and again later when the `wpcli` service's image
  got accidentally changed back to the non-CLI tag.

- **WPScan's `vp`/`vt` enumeration flags require an API token** even for a
  single lookup, and its free tier doesn't include CVE data at all —
  switched to Wordfence Intelligence entirely instead.

- **`gitleaks-action` needs an explicit `pull-requests: read` permission
  grant** — some default `GITHUB_TOKEN` scopes don't include it, causing a
  403 on PR scans.

- **Wordfence's v2 feed was deprecated mid-project** in favor of v3, which
  requires a free account, an API key, and respects a 1-request/30-min
  rate limit — the feed check caches results to disk to avoid re-hitting
  that limit on repeated re-runs during development.

- **Trivy doesn't support Docker Compose files for misconfiguration
  scanning at all** (confirmed directly from its own docs); switched to
  Checkov — which also turned out not to have a dedicated `docker_compose`
  framework despite some third-party docs claiming otherwise, so it runs
  under the `yaml` framework instead.

- **A dynamic matrix (`trivy-image`, sourced from `detect-images`' output)
  silently froze** rather than erroring clearly when the underlying data
  was malformed — root-caused by GitHub Actions' secret-masking replacing
  part of a plain image tag with `***` in the logs, which looked like a
  masking bug but wasn't; the real fix was a more robust `GITHUB_OUTPUT`
  write.

- **`security-summary`'s PR-commenting step originally used
  `context.issue.number`**, which came back empty even on genuine
  `pull_request` events — switched to `context.payload.pull_request.number`
  directly.

- **The `deploy` job needed three separate fixes to actually work**:
  1. A hardcoded `~` path resolved to the wrong user's home directory
     (whichever user the runner service actually executes as, not
     necessarily the one who set up the production directory).
  2. Once the path was corrected, a real OS permissions gap — the
     runner's service account had no access to a different user's
     directory at all, at every level of the path.
  3. Git's `safe.directory` protection — git refuses to operate on a
     repo it doesn't own by Unix file ownership, regardless of OS-level
     read/write permissions granted via group membership.
  4. Finally, a missing authentication method — the service account had
     no stored git credentials at all (those lived in a different user's
     environment from manual pushes). Solved by authenticating with the
     workflow's own short-lived `GITHUB_TOKEN` inline, rather than
     setting up persistent credentials on the runner.
