# kairos-watchers

Free-tier **cloud senses** for a private personal-AI system. This repository runs a small,
self-contained Python script (`watch.py`) on GitHub-Actions cron. It polls a list of **public**
feeds, and when one changes it writes a content-addressed JSON *observation* into `inbox/`. A
laptop later pulls and folds those observations into a private event log.

That's the whole job: **watch public things, and leave a hash-stamped note when they move.**

## The contract (read before changing anything)

This repo is **deliberately, structurally credential-free.**

- **No secrets, ever.** `watch.py` uses no OAuth token, no API key, no bot key — nothing. It only
  performs anonymous `https` GETs of the public URLs in [`doors.json`](doors.json). There are no
  GitHub Actions **secrets** referenced by any workflow, and none should ever be added. (The
  built-in `GITHUB_TOKEN` is used solely to commit observations back to *this* public repo — it is
  the repo's own ephemeral token, never a credential for any other system.)
- **Public feeds only.** Every door is a public release feed, status page, or pricing/docs page.
  No private, authenticated, or personal source is fetched here. Personal/on-device senses run on
  the laptop, never in the cloud.
- **Content-free logs.** Run logs print only counts and public door ids (`run.started` /
  `run.completed`) — never feed content.
- **Bounded + scrubbed.** Each observation carries at most a 4 KiB excerpt of the feed, and that
  excerpt is run through a gitleaks-class secret scrubber first. A second, independent gitleaks
  scan in the workflow fails the job (committing nothing) if anything slips through.
- **Untrusted by origin.** Anything produced here is treated as *untrusted data* by the laptop. It
  can never become a command, and it never carries authority.

If a change would add a secret, fetch a private source, or log feed content, it does not belong in
this repo.

## How it works

```
GitHub-Actions cron (every 30 min)
  → watch.py fetches each public feed in doors.json (https only, 2 MiB cap)
  → sha256 the body; compare to state/hashes.json (the cross-run cache)
  → unchanged  → silent (most runs)
  → moved      → write inbox/<sha256-of-observation>.json  (no timestamp → deterministic)
  → commit inbox/ + state/ back to this repo
laptop (separately)
  → pull this repo, fold each inbox/*.json into the private spine, prune
```

The observation filename is the sha256 of its own bytes, so the laptop verifies integrity by
re-hashing, and a re-observation of an unchanged feed is the same file (deduplicated).

## Files

| Path | What |
|---|---|
| `watch.py` | The standalone, stdlib-only watcher. No third-party imports. |
| `doors.json` | The public door list (id, kind, https endpoint, `data_class: open`, owner domain). |
| `.github/workflows/watch.yml` | The 30-minute sweep + secret-scan + commit-back. |
| `.github/workflows/keepalive.yml` | Weekly heartbeat so scheduled runs aren't auto-disabled at 60 days idle. |
| `inbox/` | Observations awaiting the laptop fold. |
| `state/` | The cross-run last-hash cache + keepalive heartbeat. |

## Running locally

```bash
python watch.py --doors doors.json --inbox inbox --cache state/hashes.json
```

Prints a content-free summary and exits 0 (a per-door fetch failure is contained, not a job
failure).
