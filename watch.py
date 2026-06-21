#!/usr/bin/env python3
"""KAIROS public watcher — a STANDALONE, stdlib-only cloud sense (P3.1 deploy).

This file is the payload of the SEPARATE public repo ``Duckky153/kairos-watchers``. It runs on free
GitHub-Actions cron, polls a committed list of PUBLIC feed URLs (``doors.json``), and — only when a
feed's content hash MOVES (~95% of runs are silent) — writes a content-addressed observation into
``inbox/``. The laptop later pulls + folds each observation into the private KAIROS spine as
UNTRUSTED ``cloud-inbox`` data.

WHY IT IS SELF-CONTAINED (no ``import kairos``):
* The private KAIROS package (the spine, dispatcher, vault, hands) MUST stay private. The public
  watcher carries NONE of it — only the read-only fetch-and-hash core.
* Yet the observation it writes must be BYTE-IDENTICAL to the kairos sweeper's ``build_observation``
  output, because the laptop's ``InboxFold`` is content-addressed (the file name stem == the sha256
  of its bytes). So the JSON shape, the serialization, and the secret scrub below are faithful ports
  of the private modules; a kairos-side test (``tests/test_doors_public_deploy.py``) pins that
  byte-identity so the two copies can never drift.

THE NO-SECRETS CONTRACT (Lock #7 / invariant 7):
* The watcher uses NO credentials of any kind — no OAuth, no kairos-bot key, no model-provider key,
  no Actions secret. It fetches only PUBLIC feeds over https. Logs are CONTENT-FREE (counts + public
  door ids). The feed excerpt carried in each observation is bounded AND secret-scrubbed, so even a
  feed that accidentally contains a credential cannot leak it onto the spine or into this repo.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple
from urllib.parse import urlparse

# --------------------------------------------------------------------------- #
# Observation shape (faithful port of kairos.doors.sweeper) — DO NOT diverge.
# --------------------------------------------------------------------------- #
OBSERVATION_TYPE = "door.observation"
MAX_EXCERPT_BYTES = 4096
_SCRUB_WINDOW_BYTES = 256 * 1024

# Fetch bounds (faithful port of kairos.doors.watcher).
MAX_FETCH_BYTES = 2 * 1024 * 1024
DEFAULT_TIMEOUT_S = 20.0


class Door(NamedTuple):
    """A public door row from ``doors.json``. All fields are plain strings (``kind`` /
    ``data_class`` are the StrEnum *values* the kairos registry uses, so the observation payload
    matches byte-for-byte)."""

    door_id: str
    kind: str
    endpoint: str
    data_class: str
    owner_domain: str


# --------------------------------------------------------------------------- #
# Secret scrub — a VERBATIM port of kairos.retrieval.secret_scrub.scrub_text (P1.10-C / JCODE #15).
# Returns just the scrubbed string (the public watcher needs no Finding provenance). Kept rule-for-
# rule identical to the private module; the parity test goes RED on any divergence.
# --------------------------------------------------------------------------- #
_PLACEHOLDER = "[REDACTED:{}]"

_GENERIC = re.compile(
    r"""(?ix)
    \b
    (?: [a-z0-9_.\-]* )                                  # optional owning prefix
    (?: api[_-]?key | apikey
      | secret[_-]?access[_-]?key | secret[_-]?key | client[_-]?secret | secret
      | access[_-]?token | access[_-]?key
      | auth[_-]?token | refresh[_-]?token | bearer[_-]?token | token
      | passwd | password | passphrase
      | private[_-]?key | credential )
    \s* [:=] \s*
    ['"]?
    # value excludes [] so the [REDACTED:..] placeholder can't re-trip on a 2nd pass
    (?P<value> [^\s'"`,;\[\]]{12,} )
    """,
)
_CONN_URI = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:(?P<pw>[^\s:/@]+)@")
_BEARER = re.compile(r"(?i)\bbearer\s+(?P<tok>[A-Za-z0-9._\-]{16,})")

_RULES: list[tuple[str, re.Pattern[str], int | str]] = [
    (
        "private-key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
            r"(?:(?!-----BEGIN)[\s\S])*?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        0,
    ),
    (
        "aws-access-key-id",
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16}\b"),
        0,
    ),
    ("github-fine-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), 0),
    ("github-pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), 0),
    ("stripe-key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), 0),
    ("stripe-webhook", re.compile(r"\bwhsec_[A-Za-z0-9]{20,}"), 0),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,40}"), 0),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), 0),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b"), 0),
    ("gitlab-pat", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}"), 0),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}"), 0),
    ("shopify-token", re.compile(r"\bshp(?:at|ca|pa|ss)_[A-Za-z0-9]{20,}"), 0),
    ("digitalocean-token", re.compile(r"\bdo[opr]_v1_[A-Za-z0-9]{20,}"), 0),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"), 0),
    ("twilio-key", re.compile(r"\bSK[0-9a-f]{32}\b"), 0),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"), 0),
    ("slack-app-token", re.compile(r"\bxapp-[A-Za-z0-9\-]{10,}"), 0),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+"), 0),
    (
        "discord-webhook",
        re.compile(
            r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"
        ),
        0,
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), 0),
    ("conn-uri-credential", _CONN_URI, "pw"),
    ("bearer-token", _BEARER, "tok"),
    ("generic-api-key", _GENERIC, "value"),
]


def scrub_text(text: str) -> str:
    """Redact every gitleaks-class secret in ``text`` and return the index-safe string. A non-str
    input fails CLOSED to an empty string (an unscannable chunk is suppressed). Byte-for-byte
    equivalent to ``kairos.retrieval.secret_scrub.scrub_text(text).text``."""
    if not isinstance(text, str):
        return ""

    raw: list[tuple[int, int, str]] = []
    for rule_id, pattern, group in _RULES:
        for m in pattern.finditer(text):
            start, end = m.span(group)
            if start < 0 or end <= start:
                continue
            raw.append((start, end, rule_id))
    if not raw:
        return text

    raw.sort(key=lambda t: (t[0], t[1]))
    merged: list[tuple[int, int, set[str]]] = []
    cur_start, cur_end, cur_ids = raw[0][0], raw[0][1], {raw[0][2]}
    for start, end, rule_id in raw[1:]:
        if start < cur_end:
            cur_end = max(cur_end, end)
            cur_ids.add(rule_id)
        else:
            merged.append((cur_start, cur_end, set(cur_ids)))
            cur_start, cur_end, cur_ids = start, end, {rule_id}
    merged.append((cur_start, cur_end, set(cur_ids)))

    out: list[str] = []
    cursor = 0
    for start, end, ids in merged:
        out.append(text[cursor:start])
        out.append(_PLACEHOLDER.format("+".join(sorted(ids))))
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


# --------------------------------------------------------------------------- #
# Observation builder — faithful port of kairos.doors.sweeper.build_observation.
# --------------------------------------------------------------------------- #
def _excerpt(body: bytes) -> str:
    """A bounded, secret-scrubbed text preview. Scrub a window WIDER than the excerpt first (so a
    secret straddling the cut is still seen whole), THEN cap to ``MAX_EXCERPT_BYTES`` UTF-8."""
    text = body[:_SCRUB_WINDOW_BYTES].decode("utf-8", errors="replace")
    scrubbed = scrub_text(text).encode("utf-8")[:MAX_EXCERPT_BYTES]
    return scrubbed.decode("utf-8", errors="ignore")


def build_observation(door: Door, *, body: bytes) -> tuple[bytes, str, str]:
    """Build the deterministic, content-addressed observation for ``(door, body)``. Returns
    ``(canonical_json_bytes, filename, feed_hash)``. No timestamp -> identical bytes for the same
    feed state (the laptop inbox-fold dedups a re-observation by content hash)."""
    feed_hash = hashlib.sha256(body).hexdigest()
    obj = {
        "type": OBSERVATION_TYPE,
        "domain": door.owner_domain,
        "payload": {
            "door_id": door.door_id,
            "kind": door.kind,
            "data_class": door.data_class,
            "content_sha256": feed_hash,
            "byte_len": len(body),
            "excerpt": _excerpt(body),
        },
    }
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    name = hashlib.sha256(data).hexdigest() + ".json"
    return data, name, feed_hash


# --------------------------------------------------------------------------- #
# Bounded https-only fetch (faithful port of kairos.doors.watcher).
# --------------------------------------------------------------------------- #
class FetchError(Exception):
    """A door fetch failed or was refused (non-https / oversize / network error)."""


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow a redirect to a non-https target (blocks an https->http downgrade or a
    scheme pivot to cloud-metadata / localhost). Returning None makes urllib raise the 3xx."""

    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        if not newurl.startswith("https://"):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _default_open(url: str, timeout: float) -> Any:
    opener = urllib.request.build_opener(_HttpsOnlyRedirect)
    return opener.open(url, timeout=timeout)


def http_fetch(
    door: Door,
    *,
    timeout: float = DEFAULT_TIMEOUT_S,
    _open: Callable[[str, float], Any] | None = None,
) -> bytes:
    """GET ``door.endpoint`` over https, bounded by ``MAX_FETCH_BYTES`` and ``timeout``. Refuses a
    non-https URL and an over-cap body (fail-closed). ``_open`` is a test seam."""
    url = door.endpoint
    if not url.startswith("https://"):
        raise FetchError(f"refusing non-https endpoint: {url!r}")
    open_url = _open or _default_open
    try:
        with open_url(url, timeout) as resp:
            data = resp.read(MAX_FETCH_BYTES + 1)
    except OSError as e:
        raise FetchError(f"fetch failed: {type(e).__name__}") from e
    if len(data) > MAX_FETCH_BYTES:
        raise FetchError(f"response exceeds the {MAX_FETCH_BYTES}-byte cap")
    return bytes(data)


# --------------------------------------------------------------------------- #
# Cross-run last-hash cache (faithful port) + the public door list loader.
# --------------------------------------------------------------------------- #
def load_cache(path: Path) -> dict[str, str]:
    """Load the per-door last-hash cache, FAIL-CLOSED. A missing/malformed/non-object file loads as
    ``{}``; only ``str -> str`` entries survive (a dropped entry causes at most a content-addressed
    re-emit the laptop dedups)."""
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}


def save_cache(path: Path, hashes: dict[str, str]) -> None:
    """Persist the last-hash cache atomically (tmp -> os.replace; parent created)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(dict(hashes), sort_keys=True))
    os.replace(tmp, p)


def load_doors(path: Path) -> list[Door]:
    """Load the committed public door list. Each row must be a cloud (``github_release`` / ``http``)
    door with an https endpoint and ``data_class == "open"`` — a public feed carries nothing
    private.
    Any row that is not a well-formed open cloud door is REJECTED (fail-closed), never silently
    fetched."""
    rows = json.loads(Path(path).read_text())
    if not isinstance(rows, list):
        raise ValueError("doors.json must be a JSON array")
    doors: list[Door] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"door row must be an object, got {type(row).__name__}")
        d = Door(
            door_id=str(row["door_id"]),
            kind=str(row["kind"]),
            endpoint=str(row["endpoint"]),
            data_class=str(row["data_class"]),
            owner_domain=str(row["owner_domain"]),
        )
        if d.kind not in ("github_release", "http"):
            raise ValueError(f"door {d.door_id}: only cloud kinds allowed, got {d.kind!r}")
        if d.data_class != "open":
            raise ValueError(f"door {d.door_id}: public list is open-only, got {d.data_class!r}")
        parsed = urlparse(d.endpoint)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError(f"door {d.door_id}: endpoint must be a well-formed https:// URL")
        if parsed.username or parsed.password:
            # A ``https://user:pass@host`` endpoint committed to a PUBLIC repo IS a published
            # credential — the one thing this repo must never carry (the no-secrets contract).
            # (Broader host/IP allowlisting — blocking internal targets — is the documented
            # deploy-time residual, consistent with the private registry's stated boundary.)
            raise ValueError(f"door {d.door_id}: endpoint must not embed credentials")
        if d.door_id in seen:
            raise ValueError(f"duplicate door_id: {d.door_id}")
        seen.add(d.door_id)
        doors.append(d)
    return doors


# --------------------------------------------------------------------------- #
# Sweep + runner.
# --------------------------------------------------------------------------- #
def run_watcher(
    doors: list[Door],
    *,
    inbox_dir: Path,
    cache_path: Path,
    fetch: Callable[[Door], bytes] = http_fetch,
) -> tuple[int, int, int, list[str]]:
    """Sweep every door, emit an observation on a hash-move, persist the advanced cache. Per-door
    contained: a fetch/build/write fault is recorded and the sweep moves on (a hostile or
    unreachable feed must never halt the watcher). Returns ``(emitted, silent, errors,
    emitted_door_ids)``."""
    last = load_cache(cache_path)
    new_hashes = dict(last)
    inbox_dir.mkdir(parents=True, exist_ok=True)
    emitted = silent = errors = 0
    emitted_ids: list[str] = []
    for door in doors:
        try:
            body = fetch(door)
            feed_hash = hashlib.sha256(body).hexdigest()
            if feed_hash == last.get(door.door_id):
                silent += 1
                continue
            data, name, _ = build_observation(door, body=body)
            final = inbox_dir / name
            tmp = inbox_dir / (name + ".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, final)  # atomic; advance the cache only after a successful write
            new_hashes[door.door_id] = feed_hash
            emitted += 1
            emitted_ids.append(door.door_id)
        except Exception as exc:
            errors += 1
            print(f"door.error {door.door_id} {type(exc).__name__}", file=sys.stderr)
    save_cache(cache_path, new_hashes)
    return emitted, silent, errors, emitted_ids


def main(argv: list[str] | None = None, *, fetch: Callable[[Door], bytes] = http_fetch) -> int:
    """The Actions cron entry point. Prints CONTENT-FREE ``run.started`` / ``run.completed`` lines
    (counts + public door ids only — NEVER feed content or secrets, Lock #7). Returns 0 (a per-door
    fault is contained, not a job failure; door-health is a laptop-side projection)."""
    parser = argparse.ArgumentParser(prog="watch.py", description="KAIROS public cloud watcher")
    parser.add_argument(
        "--doors", required=True, type=Path, help="the public door list (doors.json)"
    )
    parser.add_argument("--inbox", required=True, type=Path, help="dir to write inbox observations")
    parser.add_argument("--cache", required=True, type=Path, help="cross-run last-hash cache file")
    args = parser.parse_args(argv)

    doors = load_doors(args.doors)
    print(f"run.started doors={len(doors)}")
    emitted, silent, errors, ids = run_watcher(
        doors, inbox_dir=args.inbox, cache_path=args.cache, fetch=fetch
    )
    if emitted == 0:
        print(
            f"run.completed [SILENT] swept={len(doors)} emitted=0 silent={silent} errors={errors}"
        )
    else:
        print(
            f"run.completed swept={len(doors)} emitted={emitted} ({','.join(ids)}) "
            f"silent={silent} errors={errors}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
