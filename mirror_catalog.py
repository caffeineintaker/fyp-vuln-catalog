#!/usr/bin/env python3
"""
Mirror CISA KEV and FIRST EPSS into a dated, frozen snapshot.

Every run creates   snapshots/<YYYY-MM-DD>/
                        kev.json              CISA Known Exploited Vulnerabilities (full catalog)
                        epss_scores.csv.gz    EPSS scores for every CVE (full daily file)
                        manifest.json         where it came from, versions, counts, SHA-256
and updates         catalog.json          index of all snapshots

A snapshot is never overwritten (that is the point of freezing it) unless you
pass --force. Step 2 reads a snapshot from here instead of the live internet,
so the whole team gets identical results from the same snapshot date.

Usage (inside ~/fyp/vuln-catalog):
    python3 mirror_catalog.py               # snapshot for today (UTC)
    python3 mirror_catalog.py --epss-date 2026-10-28   # EPSS for a specific day
    python3 mirror_catalog.py --force       # re-download today's snapshot

Uses only the Python standard library.
"""
import argparse
import csv
import gzip
import hashlib
import io
import json
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SNAPSHOTS = ROOT / "snapshots"
INDEX = ROOT / "catalog.json"

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # Official CISA mirror on GitHub, used if cisa.gov is unreachable
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
]
EPSS_BASE = "https://epss.empiricalsecurity.com"
UA = {"User-Agent": "fyp-vuln-catalog/1.0 (student research project)"}


def fetch(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def fetch_first(urls, what):
    errors = []
    for u in urls:
        try:
            print(f"  downloading {what}: {u}")
            return fetch(u), u
        except Exception as e:  # try the next source
            errors.append(f"{u}: {e}")
            print(f"    failed: {e}")
    sys.exit(f"Could not download {what}:\n  " + "\n  ".join(errors))


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def parse_epss_header(raw_gz):
    """Return (meta dict from the '#model_version:...,score_date:...' line, row count)."""
    text = gzip.decompress(raw_gz).decode("utf-8")
    lines = text.splitlines()
    meta = {}
    if lines and lines[0].startswith("#"):
        for part in lines[0].lstrip("#").split(","):
            if ":" in part:
                k, v = part.split(":", 1)
                meta[k.strip()] = v.strip()
        lines = lines[1:]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    if reader.fieldnames is None or not {"cve", "epss", "percentile"} <= set(reader.fieldnames):
        sys.exit(f"Unexpected EPSS columns: {reader.fieldnames}")
    rows = sum(1 for _ in reader)
    return meta, rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epss-date", help="EPSS score date YYYY-MM-DD (default: latest published)")
    ap.add_argument("--force", action="store_true", help="overwrite an existing snapshot")
    args = ap.parse_args()

    today = datetime.now(timezone.utc).date()
    snap_name = today.isoformat()
    snap = SNAPSHOTS / snap_name
    if snap.exists() and not args.force:
        sys.exit(f"Snapshot {snap_name} already exists (frozen). Use --force to replace it.")

    print(f"Creating snapshot {snap_name}")

    # --- KEV ---
    kev_raw, kev_url = fetch_first(KEV_URLS, "CISA KEV")
    kev = json.loads(kev_raw)
    kev_count = len(kev.get("vulnerabilities", []))
    if kev_count == 0:
        sys.exit("KEV download has no vulnerabilities - refusing to save it.")

    # --- EPSS ---
    if args.epss_date:
        epss_urls = [f"{EPSS_BASE}/epss_scores-{args.epss_date}.csv.gz"]
    else:
        epss_urls = [f"{EPSS_BASE}/epss_scores-current.csv.gz"] + [
            f"{EPSS_BASE}/epss_scores-{(today - timedelta(days=d)).isoformat()}.csv.gz"
            for d in (0, 1, 2)
        ]
    epss_raw, epss_url = fetch_first(epss_urls, "EPSS")
    epss_meta, epss_rows = parse_epss_header(epss_raw)

    # --- save ---
    snap.mkdir(parents=True, exist_ok=True)
    (snap / "kev.json").write_bytes(kev_raw)
    (snap / "epss_scores.csv.gz").write_bytes(epss_raw)
    manifest = {
        "snapshot": snap_name,
        "downloaded_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "kev": {
            "file": "kev.json",
            "source_url": kev_url,
            "catalog_version": kev.get("catalogVersion"),
            "date_released": kev.get("dateReleased"),
            "count": kev_count,
            "sha256": sha256(kev_raw),
        },
        "epss": {
            "file": "epss_scores.csv.gz",
            "source_url": epss_url,
            "model_version": epss_meta.get("model_version"),
            "score_date": epss_meta.get("score_date"),
            "count": epss_rows,
            "sha256": sha256(epss_raw),
        },
    }
    (snap / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    index = json.loads(INDEX.read_text()) if INDEX.exists() else {"snapshots": []}
    index["snapshots"] = [s for s in index["snapshots"] if s["snapshot"] != snap_name]
    index["snapshots"].append({
        "snapshot": snap_name,
        "kev_catalog_version": manifest["kev"]["catalog_version"],
        "kev_count": kev_count,
        "epss_score_date": manifest["epss"]["score_date"],
        "epss_model_version": manifest["epss"]["model_version"],
        "epss_count": epss_rows,
    })
    index["snapshots"].sort(key=lambda s: s["snapshot"])
    index["latest"] = index["snapshots"][-1]["snapshot"]
    INDEX.write_text(json.dumps(index, indent=2) + "\n")

    print(f"\nSaved snapshots/{snap_name}/")
    print(f"  KEV : {kev_count} vulnerabilities (catalog version {manifest['kev']['catalog_version']})")
    print(f"  EPSS: {epss_rows} CVEs (score date {manifest['epss']['score_date']}, "
          f"model {manifest['epss']['model_version']})")


if __name__ == "__main__":
    main()
