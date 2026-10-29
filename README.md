# FYP vulnerability catalog (CISA KEV + EPSS mirror)

Frozen, dated copies of the two exploitability datasets used in Step 2.
Every team member points Step 2 at the **same snapshot date**, so Python,
JavaScript and Java results are enriched with identical data.

| Dataset | What it says | Source |
|---|---|---|
| CISA KEV | This CVE **has been exploited** in the wild | https://www.cisa.gov/known-exploited-vulnerabilities-catalog (mirror: https://github.com/cisagov/kev-data) |
| EPSS | Probability (0-1) this CVE **will be exploited** in the next 30 days, plus its percentile | https://www.first.org/epss/ (daily files: https://epss.empiricalsecurity.com) |

## Layout

```
catalog.json                    index of snapshots, "latest" = newest
snapshots/<YYYY-MM-DD>/
    kev.json                    full KEV catalog as downloaded
    epss_scores.csv.gz          full EPSS file (cve, epss, percentile)
    manifest.json               source URLs, KEV catalog version, EPSS score date
                                and model version, row counts, SHA-256 of each file
mirror_catalog.py               creates a new snapshot
```

## Make a snapshot

```bash
python3 mirror_catalog.py
git add . && git commit -m "Snapshot $(date -u +%F)" && git push
```

Snapshots are never overwritten (`--force` to override), so a snapshot used in
the report always stays exactly as it was. Check a file is untouched with
`sha256sum snapshots/<date>/kev.json` against `manifest.json`.

## Use it in Step 2

```bash
python3 step2.py --catalog ~/fyp/vuln-catalog --snapshot <YYYY-MM-DD>
```
