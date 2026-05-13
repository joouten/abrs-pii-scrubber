# ABRS PII Scrubber

Reusable Python tool that removes PII from Azure support ticket text
before it crosses an API boundary. Standard library only — no external
dependencies.

Current version: **v0.3.0** — unified label-required patterns for Subscription ID and Tenant ID, with batch pipeline.

## Installation

**Requirements:** Python 3.6 or later. Tested on Python 3.14.3. No external dependencies — standard library only.

1. Clone the repo:
   ```
   git clone https://github.com/joouten/abrs-pii-scrubber.git
   cd abrs-pii-scrubber
   ```

2. Verify your Python version:
   ```
   python --version
   ```

No `pip install` required. The `input/`, `output/`, and `archive/` folders are created automatically on first run.

## Quick Start

1. Drop your source file(s) into the `input/` folder
2. Run the batch scrubber:
   ```
   python batch_scrubber.py
   ```
3. Collect sanitized files from `output/` — filenames are unchanged
4. Review `output/audit_log.txt` to confirm what was replaced
5. Original files with PII are in `archive/` — see the warning below before handling them

## What it scrubs

The scrubber operates on a **label-required** model — UUIDs are only replaced when preceded by a recognised label. Bare UUIDs in free prose are left alone, because real Azure logs are full of workflow, activity, correlation, and job IDs that share the UUID format but carry no PII.

| PII type | Labels | Detection formats | Replacement |
| --- | --- | --- | --- |
| Subscription ID | `subscriptionId`, `subscription_id`, `subscriptions` | JSON key-value, URL path (`/subscriptions/` and `\/subscriptions\/`), key=value, label-colon | `[SUBSCRIPTION_ID]` |
| Tenant ID | `tenantId`, `tenant_id`, `tid`†, `directoryId`, `aadTenant`, `aadTenantId` | JSON key-value, key=value, label-colon | `[TENANT_ID]` |
| Email Address | — | Standard email pattern including `+tags`, subdomains, and long TLDs | `[EMAIL_ADDRESS]` |

† `tid` uses word boundaries — will not match inside words like `resTid`.

There is **no bare-UUID fallback**. An unlabeled UUID in free prose passes through unscrubbed — accepted residual risk in exchange for eliminating false positives (86% false-positive rate measured against a real Azure Site Recovery log with v0.1; v0.3 brings that to 0%).

## Library usage (single string)

```python
from pii_scrubber import scrub

result = scrub(ticket_text)

safe_text  = result["sanitized_text"]
audit_log  = result["audit_log"]
# audit_log: [
#   {"type": "SUBSCRIPTION_ID", "count": int},
#   {"type": "TENANT_ID",       "count": int},
#   {"type": "EMAIL_ADDRESS",   "count": int},
# ]
```

The audit log records **counts only**. Actual PII values are never
logged, returned, or persisted. Show the audit log to the User for
verification before any sanitized text is sent to an external API.

## Batch usage (folder pipeline)

For real workflows — multiple Azure logs per case — use the batch
script. It eliminates the rename friction of running the scrubber file
by file and produces a single auditable trail per run.

```
ABRS_PII_Scrubber/
├── batch_scrubber.py
├── pii_scrubber.py
├── input/          <- drop source files here (any filename, any extension)
├── output/         <- sanitized files appear here with the same filename
│   └── audit_log.txt   <- combined audit log, one per run
└── archive/        <- source files are moved here after processing
```

Run:

```
python batch_scrubber.py
```

What it does:

1. Scans `input/` for files (skips hidden files and any stray `audit_log.txt`).
2. Reads each file with an encoding fallback chain (UTF-8 → UTF-8-sig → latin-1).
3. Calls `scrub()` against the file contents.
4. Writes the sanitized result to `output/<same-filename>`.
5. Moves the source file to `archive/<same-filename>` — never deletes.
   Filename collisions in `archive/` are resolved by appending
   `.YYYYMMDDTHHMMSS` between stem and suffix.
6. Writes `output/audit_log.txt` summarising every file processed plus
   a TOTALS block.

Error handling is per-file: a single unreadable / unwritable file is
logged as `FAILED-READ`, `FAILED-WRITE`, or `WARNING-ARCHIVE` in the
audit log; the batch continues with the remaining files.

> ⚠️ **Archive folder contains original PII**
>
> After each batch run, `archive/` holds the original, unscrubbed source files — the same files you dropped into `input/`. PII is still present in those files.
>
> Treat `archive/` with the same access controls and handling requirements as your source tickets. When originals are no longer needed, delete them manually — the batch script never deletes files automatically.
>
> `archive/` is gitignored and will never enter version control.

### Audit log format

```
ABRS PII SCRUBBER - BATCH AUDIT LOG
Generated: 2026-05-11 13:45:22
Files processed: 2

ticket_001.json
  encoding: utf-8
  status: OK
  SUBSCRIPTION_ID: 3 replaced
  TENANT_ID: 1 replaced
  EMAIL_ADDRESS: 0 replaced

ticket_002.txt
  encoding: utf-8
  status: OK
  SUBSCRIPTION_ID: 0 replaced
  TENANT_ID: 0 replaced
  EMAIL_ADDRESS: 1 replaced

TOTALS
  SUBSCRIPTION_ID: 3 replaced
  TENANT_ID: 1 replaced
  EMAIL_ADDRESS: 1 replaced
```

If the latin-1 fallback fires *and* the decoded text has a suspiciously
high NUL-byte ratio (a tell for UTF-16 content decoded as 8-bit), the
file's entry gets a `WARNING: possible UTF-16 source decoded via
latin-1` note. The output is still written — the warning just flags
that it may be garbled.

`input/`, `output/`, and `archive/` are gitignored. Their contents
never enter version control.

## Run the built-in test suite

```
python pii_scrubber.py
```

Prints scrubbed samples and asserts expected replacement counts across nine cases: plain prose (no labels), URL path, JSON, expanded tenant vocabulary, single-quoted JSON, non-PII control case (`workflowId`, `activityId`, `requestId`, `resTid`), escaped URL slash (`\/subscriptions\/`), key=value tenant (`TenantId=uuid`), and label-colon (`SubscriptionId: uuid`).

## License

MIT.
