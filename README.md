# ABRS PII Scrubber

Reusable Python tool that removes PII from Azure support ticket text
before it crosses an API boundary. Standard library only — no external
dependencies.

Current version: **v0.3.0** (batch pipeline on top of the v0.2 scrubber).

## What it scrubs

The scrubber operates on a **label-required** model — UUIDs are only
replaced when they appear in a recognised, structured context. Bare
UUIDs in free prose are left alone, because real Azure logs are full
of workflow / activity / correlation / job IDs that share the UUID
format but carry no PII.

| PII type | Detection rule | Replacement |
| --- | --- | --- |
| Subscription ID | UUID in a `/subscriptions/<UUID>` URL path | `[SUBSCRIPTION_ID]` (prefix preserved) |
| Subscription ID | `"subscriptionId"` JSON key (single- or double-quoted, case-insensitive) | `[SUBSCRIPTION_ID]` |
| Tenant ID | JSON key in `{tenantId, tenant_id, tid, directoryId, aadTenant, aadTenantId}` | `[TENANT_ID]` |
| Email Address | Standard email pattern, including `+tags`, subdomains, and long TLDs | `[EMAIL_ADDRESS]` |

There is **no bare-UUID fallback**. An unlabeled subscription or tenant
UUID in free prose will pass through unscrubbed — accepted residual
risk in exchange for eliminating the v0.1 false-positive flood
(86% false positives measured against a real 765 KB Azure Site Recovery
log; v0.2 brought that to 0%).

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

Prints scrubbed samples and asserts expected replacement counts across
six cases: plain prose (no labels), URL path, JSON, expanded tenant
vocabulary, single-quoted JSON, and a non-PII control case
(`workflowId`, `activityId`, `requestId`, `resTid`).

## License

MIT.
