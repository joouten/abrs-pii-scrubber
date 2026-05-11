# ABRS PII Scrubber

Reusable Python module that removes PII from Azure support ticket text
before it crosses an API boundary. Standard library only — no external
dependencies.

## What it scrubs

| PII type | Detection rule | Replacement |
| --- | --- | --- |
| Subscription ID | UUID preceded by the keyword `subscription` (case insensitive) | `[SUBSCRIPTION_ID]` |
| Tenant ID | UUID preceded by the keyword `tenant` (case insensitive) | `[TENANT_ID]` |
| Bare UUID | Any UUID not caught by a label above | `[SUBSCRIPTION_ID]` (safe default) |
| Email Address | Standard email pattern, including `+tags`, subdomains, and long TLDs | `[EMAIL_ADDRESS]` |

Patterns are applied in the order shown — labeled patterns first, bare-UUID
fallback last — so a Tenant ID is never misclassified as a Subscription ID.

## Usage

```python
from pii_scrubber import scrub

result = scrub(ticket_text)

safe_text = result["sanitized_text"]
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

## Input formats

`scrub()` accepts any string. It has been tested against:

- Plain prose support tickets
- JSON payloads with escaped quotes (Azure log shape)
- The same UUID repeated multiple times in one ticket (global replace)
- Email edge cases: `+` tags, multiple subdomains, long TLDs (`.museum`)

## Run the built-in test

```
python pii_scrubber.py
```

Prints scrubbed samples and asserts the expected replacement counts.

## License

MIT.
