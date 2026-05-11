"""pii_scrubber - Remove PII from Azure support ticket text.

Scrubs three PII types from input text before passing to external APIs:
- Subscription ID (UUID preceded by the keyword "subscription")
- Tenant ID (UUID preceded by the keyword "tenant")
- Email Address

Bare UUIDs with no label default to [SUBSCRIPTION_ID] as the safe fallback.
Returns sanitized text plus an audit log with replacement counts only -
actual PII values are never logged or returned.

Usage:
    from pii_scrubber import scrub

    result = scrub(ticket_text)
    safe_text = result["sanitized_text"]
    counts = result["audit_log"]
"""

import json
import re

UUID_RE = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

# Characters allowed between the label keyword and the UUID. Covers JSON
# (`Id":"`), URL paths (`/`), and prose (`: `, ` ID `, etc.). Non-greedy and
# bounded so the engine picks the nearest UUID after the keyword.
_GAP_RE = r"[\w\s:=\"'/_.\-]{0,40}?"

SUBSCRIPTION_PATTERN = re.compile(
    rf"(?i)(\bsubscription{_GAP_RE})({UUID_RE})\b"
)
TENANT_PATTERN = re.compile(
    rf"(?i)(\btenant{_GAP_RE})({UUID_RE})\b"
)
BARE_UUID_PATTERN = re.compile(rf"(?i)\b{UUID_RE}\b")
EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
)


def scrub(text: str) -> dict:
    counts = {"SUBSCRIPTION_ID": 0, "TENANT_ID": 0, "EMAIL_ADDRESS": 0}

    def _sub_repl(match):
        counts["SUBSCRIPTION_ID"] += 1
        return f"{match.group(1)}[SUBSCRIPTION_ID]"

    def _tenant_repl(match):
        counts["TENANT_ID"] += 1
        return f"{match.group(1)}[TENANT_ID]"

    def _bare_uuid_repl(_match):
        counts["SUBSCRIPTION_ID"] += 1
        return "[SUBSCRIPTION_ID]"

    def _email_repl(_match):
        counts["EMAIL_ADDRESS"] += 1
        return "[EMAIL_ADDRESS]"

    text = SUBSCRIPTION_PATTERN.sub(_sub_repl, text)
    text = TENANT_PATTERN.sub(_tenant_repl, text)
    text = BARE_UUID_PATTERN.sub(_bare_uuid_repl, text)
    text = EMAIL_PATTERN.sub(_email_repl, text)

    return {
        "sanitized_text": text,
        "audit_log": [
            {"type": "SUBSCRIPTION_ID", "count": counts["SUBSCRIPTION_ID"]},
            {"type": "TENANT_ID", "count": counts["TENANT_ID"]},
            {"type": "EMAIL_ADDRESS", "count": counts["EMAIL_ADDRESS"]},
        ],
    }


if __name__ == "__main__":
    plain_ticket = (
        "User reports backup failure on subscription "
        "11111111-2222-3333-4444-555555555555 in tenant "
        "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE. "
        "Contact user.name+azure@contoso.co.uk for callback. "
        "Orphan resource UUID: 99999999-8888-7777-6666-555555555555. "
        "Same subscription 11111111-2222-3333-4444-555555555555 reappears."
    )

    json_ticket = json.dumps({
        "subscriptionId": "12345678-1234-1234-1234-1234567890ab",
        "tenantId": "abcdef01-2345-6789-abcd-ef0123456789",
        "contact": "first.last@mail.sub.example.museum",
        "resourceUuid": "deadbeef-dead-beef-dead-beefdeadbeef",
    })

    for label, sample in (("plain", plain_ticket), ("json", json_ticket)):
        result = scrub(sample)
        print(f"=== {label} ===")
        print(f"sanitized: {result['sanitized_text']}")
        print(f"audit_log: {result['audit_log']}")
        print()

    plain_result = scrub(plain_ticket)
    assert plain_result["audit_log"][0]["count"] == 3, (
        f"plain: expected 3 SUBSCRIPTION_ID, got {plain_result['audit_log'][0]['count']}"
    )
    assert plain_result["audit_log"][1]["count"] == 1, "plain: expected 1 TENANT_ID"
    assert plain_result["audit_log"][2]["count"] == 1, "plain: expected 1 EMAIL_ADDRESS"
    assert "11111111" not in plain_result["sanitized_text"], "plain: subscription UUID leaked"
    assert "AAAAAAAA" not in plain_result["sanitized_text"].upper() or \
        plain_result["sanitized_text"].upper().count("AAAAAAAA") == 0, "plain: tenant UUID leaked"
    assert "contoso" not in plain_result["sanitized_text"], "plain: email leaked"
    assert "99999999" not in plain_result["sanitized_text"], "plain: bare UUID leaked"

    json_result = scrub(json_ticket)
    assert json_result["audit_log"][0]["count"] == 2, (
        f"json: expected 2 SUBSCRIPTION_ID (labeled + bare), got {json_result['audit_log'][0]['count']}"
    )
    assert json_result["audit_log"][1]["count"] == 1, "json: expected 1 TENANT_ID"
    assert json_result["audit_log"][2]["count"] == 1, "json: expected 1 EMAIL_ADDRESS"
    assert "12345678" not in json_result["sanitized_text"], "json: subscription UUID leaked"
    assert "abcdef01" not in json_result["sanitized_text"], "json: tenant UUID leaked"
    assert "deadbeef" not in json_result["sanitized_text"], "json: bare UUID leaked"
    assert "example.museum" not in json_result["sanitized_text"], "json: long-TLD email leaked"

    print("All tests passed.")
