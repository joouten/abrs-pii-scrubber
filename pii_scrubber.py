"""pii_scrubber - Remove PII from Azure support ticket text.

v0.2.0 — Label-required matching only. Bare UUIDs without a recognised
PII-bearing field label pass through unscrubbed.

Scrubs three PII types from input text before passing to external APIs:
- Subscription ID: matched only when the UUID is preceded by a
  /subscriptions/ URL path segment OR keyed by "subscriptionId" in JSON.
- Tenant ID: matched only when the UUID value is keyed by one of
  tenantId, tenant_id, tid, directoryId, aadTenant, or aadTenantId in JSON.
- Email Address.

Bare/unlabeled UUIDs are NOT scrubbed. This is a deliberate v0.2 design
choice after v0.1 testing showed an 86% false-positive rate on real Azure
Site Recovery logs where workflow/activity/correlation IDs are also UUID-
formatted. Residual risk accepted: an unlabeled subscription or tenant
UUID in free prose will leak.

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

__version__ = "0.2.0"

UUID_RE = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

# 1. Subscription ID in ARM-style URL paths: /subscriptions/<UUID>.
SUBSCRIPTION_URL_PATTERN = re.compile(
    rf"(/subscriptions/)({UUID_RE})",
    re.IGNORECASE,
)

# 2. Subscription ID as a quoted JSON key. Handles both double- and
# single-quoted JSON.
SUBSCRIPTION_JSON_PATTERN = re.compile(
    rf"""(["']subscriptionId["']\s*:\s*["'])({UUID_RE})(["'])""",
    re.IGNORECASE,
)

# 3. Tenant ID as a quoted JSON key. Quoted-key context is required so
# the short alias `tid` cannot false-match substrings like "resTid".
_TENANT_KEYS = r"(?:aadTenantId|aadTenant|tenantId|tenant_id|directoryId|tid)"
TENANT_JSON_PATTERN = re.compile(
    rf"""(["']{_TENANT_KEYS}["']\s*:\s*["'])({UUID_RE})(["'])""",
    re.IGNORECASE,
)

# 4. Email - unchanged from v0.1.0.
EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
)


def scrub(text: str) -> dict:
    counts = {"SUBSCRIPTION_ID": 0, "TENANT_ID": 0, "EMAIL_ADDRESS": 0}

    def _sub_url_repl(match):
        counts["SUBSCRIPTION_ID"] += 1
        return f"{match.group(1)}[SUBSCRIPTION_ID]"

    def _sub_json_repl(match):
        counts["SUBSCRIPTION_ID"] += 1
        return f"{match.group(1)}[SUBSCRIPTION_ID]{match.group(3)}"

    def _tenant_repl(match):
        counts["TENANT_ID"] += 1
        return f"{match.group(1)}[TENANT_ID]{match.group(3)}"

    def _email_repl(_match):
        counts["EMAIL_ADDRESS"] += 1
        return "[EMAIL_ADDRESS]"

    text = SUBSCRIPTION_URL_PATTERN.sub(_sub_url_repl, text)
    text = SUBSCRIPTION_JSON_PATTERN.sub(_sub_json_repl, text)
    text = TENANT_JSON_PATTERN.sub(_tenant_repl, text)
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
    plain_prose_ticket = (
        "User reports backup failure for subscription "
        "11111111-2222-3333-4444-555555555555. "
        "Tenant 99999999-8888-7777-6666-444444444444 affected. "
        "Contact user.name+azure@contoso.co.uk for callback."
    )

    url_path_ticket = (
        "Resource: "
        "/subscriptions/12345678-1234-1234-1234-1234567890ab"
        "/resourceGroups/rg-prod/providers/Microsoft.RecoveryServices/vaults/v1. "
        "Same ARM ID appears twice: "
        "/subscriptions/12345678-1234-1234-1234-1234567890ab/resourceGroups/other."
    )

    json_ticket = json.dumps({
        "subscriptionId": "11111111-2222-3333-4444-555555555555",
        "tenantId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "contact": "first.last@mail.sub.example.museum",
        "resourceUuid": "deadbeef-dead-beef-dead-beefdeadbeef",
    })

    expanded_tenant_ticket = json.dumps({
        "tid": "11111111-1111-1111-1111-111111111111",
        "directoryId": "22222222-2222-2222-2222-222222222222",
        "aadTenant": "33333333-3333-3333-3333-333333333333",
        "aadTenantId": "44444444-4444-4444-4444-444444444444",
        "tenant_id": "55555555-5555-5555-5555-555555555555",
    })

    single_quoted_ticket = (
        "{'subscriptionId': '66666666-7777-8888-9999-aaaaaaaaaaaa', "
        "'note': 'log line'}"
    )

    non_pii_ticket = (
        '{"workflowId":"77777777-8888-9999-aaaa-bbbbbbbbbbbb",'
        '"activityId":"88888888-9999-aaaa-bbbb-cccccccccccc",'
        '"requestId":"99999999-aaaa-bbbb-cccc-dddddddddddd",'
        '"resTid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}'
    )

    cases = [
        ("plain prose (no labels)", plain_prose_ticket, (0, 0, 1)),
        ("url path",                url_path_ticket,    (2, 0, 0)),
        ("json",                    json_ticket,        (1, 1, 1)),
        ("expanded tenant",         expanded_tenant_ticket, (0, 5, 0)),
        ("single-quoted json",      single_quoted_ticket,   (1, 0, 0)),
        ("non-PII fields",          non_pii_ticket,         (0, 0, 0)),
    ]

    for label, sample, expected in cases:
        result = scrub(sample)
        counts = (
            result["audit_log"][0]["count"],
            result["audit_log"][1]["count"],
            result["audit_log"][2]["count"],
        )
        print(f"=== {label} ===")
        print(f"sanitized: {result['sanitized_text']}")
        print(f"audit_log: {result['audit_log']}")
        assert counts == expected, (
            f"{label}: expected {expected} (sub, tenant, email), got {counts}"
        )
        print()

    # URL prefix preservation - Pattern 1 must leave /subscriptions/ intact.
    url_result = scrub(url_path_ticket)
    assert "/subscriptions/[SUBSCRIPTION_ID]" in url_result["sanitized_text"], (
        "URL prefix /subscriptions/ must be preserved in sanitized output"
    )
    assert "12345678" not in url_result["sanitized_text"], "URL UUID leaked"

    # tid-substring guard - "resTid" must not be misread as the tenant alias.
    npr_result = scrub(non_pii_ticket)
    assert npr_result["audit_log"][1]["count"] == 0, (
        "non-PII fields must not produce any TENANT_ID - 'resTid' is not 'tid'"
    )
    assert "77777777" in npr_result["sanitized_text"], (
        "bare workflowId UUID must pass through unscrubbed"
    )
    assert "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" in npr_result["sanitized_text"], (
        "resTid UUID must pass through - it is not a recognised tenant label"
    )

    # v0.2 contract - bare UUID in plain prose passes through.
    prose_result = scrub(plain_prose_ticket)
    assert "11111111-2222-3333-4444-555555555555" in prose_result["sanitized_text"], (
        "v0.2 contract: unlabeled bare UUIDs in prose must pass through unscrubbed"
    )

    print("All v0.2 tests passed.")
