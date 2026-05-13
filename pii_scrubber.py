"""pii_scrubber - Remove PII from Azure support ticket text.

v0.3.0 — Unified label-required matching for both Subscription ID and Tenant ID.

Scrubs three PII types from input text before passing to external APIs:
- Subscription ID: matched when a recognised subscription label
  (subscriptionId, subscription_id, or a /subscriptions/ URL path segment,
  including escaped \/ forms) is followed by a UUID across any common
  Azure-log delimiter — JSON colon-quote, URL slash, escaped slash, equals,
  or whitespace.
- Tenant ID: matched when a recognised tenant label (tenantId, tenant_id,
  tid, directoryId, aadTenant, aadTenantId) is followed by a UUID across
  the same delimiter set — JSON key-value, key=value, and label-colon
  formats all included.
- Email Address.

Bare/unlabeled UUIDs are NOT scrubbed. This is a deliberate v0.3 design
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

__version__ = "0.3.0"

UUID_RE = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

# Shared separator — matches any common label-to-value delimiter in Azure logs.
# Covers: JSON colon-quote, URL slash, escaped slash, equals, whitespace.
_SEP = r"""[\s:="'\/\\]{1,5}"""

# Subscription ID — matches subscriptionId, subscription_id, or /subscriptions/ URL path.
SUBSCRIPTION_PATTERN = re.compile(
    rf"\b(subscription_?id|subscriptions)({_SEP})({UUID_RE})",
    re.IGNORECASE,
)

# Tenant ID — matches all known label aliases.
# \btid\b uses word boundaries to prevent matching 'tid' inside words like 'resTid'.
_TENANT_LABELS = r"(?:aadtenantid|aadtenant|tenantid|tenant_id|directoryid|\btid\b)"
TENANT_PATTERN = re.compile(
    rf"({_TENANT_LABELS})({_SEP})({UUID_RE})",
    re.IGNORECASE,
)

# 4. Email - unchanged from v0.1.0.
EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
)


def scrub(text: str) -> dict:
    counts = {"SUBSCRIPTION_ID": 0, "TENANT_ID": 0, "EMAIL_ADDRESS": 0}

    def _sub_repl(match):
        counts["SUBSCRIPTION_ID"] += 1
        return f"{match.group(1)}{match.group(2)}[SUBSCRIPTION_ID]"

    def _tenant_repl(match):
        counts["TENANT_ID"] += 1
        return f"{match.group(1)}{match.group(2)}[TENANT_ID]"

    def _email_repl(_match):
        counts["EMAIL_ADDRESS"] += 1
        return "[EMAIL_ADDRESS]"

    text = SUBSCRIPTION_PATTERN.sub(_sub_repl, text)
    text = TENANT_PATTERN.sub(_tenant_repl, text)
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

    escaped_url_ticket = (
        r"\"VaultResourceArmId\": \"\/subscriptions\/1e5a0f82-cb0a-4085-88de-cdbeb42ec782"
        r"\/resourceGroups\/rg-prod\""
    )

    key_equals_ticket = "TenantId=650276a4-323f-4f8e-9069-a2e10e21197e"

    label_colon_ticket = "SubscriptionId: 1e5a0f82-cb0a-4085-88de-cdbeb42ec782"

    cases = [
        ("plain prose (no labels)", plain_prose_ticket, (0, 0, 1)),
        ("url path",                url_path_ticket,    (2, 0, 0)),
        ("json",                    json_ticket,        (1, 1, 1)),
        ("expanded tenant",         expanded_tenant_ticket, (0, 5, 0)),
        ("single-quoted json",      single_quoted_ticket,   (1, 0, 0)),
        ("non-PII fields",          non_pii_ticket,         (0, 0, 0)),
        ("escaped url slash",       escaped_url_ticket,     (1, 0, 0)),
        ("key=value tenant",        key_equals_ticket,      (0, 1, 0)),
        ("label colon space",       label_colon_ticket,     (1, 0, 0)),
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

    # v0.3 SUBSCRIPTION_PATTERN matches the URL-path form and replaces the UUID with [SUBSCRIPTION_ID].
    assert SUBSCRIPTION_PATTERN.search(url_path_ticket), (
        "SUBSCRIPTION_PATTERN must match a /subscriptions/<UUID> URL path"
    )
    url_result = scrub(url_path_ticket)
    assert "[SUBSCRIPTION_ID]" in url_result["sanitized_text"], (
        "sanitized output must contain [SUBSCRIPTION_ID]"
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

    # v0.3 contract - bare UUID in plain prose passes through.
    prose_result = scrub(plain_prose_ticket)
    assert "11111111-2222-3333-4444-555555555555" in prose_result["sanitized_text"], (
        "v0.2 contract: unlabeled bare UUIDs in prose must pass through unscrubbed"
    )

    print("All v0.3 tests passed.")
