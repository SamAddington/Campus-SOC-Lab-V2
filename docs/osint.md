# OSINT enrichment

The `osint` service adds **external threat-intel context** to events
without changing the action model: it is a *proposer*, like the LMS
integrations and the traffic ingestor. It never enforces, never blocks,
and never takes an autonomous action. Everything it produces is a
structured summary that the policy engine and the LLM assistant can
read.

## What gets enriched

Indicators are extracted locally from each event's `message` field:

* URLs (`http://`, `https://`)
* Domains (DNS labels with a known TLD)
* IPv4 / IPv6 addresses (public only -- private ranges are rejected)
* File hashes (MD5/SHA-1/SHA-256)

Defanged forms (`hxxps://evil[.]com`) are refanged before extraction so
analysts can forward pre-obfuscated indicators safely.

## What never leaves the stack

The following are **never** sent to any OSINT provider:

* `user_id`, `user_id_hash`, `anon_user`
* Email address or its hash
* The full message body (only the extracted indicator is forwarded)
* Any traffic-anomaly event (`source: traffic_anomaly` is skipped by
  the orchestrator because synthesized messages have no meaningful
  indicators)
* Any private / loopback / link-local / reserved IP (rejected at
  extraction)

## Providers

| Provider | Key required? | Indicators supported | Notes |
|---|---|---|---|
| VirusTotal v3 | Yes (`VT_API_KEY`) | URL, domain, IP, hash | Uses `last_analysis_stats`; no file upload |
| URLhaus (abuse.ch) | No | URL, host | Free, generous RPM |
| AbuseIPDB | Yes (`ABUSEIPDB_API_KEY`) | IP | `abuseConfidenceScore` mapped to verdict |
| AlienVault OTX | Yes (`OTX_API_KEY`) | URL, domain, IP, hash | Uses pulse count |
| Phishtank | Optional (`PHISHTANK_API_KEY`, `PHISHTANK_APP_KEY`) | URL | Verified entries = malicious |
| OpenPhish | No | URL | Bulk feed, cached in memory |
| MITRE (local) | n/a | Event context | No network call; maps event_type to a MITRE technique |

Enabling any key-required provider is opt-in: leaving the key blank in
`.env` keeps it disabled, period.

## Scope allowlist

Every outbound HTTP request is validated against `osint/scopes.yaml`
by `http_client.ScopedHTTP` **before** it is sent:

```yaml
providers:
  virustotal:
    base_url: https://www.virustotal.com
    allow:
      - method: GET
        path_prefix: /api/v3/urls/
      - method: GET
        path_prefix: /api/v3/domains/
      ...
```

A misconfigured provider cannot call anything not in the allowlist.
Adding a new lookup requires editing both the provider class *and*
`scopes.yaml` -- a governance reviewer needs to sign off on both.

## Aggregation and verdicts

For each indicator we collect findings from every applicable provider,
then reduce to one of four verdicts:

* `malicious` -- at least one provider said malicious with confidence.
* `suspicious` -- one or more providers flagged it but without strong
  consensus.
* `benign` -- every provider that returned data said it was clean.
* `unknown` -- no provider returned signal (new indicator, no API
  coverage, etc.).

The aggregated event verdict is the worst verdict across indicators.
An event with five benign indicators and one malicious indicator is
malicious.

## Cache

All provider summaries are cached with **HMAC-keyed** cache keys:

```
key = HMAC-SHA256(HMAC_SECRET, f"{provider}|{kind}|{value}")[:24]
```

The raw indicator is never stored as a key, so reading a cache dump
does not reveal the list of indicators that have been checked. Clean
results are cached for `OSINT_CACHE_TTL_CLEAN` seconds (default 24h);
hits (malicious/suspicious) are cached for `OSINT_CACHE_TTL_HIT` (1h)
because threat-intel changes fast once something becomes "known bad".

## How the orchestrator uses it

```
collector -> detector -> OSINT enrichment (opt-in) -> policy engine -> LLM assist -> audit
```

Enrichment runs when:

* `source == "email_gateway"` (indicator density is high), **or**
* `risk_score_rule >= OSINT_MIN_RULE_SCORE` (default 0.40) for any
  other source,
* **and** the source is not `traffic_anomaly`.

The policy engine sees `osint_verdict` (and `osint_score`,
`osint_indicator_count`) as `features`, which means rules can match on
them:

```yaml
- id: OSINT-MALICIOUS-001
  when:
    feature_flags:
      osint_verdict: malicious
  action: escalate
  requires_human_review: true
```

The LLM assistant receives a short natural-language summary of the
OSINT findings so its explanation can cite them without being given
raw provider payloads.

## Decision card fields

Each decision card gains the following (all optional for backward
compatibility):

```json
{
  "osint_enabled": true,
  "osint_skipped": false,
  "osint_verdict": "malicious",
  "osint_score": 0.78,
  "osint_indicator_count": 2,
  "osint_providers_used": ["virustotal", "urlhaus"],
  "osint_short_explanation": "2 indicator(s) checked across 2 provider(s); aggregate verdict is known malicious."
}
```

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness + HMAC-keyed check + enabled providers |
| `GET /status` | Full config, cache stats, provider caps |
| `GET /providers` | Each provider and what kinds of indicators it supports |
| `GET /cache/stats` | Cache hit/miss counters |
| `POST /cache/clear` | Drop the cache |
| `POST /enrich` | Explicit indicator list (for tools and the simulator) |
| `POST /enrich_event` | Raw message -> extraction -> enrichment -> explanation |

## Example

```bash
curl -sX POST localhost:8028/enrich_event -H 'content-type: application/json' -d '{
  "message": "Reset your password now at https://login-example.invalid/reset or call 10.0.0.5",
  "event_type": "suspicious_email"
}' | jq .
```

The private IP `10.0.0.5` is dropped at extraction; only the external
URL is forwarded to providers, and the response is refanged in the
`per_indicator.value` field for safe display.

## Governance posture

| Concern | How we address it |
|---|---|
| PII leaving the deployment | Only indicators are sent; user IDs and emails are never serialized to any provider |
| Accidental lookups of internal ranges | Private IPv4/IPv6 rejected at extraction (`OSINT_REJECT_PRIVATE_IPS=1`) |
| Runaway costs / rate-limit blowups | Per-event caps (`OSINT_MAX_URLS`, etc.) + per-provider token-bucket rate limiters + per-enrichment deadline |
| Cache re-identification | Cache keys are HMAC-SHA256 of `(provider, kind, indicator)`, truncated to 24 hex chars |
| Scope creep | Every outbound call validated against `scopes.yaml`; a new endpoint requires an explicit allowlist edit |
| Proposer vs. enforcer | Policy engine always adjudicates; no OSINT rule permits an automated enforcement action |

## When not to trust a verdict

* `osint_verdict == unknown` combined with `providers_errored` being
  non-empty -- your outbound connectivity to providers is degraded.
* `deadline_reached: true` in the summary -- some providers were
  skipped for this event; run a manual `POST /enrich` after triage.
* `indicator_count == 0` -- nothing was extracted. The OSINT verdict
  is uninformative; rely on the detector's signal.
