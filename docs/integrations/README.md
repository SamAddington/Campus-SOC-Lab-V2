# Integrations & connectors

The `integrations` service pulls events from supported platforms (LMS + opt-in
network / identity connectors) and forwards **anonymized summaries** to the
collector using the existing `/ingest` contract. It runs on port **8025**.

## Design principles

1. **Read-only by construction.** Every provider has a path allowlist in
   `integrations/scopes.yaml`. The HTTP client refuses requests outside the
   allowlist. Widening the allowlist is a governance change.
2. **Anonymize at the source.** User IDs and emails are HMAC-hashed *before*
   the request leaves the integrations container, using the same
   `HMAC_SECRET` the collector uses. The collector never sees raw LMS
   identifiers even on the internal Docker network.
3. **Degrade cleanly.** Missing credentials never throw 5xx. `/sync`
   returns a `warnings` list and `pulled=0` so operators can see exactly
   why a sync returned nothing.
4. **Rate-limited.** Each provider has a token bucket sized for the
   vendor's published limits. Burst requests never exceed the bucket.
5. **Minimum data.** We pull only the fields we need for detection: author
   id, message body, coarse event type, timestamp, locale hint. We never
   pull grades, submissions, quiz answers, or gradebook data.

## Supported providers

| Slug | Platform | Auth | Notes |
|---|---|---|---|
| `canvas` | Canvas LMS (Instructure) | Bearer token | [canvas.md](canvas.md) |
| `blackboard` | Blackboard Learn | OAuth2 client-credentials | [blackboard.md](blackboard.md) |
| `moodle` | Moodle | Web Services token | [moodle.md](moodle.md) |
| `brightspace` | D2L Brightspace | OAuth2 refresh token | [brightspace.md](brightspace.md) |
| `meraki` | Cisco Meraki Dashboard | API key header | [meraki.md](meraki.md) |
| `duo` | Cisco Duo Admin API | HMAC-signed requests | Pulls auth/admin logs (read-only) |
| `umbrella` | Cisco Umbrella Reporting | Bearer token | Pulls activity report rows (read-only) |
| `ise` | Cisco ISE | Basic auth | Pulls active-session summary (read-only, minimal) |
| `firepower` | Cisco Firepower FMC | Token (basic → header) | Pulls audit record summaries (read-only) |
| `restconf` | RESTCONF (generic) | Bearer token | Gets one bounded model snapshot |
| `snmp` | SNMP polling (generic) | Community | Device allowlist required |
| `netconf` | NETCONF polling (generic) | Username/password | Device allowlist required |
| `ssh_poll` | SSH polling (generic) | Password/key | Device allowlist required |

## Endpoints

```text
GET  /health                 service + HMAC + per-provider configured booleans
GET  /providers              per-provider status, allowlisted paths, credentials_present
GET  /sources                scope allowlist per provider
POST /sync/{provider}        pull once and forward to collector
GET  /status                 aggregated last-sync state
GET  /state/{provider}       single provider state
POST /webhook/{provider}     record a push notification (does not trust payload)
```

Example dry-run against Canvas to preview the anonymized payload without
calling the collector:

```bash
curl -X POST http://localhost:8025/sync/canvas \
  -H "Content-Type: application/json" \
  -d '{"limit":5,"dry_run":true}'
```

## Scheduling

The service does not run its own cron. Any scheduler that can POST HTTP
works. For the workshop a host cron entry is the simplest option:

```cron
*/15 * * * * curl -sS -X POST -H 'content-type: application/json' \
  -d '{"limit":50}' http://localhost:8025/sync/canvas > /dev/null
```

## Governance checklist

Before enabling a provider in production:

- [ ] `HMAC_SECRET` is set to a non-default value.
- [ ] The API token has only the minimum scopes required for the
      endpoints listed in `scopes.yaml` for that provider.
- [ ] The token is stored outside the repository (env file, secret store,
      or mounted secret). Never committed.
- [ ] Rate limit for the token is verified with the vendor and matches
      the provider's `capacity` / `refill_per_sec` in `rate_limiter.py`.
- [ ] An operator has reviewed a `dry_run=true` payload for at least one
      event and confirmed no raw identifiers are present.
