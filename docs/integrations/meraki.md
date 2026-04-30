# Cisco Meraki connector (`meraki`)

The `integrations` service includes a **read-only** Cisco Meraki Dashboard API
connector that pulls **organization events** and forwards anonymized summaries
to the collector.

## Configuration

Set these env vars (see `.env.example`):

- `MERAKI_API_KEY`: Meraki Dashboard API key
- `MERAKI_ORG_ID`: Organization ID (recommended). If omitted, the connector will
  call `/api/v1/organizations` and use the first org returned.
- `MERAKI_BASE_URL`: defaults to `https://api.meraki.com`

Optional filters:

- `MERAKI_EVENT_TYPES`: comma-separated Meraki event types to include
- `MERAKI_PRODUCT_TYPES`: comma-separated product types
- `MERAKI_LOOKBACK_SECONDS`: when there is no saved cursor yet, pull at most
  this many seconds of history (default: 3600)

## Syncing

Call:

- `POST /sync/meraki` on port 8025 (or via the console proxy)

State is persisted in `integrations/state/meraki.json` (mounted volume). The
connector uses the last `eventId` as its cursor and paginates until it reaches
your requested limit.

## Governance notes

- This connector is **read-only** by construction and cannot change device state.
- Expand `integrations/scopes.yaml` only with explicit sign-off.
- Treat Meraki events as operational/security telemetry; avoid sending raw
  identifiers downstream. This stack anonymizes identifiers before leaving the
  connector container.

