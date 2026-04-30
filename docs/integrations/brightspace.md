# D2L Brightspace

## Credentials

Use the **OAuth2 refresh-token flow**. Register an application with your
Brightspace admin and request the minimum scopes needed for the news feed
endpoints listed below (typically within `core:*:*`).

Environment variables:

| Variable | Required | Description |
|---|---|---|
| `BRIGHTSPACE_BASE_URL` | yes | Your Brightspace API host, e.g. `https://example.brightspace.com` |
| `BRIGHTSPACE_CLIENT_ID` | yes | OAuth2 client id |
| `BRIGHTSPACE_CLIENT_SECRET` | yes | OAuth2 client secret |
| `BRIGHTSPACE_REFRESH_TOKEN` | yes | Initial refresh token (will be rotated) |
| `BRIGHTSPACE_API_VERSION` | optional | Valence API version, default `1.26` |
| `BRIGHTSPACE_ORG_UNIT_ID` | optional | If set, per-org-unit news is pulled |
| `BRIGHTSPACE_SCOPE` | optional | OAuth2 scope, default `core:*:*` |

## Refresh-token rotation

Brightspace rotates the refresh token on every access-token request. The
provider persists the new refresh token to
`/app/integration_state/brightspace_refresh.txt` so a restart does not
invalidate access. Protect that file the same way you protect the original
credentials (file permissions, volume encryption).

## Allowed paths

From `scopes.yaml`:

- `GET /d2l/api/lp/{version}/users/whoami`
- `GET /d2l/api/lp/{version}/feed`
- `GET /d2l/api/le/{version}/{org_unit_id}/news/`

The token-issuing host (`auth.brightspace.com`) is distinct from the API
host and is not routed through the scoped client.

## Out of scope

Grades, competencies, and assessment endpoints are not in the allowlist.
