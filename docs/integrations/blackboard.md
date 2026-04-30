# Blackboard Learn

## Credentials

Register a REST application in the **Developer Portal** and have your
Blackboard admin approve it for the target Learn instance. The application
key / secret pair is used for the OAuth2 client-credentials grant.

Environment variables:

| Variable | Required | Description |
|---|---|---|
| `BLACKBOARD_BASE_URL` | yes | e.g. `https://learn.example.edu` |
| `BLACKBOARD_APP_KEY` | yes | REST application key |
| `BLACKBOARD_APP_SECRET` | yes | REST application secret |

## Allowed endpoints

From `scopes.yaml`:

- `POST /learn/api/v1/oauth2/token` (token issuance only)
- `GET /learn/api/public/v1/announcements`
- `GET /learn/api/public/v1/users/{user_id}/messages`
- `GET /learn/api/public/v3/courses/{course_id}/messages`

The admin should grant the application only the **entitlements** matching
these endpoints. Blackboard applies entitlements server-side.

## Token lifecycle

Access tokens expire (typically 3600s). The provider caches the token in
process memory and refreshes it 60s before expiry. A restart forces a
fresh token request.

## Out of scope

Grade Center, Content items, and Assessment endpoints are not in the
allowlist.
