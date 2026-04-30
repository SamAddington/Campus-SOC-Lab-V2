# Canvas LMS

## Credentials

Create a **Canvas API access token** for a dedicated service account user.
Do not use a personal teacher / admin token.

- The user should have read-only permissions on the announcements and
  inbox the campus wants analyzed. Canvas enforces permissions server-side,
  so the path allowlist is a defense-in-depth layer, not the primary gate.
- Rotate the token on the schedule in the campus data-handling policy.

Environment variables:

| Variable | Required | Description |
|---|---|---|
| `CANVAS_BASE_URL` | yes | e.g. `https://canvas.instructure.com` |
| `CANVAS_API_TOKEN` | yes | Bearer token for the service account |
| `CANVAS_ANNOUNCEMENT_CONTEXTS` | optional | Comma-separated `context_codes[]`, e.g. `course_1234,course_5678`. Required to pull announcements. |
| `CANVAS_INCLUDE_CONVERSATIONS` | optional (default `1`) | Set to `0` to skip inbox |
| `CANVAS_INCLUDE_ANNOUNCEMENTS` | optional (default `1`) | Set to `0` to skip announcements |

## Allowed endpoints

From `scopes.yaml`:

- `GET /api/v1/users/self`
- `GET /api/v1/users/self/activity_stream`
- `GET /api/v1/announcements`
- `GET /api/v1/conversations`
- `GET /api/v1/courses/{course_id}/discussion_topics`

## Out of scope

- Grades, submissions, quizzes, files, and assignment content are not in
  the allowlist. Requests to those endpoints fail before leaving the
  integrations container.

## Rate limits

Canvas documents ~3000 requests/hour per token. The provider is
configured with a token bucket of capacity 5 and refill ~0.83/sec.
