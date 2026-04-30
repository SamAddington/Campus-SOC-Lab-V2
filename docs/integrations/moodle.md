# Moodle

## Credentials

Moodle Web Services:

1. Site administration → Plugins → Web services → External services.
2. Create a new **external service** and enable only the functions listed
   below under "Allowed wsfunctions".
3. Create a dedicated service-account user and assign the service to it.
4. Generate a token for that user.

Environment variables:

| Variable | Required | Description |
|---|---|---|
| `MOODLE_BASE_URL` | yes | e.g. `https://moodle.example.edu` |
| `MOODLE_WSTOKEN` | yes | Web services token |
| `MOODLE_USER_ID` | optional | Numeric user id for `core_message_get_messages` (default `0`) |
| `MOODLE_FORUM_ID` | optional | If set, discussions from this forum are pulled |

## Allowed wsfunctions

Moodle routes every call through `/webservice/rest/server.php`, so path
scoping alone is insufficient. The provider enforces an **allowlist of
`wsfunction` values** via `ScopedHTTP.extra_validator`:

- `core_webservice_get_site_info` (auth check only)
- `core_message_get_messages`
- `mod_forum_get_forum_discussions`
- `mod_forum_get_forum_discussion_posts`

Any other `wsfunction` is rejected before the request is sent.

## Out of scope

Assignment, quiz, gradebook, and grade-related functions
(`mod_assign_*`, `mod_quiz_*`, `gradereport_*`) are not in the allowlist.
