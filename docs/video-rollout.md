# VagasIO video-call rollout (internal preview only)

This feature is isolated behind `VAGASIO_VIDEO_CALLS`, which defaults to disabled. The API route remains mounted only to return a generic response; no portal page links to it.

## Required preview environment

Backend (preview service only):

- `VAGASIO_VIDEO_CALLS=1`
- `VAGASIO_VIDEO_INTERNAL_USER_IDS` — comma-separated synthetic candidate/recruiter IDs
- `VAGASIO_VIDEO_INTERNAL_EMAILS` — comma-separated synthetic identities (lowercase comparison)
- `VAGASIO_VIDEO_SIGNAL_URL` — **must be an explicit `wss://` preview signaling endpoint**
- Existing `JWT_SECRET` and `DATABASE_URL` remain required; do not replace the complete Render env-var array when adding these.

Do not set these variables on production services. Never use real candidate/company identities in the allowlists.

## Auth and role behavior

`GET /api/video/config` requires the existing bearer JWT. The candidate token maps to `candidate`; an authenticated empresa/recruiter token maps to `recruiter`; admin maps to `admin`. A valid JWT that is not in either internal allowlist receives the same generic 404 as the disabled flag. Successful responses are `Cache-Control: no-store` and contain only the preview signaling URL and role metadata; no JWT or secret is returned.

Room creation, room membership, expiry, and signaling authorization remain the responsibility of the isolated preview signaling service. This branch does not connect production signaling or add a public portal entry point.

## Controlled rollout

1. Deploy the backend branch to a separate preview service, preserving all existing environment variables.
2. Provision/verify an isolated signaling service and set its explicit `wss://` URL in the preview env only.
3. Create synthetic candidate and recruiter identities, then add their IDs/emails to the preview allowlists.
4. Use the internal video test page/checklist; verify cross-room isolation, role/token rejection, expiry, reconnect, and browser permissions.
5. Run candidate/empresa login, candidature, agenda, and chat smoke tests.
6. Review logs and security results; only then decide whether to propose a separate production design. Do not merge this branch or deploy production as part of this phase.

Current blocker: no safe preview signaling service is provisioned by this change, so the end-to-end call cannot be enabled yet.
