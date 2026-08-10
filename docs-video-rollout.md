# VagasIO authenticated video preview

Branch-only; feature is disabled unless `VAGASIO_VIDEO_CALLS=1` and the JWT identity matches one of the internal allowlists. Required preview-only variables: `VAGASIO_VIDEO_INTERNAL_USER_IDS`, `VAGASIO_VIDEO_INTERNAL_EMAILS`, `VAGASIO_VIDEO_SIGNAL_URL` (must be `wss://`), and `VAGASIO_VIDEO_TOKEN_SECRET` (backend secret, never frontend). Optional `VAGASIO_VIDEO_ROOM_TTL_SECONDS` is clamped to 15 minutes–24 hours.

Migration 019 creates `video_rooms` and `video_participant_tokens`; it is additive and idempotent. Rollback: disable the flag first, then drop those two tables during a maintenance window (tokens are cascade-deleted); no existing interview/Meet data is changed. Do not change production env or merge to main.

Room and token endpoints require JWT and verify the interview's candidature, candidate ownership, company tenant ownership, or admin role. Tokens are short-lived JWTs signed by `VAGASIO_VIDEO_TOKEN_SECRET`, stored hashed, and claim room/candidature/interview/role/user. Recruiter-only end marks the room ended. The isolated signaling service must independently validate those claims and expiry.

Candidate agenda keeps Google Meet as fallback. Video entry is rendered only after authenticated config succeeds; identity is read from session storage/JWT, never from URL. Preview remains blocked until a safe signaling service and synthetic allowlisted accounts are available.
