# Security Policy — tandabill-website

This is the public web presence of TandaBill: a static marketing surface
plus one Vercel serverless function (`api/agentmail-hook.js`). No money
logic lives here — the escrow contracts are in
[`FluxNimbusAi/tanda`](https://github.com/FluxNimbusAi/tanda) and the
product app is in
[`FluxNimbusAi/tanda-miniapp`](https://github.com/FluxNimbusAi/tanda-miniapp),
each with its own policy document.

## Reporting a vulnerability

Email **tandabill-support@agentmail.to** with the affected surface
(page, asset, or the webhook function) and a minimal reproduction using
test routes only. We acknowledge within 72 hours. Anything that can reach
user data or forge inbound events is treated as critical.

## Scope

In scope:

- `index.html` and static assets served at tandabill.world
- `api/agentmail-hook.js` — the inbound agent-mail event receiver

Out of scope:

- the escrow protocol and mini-app surfaces (their policies above govern)
- Vercel platform infrastructure itself

## Known issues (live honesty section)

- **The webhook lane is fail-closed until provisioned.** The receiver
  needs `AGENTMAIL_HOOK_SECRET`, `AGENTMAIL_TRACKER_REF`, and
  `AGENTMAIL_GH_TOKEN` placed in Vercel env before it accepts anything;
  unprovisioned, it rejects rather than trusts. Until registration
  completes, the inbound-mail event lane is simply not live.
- **Static content only.** No accounts, cookies, or user input are
  processed by the marketing pages themselves.

## Hardening already in place (so reports land faster)

- Webhook verification requires the exact raw request bytes: body parsing
  is disabled and an HMAC-SHA256 check runs over the canonical signing
  string (timing-safe comparison), with a documented secondary scheme for
  alternate delivery surfaces.
- PII stays out of the public record by design: the hook appends only
  event type, timestamp, and a sha256 prefix of the message id to the
  private tracker — never sender, subject, or body.
- Least-privilege token: the GitHub credential it uses is scoped to
  issues-write on one repository only.
- Every commit carries provenance trailers
  ([`FluxNimbusAi/provenance-gate`](https://github.com/FluxNimbusAi/provenance-gate))
  and a nightly sweep re-validates the public record.
