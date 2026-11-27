# audits/

Landing zone for security review reports covering this web surface
(static site + the agent-mail webhook receiver).

## Status (2026-11-27)

**No external audit yet, and the surface is small by design.** The
marketing pages process no user input; the one serverless function is
fail-closed until its secrets are provisioned and verifies HMAC signatures
over raw request bytes (see `SECURITY.md`).

## Where the real audit trail lives

The money layer publishes the canonical internal-evidence index — security
sweeps, coverage-gap landscapes, deploy receipts — in
[`FluxNimbusAi/tanda/audits/README.md`](https://github.com/FluxNimbusAi/tanda/tree/main/audits).

## Naming law for future reports

`YYYY-MM-DD_<auditor>_<scope>.pdf` plus a sibling `.md` summary stating
scope, environment, findings by severity, and the sha256 of the report
bytes.
