// AgentMail inbound-event receiver (t_b4f64076, design per Nimbus 2026-11-23).
// Vercel serverless function on the website lane — zero new infra.
//
// Flow: AgentMail webhook (message.received / message.security.completed)
//   -> POST here -> HMAC check -> PRIVACY-SAFE summary appended to the
//   tracker issue thread (event type + timestamp + message-id sha256 prefix;
//   NEVER sender, subject, or body — public repo hygiene, PII stays out).
//
// Required Vercel env (secret placement = owner/Flux action, see issue body):
//   AGENTMAIL_HOOK_SECRET  - shared secret, AgentMail signs payloads with it
//   AGENTMAIL_TRACKER_REF  - "FluxNimbusAi/tanda:<issue#>" for the event ledger
//   AGENTMAIL_GH_TOKEN     - fine-grained PAT, issues:write on that repo only
//
// Registration once key lands (one curl, key read from ~/.hermes-secrets, never chat):
//   POST https://api.agentmail.to/v0/webhooks
//     {"url":"https://tandabill.world/api/agentmail-hook","event_types":["message.received","message.security.completed"],"secret":"<HOOK_SECRET>"}

import { createHmac, timingSafeEqual, createHash } from "node:crypto";

function summarize(evt) {
  const id = String(evt.message_id || evt.id || evt.event_id || "");
  return {
    event: String(evt.event_type || evt.type || "unknown").slice(0, 60),
    at: new Date().toISOString(),
    ref: id ? createHash("sha256").update(id).digest("hex").slice(0, 12) : "n/a",
  };
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "method" });
  const secret = process.env.AGENTMAIL_HOOK_SECRET;
  const tracker = process.env.AGENTMAIL_TRACKER_REF; // "owner/repo:number"
  const ghToken = process.env.AGENTMAIL_GH_TOKEN;
  if (!secret || !tracker || !ghToken)
    return res.status(501).json({ error: "receiver not wired (missing env)" });

  // Verify signature header (AgentMail sends X-AgentMail-Signature: sha256=<hex>)
  const sig = String(req.headers["x-agentmail-signature"] || "");
  const raw = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
  const expect = "sha256=" + createHmac("sha256", secret).update(raw).digest("hex");
  if (
    sig.length !== expect.length ||
    !timingSafeEqual(Buffer.from(sig), Buffer.from(expect))
  )
    return res.status(401).json({ error: "bad signature" });

  let payload;
  try {
    payload = JSON.parse(raw);
  } catch {
    return res.status(400).json({ error: "bad json" });
  }
  const s = summarize(payload);
  const [repo, num] = [tracker.split(":")[0], tracker.split(":")[1]];
  const body = `agentmail-event \`${s.event}\` at ${s.at} — ref \`${s.ref}\` (sender/subject withheld by design)`;
  const r = await fetch(
    `https://api.github.com/repos/${repo}/issues/${num}/comments`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ghToken}`,
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-08-09",
      },
      body: JSON.stringify({ body }),
    }
  );
  if (!r.ok) return res.status(502).json({ error: "ledger append failed", code: r.status });
  return res.status(200).json({ ok: true, event: s.event });
}
