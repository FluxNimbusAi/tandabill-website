// AgentMail inbound-event receiver (t_b4f64076, design per Nimbus 2026-11-23;
// signature law corrected 2026-11-24 to the live docs.agentmail.to contract).
// Vercel serverless function on the website lane — zero new infra, zero deps.
//
// Flow: AgentMail webhook (message.received / message.security.completed)
//   -> POST here -> signature check -> PRIVACY-SAFE summary appended to the
//   tracker issue thread (event type + timestamp + message-id sha256 prefix;
//   NEVER sender, subject, or body — public repo hygiene, PII stays out).
//
// Signature contract (docs.agentmail.to/webhook-verification): AgentMail
// delivers via Svix — headers svix-id / svix-timestamp / svix-signature,
// where the signature is a space-delimited list of "v1,<base64>" entries,
// each an HMAC-SHA256 over "{svix-id}.{svix-timestamp}.{RAW body bytes}"
// keyed with the base64-decoded whsec_ secret. Verification REQUIRES the
// exact raw bytes, hence bodyParser is disabled below. A secondary
// "X-AgentMail-Signature: sha256=<hex>" HMAC-of-body scheme is accepted as
// fallback for alternate delivery surfaces.
//
// Required Vercel env (secret placement = owner/Flux action, never chat):
//   AGENTMAIL_HOOK_SECRET  - Svix whsec_ secret (or plain secret for hex scheme)
//   AGENTMAIL_TRACKER_REF  - "FluxNimbusAi/tanda:<issue#>" for the event ledger
//   AGENTMAIL_GH_TOKEN     - fine-grained PAT, issues:write on that repo only
//
// Registration once key lands (one curl, key read from ~/.hermes-secrets, never chat):
//   POST https://api.agentmail.to/v0/webhooks
//     {"url":"https://tandabill.world/api/agentmail-hook","event_types":["message.received","message.security.completed"]}
//   (the response returns the whsec_ secret; place it in Vercel env as AGENTMAIL_HOOK_SECRET)

import { createHmac, timingSafeEqual, createHash } from "node:crypto";

export const config = { api: { bodyParser: false } };

const TS_TOLERANCE_S = 300; // reject stale deliveries (5 min)

async function readRawBody(req) {
  if (Buffer.isBuffer(req.body)) return req.body;
  if (typeof req.body === "string") return Buffer.from(req.body, "utf8");
  if (req.body && typeof req.body === "object") {
    // A parser ran despite bodyParser:false — best-effort compact
    // re-serialization; Svix serializes compact, so this round-trips in
    // practice. Raw stream below is always preferred when available.
    return Buffer.from(JSON.stringify(req.body), "utf8");
  }
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks);
}

function constantTimeEq(a, b) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

function verifySvix(raw, headers, secret) {
  const id = headers["svix-id"];
  const ts = headers["svix-timestamp"];
  const sig = headers["svix-signature"];
  if (!id || !ts || !sig) return false;
  const age = Math.abs(Date.now() / 1000 - Number(ts));
  if (!Number.isFinite(age) || age > TS_TOLERANCE_S) return false;
  let key;
  try {
    key = Buffer.from(String(secret).replace(/^whsec_/, ""), "base64");
  } catch {
    return false;
  }
  const signed = Buffer.concat([Buffer.from(`${id}.${ts}.`, "utf8"), raw]);
  const expected = createHmac("sha256", key).update(signed).digest("base64");
  return String(sig)
    .split(" ")
    .some((entry) => {
      const [version, value] = String(entry).split(",");
      if (version !== "v1" || !value) return false;
      try {
        return constantTimeEq(Buffer.from(expected, "base64"), Buffer.from(value, "base64"));
      } catch {
        return false;
      }
    });
}

function verifyHexSignature(raw, headers, secret) {
  const sig = String(headers["x-agentmail-signature"] || "").replace(/^sha256=/, "");
  if (!/^[0-9a-f]{64}$/i.test(sig)) return false;
  const expected = createHmac("sha256", secret).update(raw).digest("hex");
  return constantTimeEq(Buffer.from(expected, "hex"), Buffer.from(sig, "hex"));
}

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

  const raw = await readRawBody(req);
  const ok = verifySvix(raw, req.headers, secret) || verifyHexSignature(raw, req.headers, secret);
  if (!ok) return res.status(401).json({ error: "bad signature" });

  let payload;
  try {
    payload = JSON.parse(raw.toString("utf8"));
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
