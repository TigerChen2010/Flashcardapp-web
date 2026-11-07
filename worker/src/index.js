/* Flashcards reminder sender (Cloudflare Worker).
   Phones register with an anonymous id + their Web Push subscription, then send their upcoming reminder
   times. Every 5 minutes the cron sends whatever is due. No names, no sets: only times and short texts.
   The VAPID signing key is created by the Worker itself on first use and kept in KV (never in the repo). */

const ORIGINS = ["https://flashcard-spaced-repetition.com", "https://www.flashcard-spaced-repetition.com", "https://flashcardapp-web.pages.dev"];
const SUBJECT = "https://flashcard-spaced-repetition.com";
const MAX_ITEMS = 80, MAX_AHEAD = 9 * 864e5, LATE_OK = 3 * 36e5;

const enc = new TextEncoder();
const b64u = buf => { let s = ""; new Uint8Array(buf).forEach(b => s += String.fromCharCode(b)); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const unb64u = str => { str = str.replace(/-/g, "+").replace(/_/g, "/"); while (str.length % 4) str += "="; const bin = atob(str); const a = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; };
const cat = (...arrs) => { const n = arrs.reduce((s, a) => s + a.length, 0); const o = new Uint8Array(n); let p = 0; arrs.forEach(a => { o.set(a, p); p += a.length; }); return o; };
async function hmac(key, data) { const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); return new Uint8Array(await crypto.subtle.sign("HMAC", k, data)); }

/* ---------- VAPID keys (made once, stored in KV) ---------- */
async function vapid(env) {
  let v = await env.KV.get("vapid", "json");
  if (!v) {
    const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const priv = await crypto.subtle.exportKey("jwk", kp.privateKey);
    const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    v = { priv, pub: b64u(pub) };
    await env.KV.put("vapid", JSON.stringify(v));
  }
  return v;
}
async function vapidHeader(env, endpoint) {
  const v = await vapid(env);
  const aud = new URL(endpoint).origin;
  const head = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const body = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: SUBJECT })));
  const key = await crypto.subtle.importKey("jwk", v.priv, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(head + "." + body));
  return `vapid t=${head}.${body}.${b64u(sig)}, k=${v.pub}`;
}

/* ---------- RFC 8291 payload encryption (aes128gcm) ---------- */
export async function encryptPayload(sub, text) {
  const uaPub = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth);
  const as = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", as.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, as.privateKey, 256));
  const prkKey = await hmac(auth, shared);
  const ikm = await hmac(prkKey, cat(enc.encode("WebPush: info\0"), uaPub, asPub, new Uint8Array([1])));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hmac(salt, ikm);
  const cek = (await hmac(prk, cat(enc.encode("Content-Encoding: aes128gcm\0"), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmac(prk, cat(enc.encode("Content-Encoding: nonce\0"), new Uint8Array([1])))).slice(0, 12);
  const k = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, k, cat(enc.encode(text), new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 16, 0]);
  return cat(salt, rs, new Uint8Array([asPub.length]), asPub, ct);
}
async function sendPush(env, sub, msg) {
  const body = await encryptPayload(sub, JSON.stringify(msg));
  const r = await fetch(sub.endpoint, { method: "POST", headers: { "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: "86400", Urgency: "normal", Authorization: await vapidHeader(env, sub.endpoint) }, body });
  return r.status;
}

/* ---------- API ---------- */
const okId = id => typeof id === "string" && /^[a-f0-9]{32}$/.test(id);
function cors(req) { const o = req.headers.get("Origin"); return { "Access-Control-Allow-Origin": ORIGINS.includes(o) ? o : ORIGINS[0], "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Max-Age": "86400", Vary: "Origin" }; }
const json = (req, o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "Content-Type": "application/json", ...cors(req) } });
function cleanItems(items) {
  const now = Date.now();
  return (Array.isArray(items) ? items : []).filter(x => x && typeof x.at === "number" && x.at > now - LATE_OK && x.at < now + MAX_AHEAD)
    .slice(0, MAX_ITEMS).map(x => ({ at: x.at, title: String(x.title || "Flashcards").slice(0, 80), body: String(x.body || "").slice(0, 180), tag: String(x.tag || "").slice(0, 40), url: String(x.url || "/").slice(0, 120) }));
}
function okSub(s) { try { return s && typeof s.endpoint === "string" && /^https:\/\//.test(s.endpoint) && s.keys && s.keys.p256dh && s.keys.auth && unb64u(s.keys.p256dh).length === 65 && unb64u(s.keys.auth).length === 16; } catch (e) { return false; } }

async function handle(req, env) {
  const url = new URL(req.url);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(req) });
  if (url.pathname === "/api/key" && req.method === "GET") return json(req, { key: (await vapid(env)).pub });
  if (req.method !== "POST") return json(req, { ok: true, service: "flashcards-push" });
  let b = {}; try { b = await req.json(); } catch (e) { return json(req, { error: "bad json" }, 400); }
  if (!okId(b.id)) return json(req, { error: "bad id" }, 400);
  const k = "s:" + b.id;
  if (url.pathname === "/api/subscribe") {
    if (!okSub(b.sub)) return json(req, { error: "bad subscription" }, 400);
    const cur = (await env.KV.get(k, "json")) || {};
    await env.KV.put(k, JSON.stringify({ sub: { endpoint: b.sub.endpoint, keys: { p256dh: b.sub.keys.p256dh, auth: b.sub.keys.auth } }, items: cleanItems(b.items || cur.items), seen: Date.now() }));
    return json(req, { ok: true });
  }
  if (url.pathname === "/api/schedule") {
    const cur = await env.KV.get(k, "json");
    if (!cur) return json(req, { error: "not subscribed" }, 404);
    cur.items = cleanItems(b.items); cur.seen = Date.now();
    await env.KV.put(k, JSON.stringify(cur));
    return json(req, { ok: true, n: cur.items.length });
  }
  if (url.pathname === "/api/unsubscribe") { await env.KV.delete(k); return json(req, { ok: true }); }
  if (url.pathname === "/api/test") {
    const cur = await env.KV.get(k, "json");
    if (!cur) return json(req, { error: "not subscribed" }, 404);
    const st = await sendPush(env, cur.sub, { title: "Reminders are on", body: "This is what a Flashcards reminder looks like.", tag: "test", url: "/" });
    if (st === 404 || st === 410) await env.KV.delete(k);
    return json(req, { ok: st >= 200 && st < 300, status: st });
  }
  return json(req, { error: "not found" }, 404);
}

/* ---------- every 5 minutes ---------- */
async function tick(env) {
  const now = Date.now();
  let cursor;
  do {
    const page = await env.KV.list({ prefix: "s:", cursor });
    for (const { name } of page.keys) {
      const rec = await env.KV.get(name, "json");
      if (!rec) continue;
      const due = rec.items.filter(x => x.at <= now + 30e3);
      if (!due.length) continue;
      // one notification per tag: the latest due one, if it isn't hours late
      const pick = new Map();
      due.forEach(x => { if (now - x.at < LATE_OK) pick.set(x.tag || String(x.at), x); });
      let gone = false;
      for (const x of pick.values()) {
        const st = await sendPush(env, rec.sub, { title: x.title, body: x.body, tag: x.tag, url: x.url });
        if (st === 404 || st === 410) { gone = true; break; }
      }
      if (gone) { await env.KV.delete(name); continue; }
      rec.items = rec.items.filter(x => x.at > now + 30e3);
      await env.KV.put(name, JSON.stringify(rec));
    }
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
}

export default {
  fetch: (req, env) => handle(req, env).catch(e => json(req, { error: String(e && e.message || e) }, 500)),
  scheduled: (ev, env, ctx) => ctx.waitUntil(tick(env))
};
