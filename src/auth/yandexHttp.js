import crypto from "node:crypto";
import { isIP } from "node:net";
import { Router, json } from "express";
import { loadYandexOAuthConfig, YANDEX_FLOW_TTL_MS } from "./yandexConfig.js";
import { createYandexOAuthFoundation, YandexOAuthError } from "./yandexOAuth.js";
import { createYandexFlowStore } from "./yandexFlowStore.js";
import { createYandexAccountStore } from "./yandexAccountStore.js";
import { createGoogleAccountService } from "./googleAccounts.js";
import { GoogleOAuthError } from "./googleOAuth.js";

const BINDING_COOKIE = "__Host-dizain-yandex-flow";
const PROOF_COOKIE = "__Host-dizain-yandex-proof";
const BINDING = /^[A-Za-z0-9_-]{43}$/;
const FLOW_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const COOKIE_OPTIONS = { httpOnly: true, secure: true, sameSite: "lax", path: "/" };
const ACTIONS = new Set(["resolve", "cancel"]);
const ERROR_STATUS = {
  yandex_proof_invalid: 401, yandex_callback_invalid: 400, yandex_identity_invalid: 400,
  yandex_scope_invalid: 400, yandex_authorization_denied: 400, yandex_identity_already_linked: 409,
  yandex_account_ambiguous: 409, yandex_schema_unavailable: 503,
  yandex_oauth_failed: 503, yandex_oauth_unavailable: 503,
};

function normalizeIp(value) {
  if (typeof value !== "string" || !value || value.includes("%") || !isIP(value)) return null;
  if (isIP(value) === 4) return value;
  const ip = new URL(`http://[${value}]/`).hostname.slice(1, -1);
  if (!ip.startsWith("::ffff:")) return ip;
  const parts = ip.slice(7).split(":");
  if (parts.length !== 2) return ip;
  const [high, low] = parts.map(part => parseInt(part, 16));
  return `${high >>> 8}.${high & 255}.${low >>> 8}.${low & 255}`;
}

function verifiedTransportIp(req, key, time) {
  try {
    const context = req.get("X-Dizain-Yandex-Context");
    const signature = req.get("X-Dizain-Yandex-Signature");
    if (typeof context !== "string" || !/^[A-Za-z0-9_-]{1,1024}$/.test(context) ||
        typeof signature !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(signature)) return null;
    const supplied = Buffer.from(signature, "base64url");
    const expected = crypto.createHmac("sha256", key).update(context).digest();
    if (supplied.length !== 32 || supplied.toString("base64url") !== signature ||
        !crypto.timingSafeEqual(supplied, expected)) return null;
    const fields = JSON.parse(Buffer.from(context, "base64url").toString("utf8"));
    if (!Array.isArray(fields) || fields.length !== 6) return null;
    const [version, ip, timestamp, method, path, queryHash] = fields;
    if (version !== "dizain-yandex-transport-v1" || !ip || normalizeIp(ip) !== ip ||
        typeof timestamp !== "string" || !/^(0|[1-9]\d{0,15})$/.test(timestamp) ||
        !Number.isSafeInteger(Number(timestamp)) || Math.abs(time - Number(timestamp)) > 60000) return null;
    const url = new URL(req.originalUrl, "https://unused.invalid");
    const digest = crypto.createHash("sha256").update(JSON.stringify([...url.searchParams])).digest("hex");
    if (method !== req.method || path !== url.pathname || queryHash !== digest ||
        Buffer.from(JSON.stringify(fields)).toString("base64url") !== context) return null;
    return ip;
  } catch {
    return null;
  }
}

function createServices({ pool, config, jwtSecret }) {
  const service = createGoogleAccountService({ store: createYandexAccountStore(pool), jwtSecret,
    sendVerification: async () => { throw new YandexOAuthError(); } });
  return { foundation: createYandexOAuthFoundation({ config, store: createYandexFlowStore(pool) }),
    accounts: { resolve: service.resolve, cancel: service.cancel } };
}

function replyError(res, status, code) {
  return res.status(status).json({ ok: false, error: code });
}

function clearProof(res) {
  res.clearCookie(BINDING_COOKIE, COOKIE_OPTIONS);
  res.clearCookie(PROOF_COOKIE, COOKIE_OPTIONS);
}

function readCookie(req, name, pattern, required = true) {
  const values = (req.headers.cookie || "").split(";").map(part => part.trim())
    .filter(part => part.split("=", 1)[0] === name).map(part => part.slice(name.length + 1));
  if ((!required && values.length === 0) || (values.length === 1 && pattern.test(values[0]))) return values[0];
  throw new YandexOAuthError("yandex_proof_invalid");
}

export function createYandexHttpRouter({ pool, env = process.env, servicesFactory = createServices, now = Date.now } = {}) {
  const router = Router({ caseSensitive: true, strict: true });
  if (env.YANDEX_OAUTH_ENABLED !== "true") return router;
  let services, frontendOrigin, transportKey;
  try {
    const encoded = env.YANDEX_TRANSPORT_HMAC_KEY;
    if (typeof encoded !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(encoded)) throw new Error();
    transportKey = Buffer.from(encoded, "base64url");
    if (transportKey.length !== 32 || transportKey.toString("base64url") !== encoded) throw new Error();
    const checked = loadYandexOAuthConfig(env);
    const origin = env.YANDEX_OAUTH_FRONTEND_ORIGIN ?? "https://dizain.pro";
    const parsed = new URL(origin);
    if (!checked.ready || parsed.protocol !== "https:" || parsed.origin !== origin ||
        transportKey.equals(checked.config.stateKey) ||
        typeof env.JWT_SECRET !== "string" || !env.JWT_SECRET ||
        typeof pool?.query !== "function" || typeof pool?.connect !== "function") throw new Error();
    frontendOrigin = origin;
    services = servicesFactory({ pool, config: checked.config, jwtSecret: env.JWT_SECRET });
    if (typeof services?.foundation?.start !== "function" || typeof services.foundation.verifyCallback !== "function" ||
        [...ACTIONS].some(method => typeof services?.accounts?.[method] !== "function")) throw new Error();
  } catch {
    router.use((req, res) => {
      res.set("Cache-Control", "no-store");
      return replyError(res, 503, "yandex_oauth_unavailable");
    });
    return router;
  }
  const buckets = new Map();
  function allowed(ip, kind, limit) {
    const key = `${kind}:${crypto.createHash("sha256").update(ip).digest("hex")}`;
    const time = now();
    if (buckets.size >= 10000) {
      for (const [id, row] of buckets) if (row.until <= time) buckets.delete(id);
      if (buckets.size >= 10000 && !buckets.has(key)) return false;
    }
    let row = buckets.get(key);
    if (!row || row.until <= time) { row = { count: 0, until: time + 15 * 60 * 1000 }; buckets.set(key, row); }
    if (row.count >= limit) return false;
    row.count += 1;
    return true;
  }
  function run(handler) {
    return (req, res) => Promise.resolve().then(() => handler(req, res)).catch(error => {
      if (res.headersSent) return;
      const candidate = error instanceof GoogleOAuthError ? error.code.replace(/^google_/, "yandex_") :
        error instanceof YandexOAuthError ? error.code : null;
      const code = Object.hasOwn(ERROR_STATUS, candidate) ? candidate : "yandex_oauth_failed";
      if (code === "yandex_proof_invalid") clearProof(res);
      return replyError(res, ERROR_STATUS[code], code);
    });
  }
  router.use((req, res, next) => {
    res.setTimeout(120000);
    res.set({ "Cache-Control": "no-store", Pragma: "no-cache", "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff" });
    res.vary("Origin");
    const origin = req.get("Origin");
    if (origin === frontendOrigin) res.set({ "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true" });
    const method = req.path === "/callback" ? "GET" :
      req.path === "/start" || ACTIONS.has(req.path.slice(1)) ? "POST" : null;
    if (!method) return replyError(res, 404, "yandex_route_not_found");
    if (req.method === "OPTIONS") {
      const headers = (req.get("Access-Control-Request-Headers") || "").split(",").map(value => value.trim().toLowerCase()).filter(Boolean);
      if (origin !== frontendOrigin || req.get("Access-Control-Request-Method") !== method ||
          headers.some(value => value !== "content-type")) return replyError(res, 403, "yandex_origin_invalid");
      res.set({ "Access-Control-Allow-Methods": method, "Access-Control-Allow-Headers": "Content-Type" });
      return res.sendStatus(204);
    }
    if (req.method !== method) {
      res.set("Allow", `${method}, OPTIONS`);
      return replyError(res, 405, "yandex_method_invalid");
    }
    if (method === "POST") {
      if (origin !== frontendOrigin || req.get("Sec-Fetch-Site") === "cross-site") return replyError(res, 403, "yandex_origin_invalid");
      if (!req.is("application/json")) return replyError(res, 415, "yandex_json_required");
      if (new URL(req.originalUrl, "https://unused.invalid").search) return replyError(res, 400, "yandex_request_invalid");
    }
    const ip = verifiedTransportIp(req, transportKey, now());
    if (!ip) return replyError(res, 403, "yandex_transport_invalid");
    const kind = req.path === "/start" ? "start" : req.path === "/callback" ? "callback" : "action";
    if (!allowed(ip, kind, kind === "start" ? 20 : kind === "callback" ? 60 : 120)) {
      res.set("Retry-After", "900");
      return replyError(res, 429, "yandex_rate_limited");
    }
    next();
  });
  router.use(json({ limit: "8kb", strict: true }));
  function validBody(req) {
    return req.body && typeof req.body === "object" && !Array.isArray(req.body) && Object.keys(req.body).length === 0;
  }
  router.post("/start", run(async (req, res) => {
    if (!validBody(req)) return replyError(res, 400, "yandex_request_invalid");
    readCookie(req, BINDING_COOKIE, BINDING, false);
    readCookie(req, PROOF_COOKIE, FLOW_ID, false);
    const started = await services.foundation.start();
    res.clearCookie(PROOF_COOKIE, COOKIE_OPTIONS);
    res.cookie(started.cookie.name, started.cookie.value, started.cookie.options);
    return res.json({ ok: true, authorizationUrl: started.authorizationUrl });
  }));
  router.get("/callback", run(async (req, res) => {
    if (req.originalUrl.length > 8192) throw new YandexOAuthError("yandex_callback_invalid");
    const params = new URL(req.originalUrl, "https://unused.invalid").searchParams;
    if (new Set(params.keys()).size !== [...params.keys()].length) throw new YandexOAuthError("yandex_callback_invalid");
    const browserBinding = readCookie(req, BINDING_COOKIE, BINDING);
    readCookie(req, PROOF_COOKIE, FLOW_ID, false);
    const verified = await services.foundation.verifyCallback({ state: params.get("state") ?? undefined,
      code: params.get("code") ?? undefined, error: params.get("error") ?? undefined, browserBinding });
    res.cookie(PROOF_COOKIE, verified.flowId, { ...COOKIE_OPTIONS, maxAge: YANDEX_FLOW_TTL_MS });
    return res.redirect(303, `${frontendOrigin}/auth/login?yandex=complete`);
  }));
  for (const action of ACTIONS) router.post(`/${action}`, run(async (req, res) => {
    if (!validBody(req)) return replyError(res, 400, "yandex_request_invalid");
    const result = await services.accounts[action]({ flowId: readCookie(req, PROOF_COOKIE, FLOW_ID),
      browserBinding: readCookie(req, BINDING_COOKIE, BINDING) });
    if (result.token || result.code === "CANCELLED") clearProof(res);
    const code = result.code === "GOOGLE_EMAIL_REQUIRED" ? "YANDEX_EMAIL_REQUIRED" : result.code;
    const status = result.ok === false ? (code === "ACCOUNT_EXISTS" ? 409 : code === "EMAIL_NOT_VERIFIED" ? 403 : 400) : 200;
    return res.status(status).json(result.ok === false ? { ...result, code, error: code } : result);
  }));
  router.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    return replyError(res, error.type === "entity.too.large" ? 413 : 400, "yandex_request_invalid");
  });
  return router;
}
