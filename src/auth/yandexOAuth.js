import crypto from "node:crypto";
import { loadYandexOAuthConfig, YANDEX_FLOW_TTL_MS, YANDEX_SCOPE } from "./yandexConfig.js";

const RANDOM_TOKEN = /^[A-Za-z0-9_-]{43}$/;

export class YandexOAuthError extends Error {
  constructor(code = "yandex_oauth_failed") {
    super(code);
    this.name = "YandexOAuthError";
    this.code = code;
  }
}

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function verifierContext(flow) {
  return Buffer.from(`dizain:yandex:${flow.id}:${flow.stateHash}:${flow.browserBindingHash}`);
}

function sealVerifier(verifier, flow, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(verifierContext(flow));
  const encrypted = Buffer.concat([cipher.update(verifier, "utf8"), cipher.final()]);
  return [iv, encrypted, cipher.getAuthTag()].map(part => part.toString("base64url")).join(".");
}

function openVerifier(flow, key) {
  const parts = flow.codeVerifierBox.split(".");
  if (parts.length !== 3) throw new YandexOAuthError();
  const [iv, encrypted, tag] = parts.map(part => Buffer.from(part, "base64url"));
  if (iv.length !== 12 || tag.length !== 16) throw new YandexOAuthError();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(verifierContext(flow));
  decipher.setAuthTag(tag);
  const verifier = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
  if (!/^[A-Za-z0-9_-]{86}$/.test(verifier)) throw new YandexOAuthError();
  return verifier;
}

async function providerJson(fetcher, url, options) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  let reader;
  try {
    const response = await fetcher(url, { ...options, signal: controller.signal, redirect: "error", cache: "no-store" });
    if (!response.ok || !response.body) throw new YandexOAuthError();
    reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 128 * 1024) throw new YandexOAuthError();
      chunks.push(Buffer.from(value));
    }
    const result = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!result || typeof result !== "object" || Array.isArray(result) || result.error) throw new YandexOAuthError();
    return result;
  } finally {
    clearTimeout(timeout);
    if (reader) {
      try { await reader.cancel(); } catch { /* Never expose provider response data. */ }
      reader.releaseLock();
    }
  }
}

export function createYandexOAuthFoundation({ config, store, fetcher = globalThis.fetch, now = Date.now } = {}) {
  const checked = loadYandexOAuthConfig({
    YANDEX_CLIENT_ID: config?.clientId, YANDEX_CLIENT_SECRET: config?.clientSecret,
    YANDEX_OAUTH_REDIRECT_URI: config?.redirectUri,
    YANDEX_OAUTH_STATE_KEY: Buffer.isBuffer(config?.stateKey) ? config.stateKey.toString("base64url") : undefined,
  });
  if (!checked.ready || typeof fetcher !== "function" ||
      !["create", "claim", "verify", "fail"].every(method => typeof store?.[method] === "function")) {
    throw new YandexOAuthError("yandex_oauth_unavailable");
  }
  config = checked.config;
  return {
    async start() {
      try {
        const state = crypto.randomBytes(32).toString("base64url");
        const browserBinding = crypto.randomBytes(32).toString("base64url");
        const verifier = crypto.randomBytes(64).toString("base64url");
        const createdAt = new Date(now());
        const flow = { id: crypto.randomUUID(), stateHash: digest(state), browserBindingHash: digest(browserBinding),
          createdAt, expiresAt: new Date(createdAt.getTime() + YANDEX_FLOW_TTL_MS) };
        flow.codeVerifierBox = sealVerifier(verifier, flow, config.stateKey);
        const url = new URL("https://oauth.yandex.ru/authorize");
        url.search = new URLSearchParams({ response_type: "code", client_id: config.clientId,
          redirect_uri: config.redirectUri, scope: YANDEX_SCOPE, state,
          code_challenge: crypto.createHash("sha256").update(verifier).digest("base64url"),
          code_challenge_method: "S256", force_confirm: "yes" }).toString();
        await store.create(flow);
        return { authorizationUrl: url.href, cookie: { name: "__Host-dizain-yandex-flow", value: browserBinding,
          options: { httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: YANDEX_FLOW_TTL_MS } } };
      } catch {
        throw new YandexOAuthError();
      }
    },

    async verifyCallback({ state, browserBinding, code, error } = {}) {
      if (typeof state !== "string" || !RANDOM_TOKEN.test(state) ||
          typeof browserBinding !== "string" || !RANDOM_TOKEN.test(browserBinding) ||
          (error !== undefined && (typeof error !== "string" || !error || error.length > 256 || code !== undefined)) ||
          (error === undefined && (typeof code !== "string" || !code || code.length > 4096))) {
        throw new YandexOAuthError("yandex_callback_invalid");
      }
      let flow;
      try {
        flow = await store.claim(digest(state), digest(browserBinding));
        if (!flow) throw new YandexOAuthError("yandex_callback_invalid");
        if (error !== undefined) throw new YandexOAuthError("yandex_authorization_denied");
        const verifier = openVerifier(flow, config.stateKey);
        const tokens = await providerJson(fetcher, "https://oauth.yandex.ru/token", {
          method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
          body: new URLSearchParams({ grant_type: "authorization_code", code, client_id: config.clientId,
            client_secret: config.clientSecret, code_verifier: verifier }).toString(),
        });
        if (tokens.token_type !== "bearer" || typeof tokens.access_token !== "string" ||
            !/^[!-~]{1,8192}$/.test(tokens.access_token)) throw new YandexOAuthError("yandex_identity_invalid");
        // Yandex omits scope when all explicitly requested rights were granted.
        if (tokens.scope !== undefined && (typeof tokens.scope !== "string" ||
            !tokens.scope.split(/\s+/).includes(YANDEX_SCOPE))) throw new YandexOAuthError("yandex_scope_invalid");
        const profile = await providerJson(fetcher, "https://login.yandex.ru/info?format=json", {
          method: "GET", headers: { Authorization: `OAuth ${tokens.access_token}`, Accept: "application/json" },
        });
        if (profile.client_id !== config.clientId || typeof profile.id !== "string" ||
            !/^[!-~]{1,255}$/.test(profile.id)) throw new YandexOAuthError("yandex_identity_invalid");
        const email = typeof profile.default_email === "string" && profile.default_email.length <= 320 &&
          /^[^\s@]+@[^\s@]+$/.test(profile.default_email.trim()) ? profile.default_email.trim().toLowerCase() : null;
        // Owner-approved email matching policy, NOT a provider email_verified claim.
        const identity = { subject: profile.id, email, emailTrusted: email !== null };
        if (!await store.verify(flow.id, identity)) throw new YandexOAuthError("yandex_callback_invalid");
        return { flowId: flow.id };
      } catch (cause) {
        if (flow) {
          try { await store.fail(flow.id); } catch { /* Claimed flows cannot replay. */ }
        }
        throw cause instanceof YandexOAuthError ? cause : new YandexOAuthError();
      }
    },
  };
}
