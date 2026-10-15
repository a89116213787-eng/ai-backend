import crypto from "node:crypto";
import { Router } from "express";
import { createGoogleIdentityClient, GOOGLE_FLOW_TTL_MS, loadGoogleOAuthConfig } from "./googleConfig.js";

const RANDOM_TOKEN = /^[A-Za-z0-9_-]{43}$/;
const ISSUERS = new Set(["https://accounts.google.com", "accounts.google.com"]);

export class GoogleOAuthError extends Error {
  constructor(code = "google_oauth_failed") {
    super(code);
    this.name = "GoogleOAuthError";
    this.code = code;
  }
}

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function matchesDigest(value, expected) {
  return typeof expected === "string" && /^[a-f0-9]{64}$/.test(expected) &&
    crypto.timingSafeEqual(Buffer.from(digest(value), "hex"), Buffer.from(expected, "hex"));
}

function verifierContext(flow) {
  return Buffer.from(`${flow.id}:${flow.stateHash}:${flow.browserBindingHash}`);
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
  if (parts.length !== 3) throw new GoogleOAuthError();
  const [iv, encrypted, tag] = parts.map(part => Buffer.from(part, "base64url"));
  if (iv.length !== 12 || tag.length !== 16) throw new GoogleOAuthError();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(verifierContext(flow));
  decipher.setAuthTag(tag);
  const verifier = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
  if (!/^[A-Za-z0-9_-]{86}$/.test(verifier)) throw new GoogleOAuthError();
  return verifier;
}

function checkedIdentity(payload, config, flow, now) {
  const seconds = Math.floor(now / 1000);
  if (
    !payload || !ISSUERS.has(payload.iss) || payload.aud !== config.clientId ||
    (payload.azp !== undefined && payload.azp !== config.clientId) ||
    !Number.isInteger(payload.exp) || payload.exp <= seconds ||
    !Number.isInteger(payload.iat) || payload.iat > seconds + 60 || payload.iat >= payload.exp ||
    typeof payload.sub !== "string" || !/^[!-~]{1,255}$/.test(payload.sub) ||
    typeof payload.nonce !== "string" || !matchesDigest(payload.nonce, flow.nonceHash)
  ) {
    throw new GoogleOAuthError("google_identity_invalid");
  }
  return {
    subject: payload.sub,
    email: typeof payload.email === "string" && payload.email.length <= 320 ? payload.email : null,
    emailVerified: payload.email_verified === true,
    hostedDomain: typeof payload.hd === "string" && payload.hd.length <= 255 ? payload.hd : null,
  };
}

export function createGoogleOAuthFoundation({
  config,
  store,
  clientFactory = createGoogleIdentityClient,
  now = Date.now,
} = {}) {
  if (!config || !store || !Buffer.isBuffer(config.stateKey) || config.stateKey.length !== 32) {
    throw new GoogleOAuthError("google_oauth_unavailable");
  }
  const checked = loadGoogleOAuthConfig({
    GOOGLE_CLIENT_ID: config.clientId,
    GOOGLE_CLIENT_SECRET: config.clientSecret,
    GOOGLE_OAUTH_REDIRECT_URI: config.redirectUri,
    GOOGLE_OAUTH_STATE_KEY: config.stateKey.toString("base64url"),
  });
  if (!checked.ready || !["create", "claim", "verify", "fail"].every(method => typeof store[method] === "function")) {
    throw new GoogleOAuthError("google_oauth_unavailable");
  }
  config = checked.config;

  return {
    async start() {
      try {
        const state = crypto.randomBytes(32).toString("base64url");
        const browserBinding = crypto.randomBytes(32).toString("base64url");
        const nonce = crypto.randomBytes(32).toString("base64url");
        const verifier = crypto.randomBytes(64).toString("base64url");
        const createdAt = new Date(now());
        const flow = {
          id: crypto.randomUUID(),
          stateHash: digest(state),
          browserBindingHash: digest(browserBinding),
          nonceHash: digest(nonce),
          createdAt,
          expiresAt: new Date(createdAt.getTime() + GOOGLE_FLOW_TTL_MS),
        };
        flow.codeVerifierBox = sealVerifier(verifier, flow, config.stateKey);
        const client = await clientFactory(config);
        const authorizationUrl = client.generateAuthUrl({
          response_type: "code",
          access_type: "online",
          scope: ["openid", "email"],
          state,
          nonce,
          code_challenge: crypto.createHash("sha256").update(verifier).digest("base64url"),
          code_challenge_method: "S256",
          prompt: "select_account",
        });
        await store.create(flow);
        // The future HTTP adapter must deliver this only as an HttpOnly cookie.
        return {
          authorizationUrl,
          cookie: {
            name: "__Host-dizain-google-flow",
            value: browserBinding,
            options: { httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: GOOGLE_FLOW_TTL_MS },
          },
        };
      } catch {
        throw new GoogleOAuthError();
      }
    },

    async verifyCallback({ state, browserBinding, code, error } = {}) {
      if (
        typeof state !== "string" || !RANDOM_TOKEN.test(state) ||
        typeof browserBinding !== "string" || !RANDOM_TOKEN.test(browserBinding) ||
        (error !== undefined && (typeof error !== "string" || !error || code !== undefined)) ||
        (error === undefined && (typeof code !== "string" || !code || code.length > 4096))
      ) {
        throw new GoogleOAuthError("google_callback_invalid");
      }

      let flow;
      try {
        flow = await store.claim(digest(state), digest(browserBinding));
        if (!flow) throw new GoogleOAuthError("google_callback_invalid");
        if (error !== undefined) throw new GoogleOAuthError("google_authorization_denied");
        const verifier = openVerifier(flow, config.stateKey);
        const client = await clientFactory(config);
        const { tokens } = await client.getToken({ code, codeVerifier: verifier, redirect_uri: config.redirectUri });
        if (typeof tokens?.id_token !== "string") throw new GoogleOAuthError("google_identity_invalid");
        const ticket = await client.verifyIdToken({ idToken: tokens.id_token, audience: config.clientId });
        const identity = checkedIdentity(ticket.getPayload(), config, flow, now());
        if (!await store.verify(flow.id, identity)) throw new GoogleOAuthError("google_callback_invalid");
        // Internal proof only: no account lookup, linking, registration or JWT.
        return { flowId: flow.id };
      } catch (cause) {
        if (flow) {
          try { await store.fail(flow.id); } catch { /* Remains claimed, so replay still fails closed. */ }
        }
        // Library errors may contain ID tokens or HTTP credentials; never expose them.
        throw cause instanceof GoogleOAuthError ? cause : new GoogleOAuthError();
      }
    },
  };
}

// Stage 1 has no HTTP endpoints and cannot be enabled by environment variables.
export function createDisabledGoogleOAuthRouter() {
  return Router();
}
