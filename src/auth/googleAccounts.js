import crypto from "node:crypto";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { GoogleOAuthError } from "./googleOAuth.js";
import { sendMail } from "../services/mailClient.js";
import { verifyEmailTemplate } from "../templates/emails/verifyEmailTemplate.js";

const FLOW_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const BINDING = /^[A-Za-z0-9_-]{43}$/;

// Internal service only: no routes, environment reads, pool creation or activation.
export function createGoogleAccountService({
  store, jwtSecret, now = Date.now,
  sendVerification = ({ email, token }) => sendMail({
    to: email,
    subject: "\u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u0435 \u043f\u043e\u0447\u0442\u044b \u2014 \u0414\u0438\u0437\u0410i\u043d",
    html: verifyEmailTemplate(`https://api.dizain.pro/api/auth/verify-email?token=${token}`, email),
  }),
} = {}) {
  if (typeof store?.withVerifiedFlow !== "function" || typeof jwtSecret !== "string" || !jwtSecret ||
      typeof sendVerification !== "function") {
    throw new GoogleOAuthError("google_oauth_unavailable");
  }

  async function execute(proof, action) {
    const { flowId, browserBinding } = proof ?? {};
    if (typeof flowId !== "string" || !FLOW_ID.test(flowId) ||
        typeof browserBinding !== "string" || !BINDING.test(browserBinding)) {
      throw new GoogleOAuthError("google_proof_invalid");
    }
    try {
      const result = await store.withVerifiedFlow({
        flowId,
        browserBindingHash: crypto.createHash("sha256").update(browserBinding).digest("hex"),
      }, action);
      const { verificationMail, ...response } = result;
      if (verificationMail) {
        // Account/proof are already committed. Delivery failure must not recreate them.
        try { await sendVerification(verificationMail); response.mailDelivery = "SENT"; }
        catch { response.mailDelivery = "FAILED"; }
      }
      return response;
    } catch (error) {
      if (error instanceof GoogleOAuthError && error.code === "google_existing_account_required") {
        return { ok: false, code: "ACCOUNT_EXISTS" };
      }
      throw error instanceof GoogleOAuthError ? error : new GoogleOAuthError();
    }
  }

  async function session(tx, user) {
    if (user.email_verified !== true) return { ok: false, code: "EMAIL_NOT_VERIFIED" };
    const token = jwt.sign({
      id: user.id, email: user.email, role: user.role, session_version: user.session_version,
    }, jwtSecret, { expiresIn: "7d" });
    await tx.consume();
    // execute returns this only AFTER the store successfully commits.
    return { ok: true, user: { id: user.id, email: user.email, role: user.role }, role: user.role, token };
  }

  async function resumePending(tx, pending) {
    if (pending.email_verified !== true) return { ok: true, code: "EMAIL_VERIFICATION_PENDING" };
    const email = typeof tx.identity.email === "string" ? tx.identity.email.trim().toLowerCase() : null;
    const fingerprint = crypto.createHash("sha256").update(pending.password_hash).digest("hex");
    if (pending.email !== pending.pending_email || email !== pending.pending_email ||
        pending.session_version !== pending.pending_session_version || fingerprint !== pending.pending_password_digest) {
      return { ok: false, code: "PENDING_ACCOUNT_CHANGED" };
    }
    // A verified, unchanged reservation must not expire solely because of its age.
    await tx.activatePending(pending.id, false);
    return session(tx, pending);
  }

  return {
    // Call only after Stage 1 verifyCallback; the DB, not browser fields, supplies identity.
    async resolve(proof) {
      return execute(proof, async tx => {
        const user = await tx.findLinkedUser();
        if (user) return session(tx, user);
        const pending = await tx.findPending();
        return pending ? resumePending(tx, pending) : { ok: true, next: "account_choice" };
      });
    },

    async linkExisting(input) {
      const { email, password, ...proof } = input ?? {};
      return execute(proof, async tx => {
        if (await tx.findLinkedUser()) return { ok: false, code: "GOOGLE_ALREADY_LINKED" };
        if (!await tx.takePasswordAttempt()) {
          await tx.consume();
          return { ok: false, code: "LINK_ATTEMPTS_EXHAUSTED" };
        }
        if (typeof email !== "string" || !email.trim() || typeof password !== "string" || !password) {
          return { ok: false, code: "INVALID_CREDENTIALS" };
        }
        // Pending-user lock precedes any other user lock, consistently with resolve.
        const pending = await tx.findPending();
        const user = await tx.findUserByEmail(email.trim().toLowerCase());
        if (!user || !await bcrypt.compare(password, user.password_hash)) return { ok: false, code: "INVALID_CREDENTIALS" };
        if (user.email_verified !== true) return { ok: false, code: "EMAIL_NOT_VERIFIED" };
        if (pending && pending.id !== user.id) return { ok: false, code: "PENDING_ACCOUNT_CONFLICT" };
        if (pending) await tx.activatePending(user.id, false);
        else await tx.link(user.id);
        return session(tx, user);
      });
    },

    async registerNew(proof) {
      return execute(proof, async tx => {
        const linked = await tx.findLinkedUser();
        if (linked) return session(tx, linked);
        const pending = await tx.findPending();
        if (pending) return resumePending(tx, pending);
        const { email, emailVerified } = tx.identity;
        if (typeof email !== "string" || email.length > 320 ||
            !/^[^\s@]+@[^\s@]+$/.test(email.trim())) {
          return { ok: false, code: "GOOGLE_EMAIL_REQUIRED" };
        }
        const normalized = email.trim().toLowerCase();
        if (await tx.findUserByEmail(normalized)) return { ok: false, code: "ACCOUNT_EXISTS" };
        const passwordHash = await bcrypt.hash(crypto.randomBytes(32).toString("base64url"), 10);
        const expires = new Date(now());
        expires.setDate(expires.getDate() + 30);
        const verifiedGmail = emailVerified === true && normalized.endsWith("@gmail.com");
        const verificationCreatedAt = new Date(now());
        const verification = verifiedGmail ? null : {
          token: crypto.randomBytes(32).toString("hex"), createdAt: verificationCreatedAt,
          expiresAt: new Date(verificationCreatedAt.getTime() + 24 * 60 * 60 * 1000),
        };
        const user = await tx.createUser(normalized, passwordHash, expires, verification);
        if (verifiedGmail) {
          await tx.link(user.id);
          return session(tx, user);
        }
        await tx.linkPending(user, verification);
        await tx.consume();
        return { ok: true, code: "EMAIL_VERIFICATION_PENDING", verificationMail: { email: user.email, token: verification.token } };
      });
    },

    async cancel(proof) {
      return execute(proof, async tx => {
        await tx.consume();
        return { ok: true, code: "CANCELLED" };
      });
    },
  };
}
