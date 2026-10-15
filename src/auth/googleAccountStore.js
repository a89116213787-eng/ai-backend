import crypto from "node:crypto";
import { GoogleOAuthError } from "./googleOAuth.js";

// Inert until explicitly supplied with a pool; never constructs a connection.
export function createGoogleAccountStore(pool) {
  if (typeof pool?.connect !== "function") throw new GoogleOAuthError("google_oauth_unavailable");

  return {
    async withVerifiedFlow({ flowId, browserBindingHash }, action) {
      const client = await pool.connect();
      let discard = false;
      try {
        await client.query("BEGIN ISOLATION LEVEL READ COMMITTED");
        await client.query("SET LOCAL lock_timeout = '3s'");
        await client.query("SET LOCAL statement_timeout = '5s'");
        const proof = await client.query(
          `SELECT id, google_sub, google_email, google_email_verified
           FROM public.google_oauth_flows
           WHERE id = $1 AND browser_binding_hash = $2
             AND status = 'verified' AND expires_at > clock_timestamp()
           FOR UPDATE`,
          [flowId, browserBindingHash]
        );
        const flow = proof.rows[0];
        if (!flow) throw new GoogleOAuthError("google_proof_invalid");

        // Separate verified flows for the same subject must not race each other.
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
          [`dizain:google-sub:${flow.google_sub}`]);

        const result = await action({
          identity: {
            subject: flow.google_sub,
            email: flow.google_email,
            emailVerified: flow.google_email_verified,
          },

          async findLinkedUser() {
            const result = await client.query(
              `SELECT u.id, u.email, u.role, u.email_verified, u.session_version
               FROM public.user_google_identities g JOIN public.users u ON u.id = g.user_id
               WHERE g.google_sub = $1 AND g.registration_pending = false FOR UPDATE OF u`,
              [flow.google_sub]
            );
            return result.rows[0] ?? null;
          },

          async findPending() {
            const result = await client.query(
              `SELECT u.id, u.email, u.password_hash, u.role, u.email_verified, u.session_version,
                      g.pending_email, g.pending_password_digest, g.pending_session_version,
                      g.pending_expires_at > clock_timestamp() AS pending_valid
               FROM public.user_google_identities g JOIN public.users u ON u.id = g.user_id
               WHERE g.google_sub = $1 AND g.registration_pending = true FOR UPDATE OF g, u`,
              [flow.google_sub]
            );
            return result.rows[0] ?? null;
          },

          async takePasswordAttempt() {
            const result = await client.query(
              `UPDATE public.google_oauth_flows SET password_attempts = password_attempts + 1
               WHERE id = $1 AND browser_binding_hash = $2
                 AND status = 'verified' AND expires_at > clock_timestamp() AND password_attempts < 5
               RETURNING password_attempts`,
              [flowId, browserBindingHash]
            );
            return result.rowCount === 1;
          },

          async findUserByEmail(email) {
            const result = await client.query(
              `SELECT id, email, password_hash, role, email_verified, session_version
               FROM public.users WHERE lower(btrim(email)) = $1 FOR UPDATE`,
              [email]
            );
            if (result.rows.length > 1) throw new GoogleOAuthError("google_account_ambiguous");
            return result.rows[0] ?? null;
          },

          async createUser(email, passwordHash, trialExpiresAt, verification = null) {
            // Do not assume a production index that is absent from the source tree.
            const schema = await client.query(
              `SELECT EXISTS (
                 SELECT 1 FROM pg_catalog.pg_index i
                 JOIN pg_catalog.pg_attribute a ON a.attrelid = i.indrelid
                   AND a.attnum = i.indkey[0]
                 WHERE i.indrelid = 'public.users'::regclass AND a.attname = 'email'
                   AND i.indisunique AND i.indisvalid AND i.indisready AND i.indimmediate
                   AND i.indnkeyatts = 1 AND i.indpred IS NULL AND i.indexprs IS NULL
               ) AS email_unique`
            );
            if (schema.rows[0]?.email_unique !== true) throw new GoogleOAuthError("google_schema_unavailable");
            const trial = await client.query(
              `INSERT INTO public.used_trials (email) VALUES ($1)
               ON CONFLICT (email) DO NOTHING RETURNING email`,
              [email]
            );
            const hasUsedTrial = trial.rowCount === 0;
            const inserted = await client.query(
              `INSERT INTO public.users
                 (email, password_hash, role, tokens, trial_used, email_verified,
                  email_verify_token, email_verify_expires, verification_reminders_sent)
               VALUES ($1, $2, 'user', $3, $4, $5, $6, $7, 0)
               ON CONFLICT DO NOTHING
               RETURNING id, email, password_hash, role, email_verified, session_version`,
              [email, passwordHash, hasUsedTrial ? 0 : 50, hasUsedTrial, verification === null,
                verification?.token ?? null, verification?.expiresAt ?? null]
            );
            const user = inserted.rows[0];
            if (!user) throw new GoogleOAuthError("google_existing_account_required");
            if (!hasUsedTrial) {
              await client.query(
                "INSERT INTO public.subscriptions (user_id, expires_at) VALUES ($1, $2)",
                [user.id, trialExpiresAt]
              );
            }
            return user;
          },

          async linkPending(user, verification) {
            const result = await client.query(
              `INSERT INTO public.user_google_identities
                 (google_sub, user_id, created_at, registration_pending, pending_email,
                  pending_password_digest, pending_session_version, pending_expires_at)
               VALUES ($1, $2, $3, true, $4, $5, $6, $7)
               ON CONFLICT (google_sub) DO NOTHING RETURNING user_id`,
              [flow.google_sub, user.id, verification.createdAt, user.email,
                crypto.createHash("sha256").update(user.password_hash).digest("hex"),
                user.session_version, verification.expiresAt]
            );
            if (result.rowCount !== 1) throw new GoogleOAuthError("google_identity_already_linked");
          },

          async activatePending(userId, requireUnexpired) {
            const result = await client.query(
              `UPDATE public.user_google_identities
               SET registration_pending = false, pending_email = NULL, pending_password_digest = NULL,
                   pending_session_version = NULL, pending_expires_at = NULL
               WHERE google_sub = $1 AND user_id = $2 AND registration_pending = true
                 AND ($3 = false OR pending_expires_at > clock_timestamp()) RETURNING user_id`,
              [flow.google_sub, userId, requireUnexpired]
            );
            if (result.rowCount !== 1) throw new GoogleOAuthError("google_pending_invalid");
          },

          async link(userId) {
            const result = await client.query(
              `INSERT INTO public.user_google_identities (google_sub, user_id)
               VALUES ($1, $2) ON CONFLICT (google_sub) DO NOTHING RETURNING user_id`,
              [flow.google_sub, userId]
            );
            if (result.rowCount !== 1) throw new GoogleOAuthError("google_identity_already_linked");
          },

          async consume() {
            const result = await client.query(
              `UPDATE public.google_oauth_flows
               SET status = 'consumed', google_sub = NULL, google_email = NULL,
                   google_email_verified = NULL, google_hosted_domain = NULL, verified_at = NULL
               WHERE id = $1 AND browser_binding_hash = $2
                 AND status = 'verified' AND expires_at > clock_timestamp()
               RETURNING id`,
              [flowId, browserBindingHash]
            );
            if (result.rowCount !== 1) throw new GoogleOAuthError("google_proof_invalid");
          },
        });
        await client.query("COMMIT");
        return result;
      } catch (error) {
        try { await client.query("ROLLBACK"); } catch { discard = true; }
        throw error;
      } finally {
        client.release(discard);
      }
    },
  };
}
