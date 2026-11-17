import { GoogleOAuthError } from "./googleOAuth.js";

// Implements the unchanged Google account service contract using only Yandex identity/flow tables.
export function createYandexAccountStore(pool) {
  if (typeof pool?.connect !== "function") throw new GoogleOAuthError("google_oauth_unavailable");
  return {
    async withVerifiedFlow({ flowId, browserBindingHash }, action) {
      const client = await pool.connect();
      let discard = false;
      let committing = false;
      try {
        await client.query("BEGIN ISOLATION LEVEL READ COMMITTED");
        await client.query("SET LOCAL lock_timeout = '3s'");
        await client.query("SET LOCAL statement_timeout = '5s'");
        const proof = await client.query(
          `SELECT id, yandex_id, yandex_email, email_trusted FROM public.yandex_oauth_flows
           WHERE id = $1 AND browser_binding_hash = $2 AND status = 'verified'
             AND expires_at > clock_timestamp() FOR UPDATE`, [flowId, browserBindingHash]
        );
        const flow = proof.rows[0];
        if (!flow) throw new GoogleOAuthError("google_proof_invalid");
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`dizain:yandex-id:${flow.yandex_id}`]);
        const result = await action({
          identity: { subject: flow.yandex_id, email: flow.email_trusted === true ? flow.yandex_email : null,
            emailVerified: false },
          async findLinkedUser() {
            const result = await client.query(
              `SELECT u.id, u.email, u.role, u.email_verified, u.session_version
               FROM public.user_yandex_identities y JOIN public.users u ON u.id = y.user_id
               WHERE y.yandex_id = $1 FOR UPDATE OF y, u`, [flow.yandex_id]
            );
            return result.rows[0] ?? null;
          },
          async findPending() { return null; },
          async findUserByEmail(email) {
            const result = await client.query(
              `SELECT id, email, password_hash, role, email_verified, session_version
               FROM public.users WHERE lower(btrim(email)) = $1 FOR UPDATE`, [email]
            );
            if (result.rows.length > 1) throw new GoogleOAuthError("google_account_ambiguous");
            return result.rows[0] ?? null;
          },
          async verifyEmail(userId) {
            const result = await client.query(
              `UPDATE public.users SET email_verified = true, email_verify_token = NULL,
                 email_verify_expires = NULL, verification_reminders_sent = 0
               WHERE id = $1 RETURNING id, email, role, email_verified, session_version`, [userId]
            );
            if (result.rowCount !== 1) throw new GoogleOAuthError();
            return result.rows[0];
          },
          async createUser(email, passwordHash, trialExpiresAt) {
            const schema = await client.query(
              `SELECT EXISTS (
                 SELECT 1 FROM pg_catalog.pg_index i
                 JOIN pg_catalog.pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
                 WHERE i.indrelid = 'public.users'::regclass AND a.attname = 'email'
                   AND i.indisunique AND i.indisvalid AND i.indisready AND i.indimmediate
                   AND i.indnkeyatts = 1 AND i.indpred IS NULL AND i.indexprs IS NULL
               ) AS email_unique`
            );
            if (schema.rows[0]?.email_unique !== true) throw new GoogleOAuthError("google_schema_unavailable");
            const trial = await client.query(
              `INSERT INTO public.used_trials (email) VALUES ($1)
               ON CONFLICT (email) DO NOTHING RETURNING email`, [email]
            );
            const hasUsedTrial = trial.rowCount === 0;
            const inserted = await client.query(
              `INSERT INTO public.users
                 (email, password_hash, role, tokens, trial_used, email_verified,
                  email_verify_token, email_verify_expires, verification_reminders_sent)
               VALUES ($1, $2, 'user', $3, $4, true, NULL, NULL, 0)
               ON CONFLICT DO NOTHING
               RETURNING id, email, password_hash, role, email_verified, session_version`,
              [email, passwordHash, hasUsedTrial ? 0 : 50, hasUsedTrial]
            );
            const user = inserted.rows[0];
            if (!user) throw new GoogleOAuthError("google_existing_account_required");
            if (!hasUsedTrial) await client.query(
              "INSERT INTO public.subscriptions (user_id, expires_at) VALUES ($1, $2)", [user.id, trialExpiresAt]
            );
            return user;
          },
          async link(userId) {
            const result = await client.query(
              `INSERT INTO public.user_yandex_identities (yandex_id, user_id)
               VALUES ($1, $2) ON CONFLICT (yandex_id) DO NOTHING RETURNING user_id`, [flow.yandex_id, userId]
            );
            if (result.rowCount !== 1) throw new GoogleOAuthError("google_identity_already_linked");
          },
          async consume() {
            const result = await client.query(
              `UPDATE public.yandex_oauth_flows SET status = 'consumed', yandex_id = NULL,
                 yandex_email = NULL, email_trusted = NULL, verified_at = NULL
               WHERE id = $1 AND browser_binding_hash = $2 AND status = 'verified'
                 AND expires_at > clock_timestamp() RETURNING id`, [flowId, browserBindingHash]
            );
            if (result.rowCount !== 1) throw new GoogleOAuthError("google_proof_invalid");
          },
        });
        committing = true;
        await client.query("COMMIT");
        committing = false;
        return result;
      } catch (error) {
        discard = committing;
        try { await client.query("ROLLBACK"); } catch { discard = true; }
        // Never turn an unknown COMMIT outcome into a registration retry.
        if (committing) throw new GoogleOAuthError();
        throw error;
      } finally {
        client.release(discard);
      }
    },
  };
}
