export function createYandexFlowStore(pool) {
  return {
    async create(flow) {
      await pool.query(
        `INSERT INTO public.yandex_oauth_flows
          (id, state_hash, browser_binding_hash, code_verifier_box, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [flow.id, flow.stateHash, flow.browserBindingHash, flow.codeVerifierBox, flow.createdAt, flow.expiresAt]
      );
    },
    async claim(stateHash, browserBindingHash) {
      const result = await pool.query(
        `UPDATE public.yandex_oauth_flows SET status = 'exchanging'
         WHERE state_hash = $1 AND browser_binding_hash = $2
           AND status = 'pending' AND expires_at > clock_timestamp()
         RETURNING id, state_hash, browser_binding_hash, code_verifier_box`,
        [stateHash, browserBindingHash]
      );
      const row = result.rows[0];
      return row ? { id: row.id, stateHash: row.state_hash,
        browserBindingHash: row.browser_binding_hash, codeVerifierBox: row.code_verifier_box } : null;
    },
    async verify(id, identity) {
      const result = await pool.query(
        `UPDATE public.yandex_oauth_flows
         SET status = 'verified', code_verifier_box = NULL, yandex_id = $2,
             yandex_email = $3, email_trusted = $4, verified_at = clock_timestamp()
         WHERE id = $1 AND status = 'exchanging' AND expires_at > clock_timestamp() RETURNING id`,
        [id, identity.subject, identity.email, identity.emailTrusted]
      );
      return result.rowCount === 1;
    },
    async fail(id) {
      await pool.query(
        `UPDATE public.yandex_oauth_flows SET status = 'failed', code_verifier_box = NULL
         WHERE id = $1 AND status = 'exchanging'`, [id]
      );
    },
  };
}
