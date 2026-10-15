// No connection is created here. A future caller must explicitly supply a pool.
export function createGoogleFlowStore(pool) {
  return {
    async create(flow) {
      await pool.query(
        `INSERT INTO public.google_oauth_flows
          (id, state_hash, browser_binding_hash, nonce_hash, code_verifier_box,
           created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [flow.id, flow.stateHash, flow.browserBindingHash, flow.nonceHash,
          flow.codeVerifierBox, flow.createdAt, flow.expiresAt]
      );
    },

    async claim(stateHash, browserBindingHash) {
      // One atomic transition, shared by all workers; never reset to pending.
      const result = await pool.query(
        `UPDATE public.google_oauth_flows
         SET status = 'exchanging'
         WHERE state_hash = $1 AND browser_binding_hash = $2
           AND status = 'pending' AND expires_at > NOW()
         RETURNING id, state_hash, browser_binding_hash, nonce_hash, code_verifier_box`,
        [stateHash, browserBindingHash]
      );
      const row = result.rows[0];
      return row ? {
        id: row.id,
        stateHash: row.state_hash,
        browserBindingHash: row.browser_binding_hash,
        nonceHash: row.nonce_hash,
        codeVerifierBox: row.code_verifier_box,
      } : null;
    },

    async verify(id, identity) {
      const result = await pool.query(
        `UPDATE public.google_oauth_flows
         SET status = 'verified', nonce_hash = NULL, code_verifier_box = NULL,
             google_sub = $2, google_email = $3, google_email_verified = $4,
             google_hosted_domain = $5, verified_at = NOW()
         WHERE id = $1 AND status = 'exchanging' AND expires_at > NOW()
         RETURNING id`,
        [id, identity.subject, identity.email, identity.emailVerified, identity.hostedDomain]
      );
      return result.rowCount === 1;
    },

    async fail(id) {
      await pool.query(
        `UPDATE public.google_oauth_flows
         SET status = 'failed', nonce_hash = NULL, code_verifier_box = NULL
         WHERE id = $1 AND status = 'exchanging'`,
        [id]
      );
    },
  };
}
