-- MANUAL REVIEW ONLY. Not executed by the application.
-- Additive schema; existing users, trials and Google tables are unchanged.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

CREATE TABLE public.user_yandex_identities (
  yandex_id text COLLATE "C" PRIMARY KEY CHECK (yandex_id ~ '^[!-~]{1,255}$'),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX user_yandex_identities_user_id_idx ON public.user_yandex_identities(user_id);

CREATE TABLE public.yandex_oauth_flows (
  id uuid PRIMARY KEY,
  state_hash text COLLATE "C" NOT NULL UNIQUE CHECK (state_hash ~ '^[a-f0-9]{64}$'),
  browser_binding_hash text COLLATE "C" NOT NULL CHECK (browser_binding_hash ~ '^[a-f0-9]{64}$'),
  code_verifier_box text CHECK (length(code_verifier_box) BETWEEN 1 AND 512),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'exchanging', 'verified', 'failed', 'consumed')),
  yandex_id text COLLATE "C" CHECK (yandex_id ~ '^[!-~]{1,255}$'),
  yandex_email text CHECK (length(yandex_email) <= 320),
  -- Application email-matching policy; not a provider email_verified claim.
  email_trusted boolean,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  verified_at timestamptz,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes'),
  CHECK (
    (status IN ('pending', 'exchanging') AND code_verifier_box IS NOT NULL
      AND yandex_id IS NULL AND yandex_email IS NULL AND email_trusted IS NULL AND verified_at IS NULL)
    OR
    (status = 'verified' AND code_verifier_box IS NULL AND yandex_id IS NOT NULL
      AND email_trusted IS NOT NULL AND verified_at IS NOT NULL)
    OR
    (status IN ('failed', 'consumed') AND code_verifier_box IS NULL
      AND yandex_id IS NULL AND yandex_email IS NULL AND email_trusted IS NULL AND verified_at IS NULL)
  )
);
CREATE INDEX yandex_oauth_flows_expires_at_idx ON public.yandex_oauth_flows(expires_at);

COMMIT;
