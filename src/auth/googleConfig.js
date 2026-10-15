export const GOOGLE_FLOW_TTL_MS = 10 * 60 * 1000;
export const GOOGLE_CALLBACK_PATH = "/api/auth/google/callback";

export function loadGoogleOAuthConfig(env = process.env) {
  const clientId = env.GOOGLE_CLIENT_ID;
  const clientSecret = env.GOOGLE_CLIENT_SECRET;
  const redirectUri = env.GOOGLE_OAUTH_REDIRECT_URI;
  const encodedKey = env.GOOGLE_OAUTH_STATE_KEY;

  try {
    if (
      typeof clientId !== "string" ||
      !/^[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$/.test(clientId) ||
      typeof clientSecret !== "string" || !clientSecret.trim() ||
      typeof redirectUri !== "string" ||
      redirectUri !== redirectUri.trim() || /[?#]/.test(redirectUri) ||
      typeof encodedKey !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(encodedKey)
    ) {
      return { ready: false };
    }

    const uri = new URL(redirectUri);
    const stateKey = Buffer.from(encodedKey, "base64url");
    if (
      uri.protocol !== "https:" || uri.username || uri.password ||
      uri.search || uri.hash || uri.pathname !== GOOGLE_CALLBACK_PATH ||
      stateKey.length !== 32 || stateKey.toString("base64url") !== encodedKey
    ) {
      return { ready: false };
    }

    return { ready: true, config: { clientId, clientSecret, redirectUri, stateKey } };
  } catch {
    return { ready: false };
  }
}

export async function createGoogleIdentityClient(config) {
  const { OAuth2Client } = await import("google-auth-library");
  return new OAuth2Client({
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    redirectUri: config.redirectUri,
    useAuthRequestParameters: false,
    transporterOptions: {
      timeout: 5000,
      retryConfig: { retry: 0 },
      maxContentLength: 128 * 1024,
    },
  });
}
