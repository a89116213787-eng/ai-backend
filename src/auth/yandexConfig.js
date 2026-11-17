export const YANDEX_FLOW_TTL_MS = 10 * 60 * 1000;
export const YANDEX_CALLBACK_PATH = "/api/auth/yandex/callback";
export const YANDEX_SCOPE = "login:email";

export function loadYandexOAuthConfig(env = process.env) {
  const clientId = env.YANDEX_CLIENT_ID;
  const clientSecret = env.YANDEX_CLIENT_SECRET;
  const redirectUri = env.YANDEX_OAUTH_REDIRECT_URI;
  const encodedKey = env.YANDEX_OAUTH_STATE_KEY;
  try {
    if (typeof clientId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(clientId) ||
        typeof clientSecret !== "string" || !clientSecret.trim() ||
        typeof redirectUri !== "string" || redirectUri !== redirectUri.trim() || /[?#]/.test(redirectUri) ||
        typeof encodedKey !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(encodedKey)) return { ready: false };
    const uri = new URL(redirectUri);
    const stateKey = Buffer.from(encodedKey, "base64url");
    if (uri.protocol !== "https:" || uri.username || uri.password || uri.pathname !== YANDEX_CALLBACK_PATH ||
        stateKey.length !== 32 || stateKey.toString("base64url") !== encodedKey) return { ready: false };
    return { ready: true, config: { clientId, clientSecret, redirectUri, stateKey } };
  } catch {
    return { ready: false };
  }
}
