/**
 * LINE Login -> Firebase Custom Token issuer (Cloudflare Worker)
 *
 * Endpoints:
 * - GET  /line/start?returnTo=<url>
 * - GET  /line/callback?code=...&state=...
 *
 * Required env vars (wrangler secrets):
 * - LINE_CHANNEL_ID
 * - LINE_CHANNEL_SECRET
 * - FIREBASE_PROJECT_ID
 * - FIREBASE_CLIENT_EMAIL
 * - FIREBASE_PRIVATE_KEY          (service account private key; keep line breaks, or use \n)
 *
 * Optional:
 * - APP_ORIGIN_ALLOWLIST          (comma-separated origins allowed for returnTo; recommended)
 */

function base64UrlEncode(bytes) {
  let binary = "";
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) binary += String.fromCharCode(bytes[i]);
  const b64 = btoa(binary);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function textToBytes(s) {
  return new TextEncoder().encode(s);
}

function randomHex(bytesLen = 16) {
  const b = new Uint8Array(bytesLen);
  crypto.getRandomValues(b);
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function cookieParse(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  const parts = cookieHeader.split(";");
  for (const p of parts) {
    const idx = p.indexOf("=");
    if (idx === -1) continue;
    const k = p.slice(0, idx).trim();
    const v = p.slice(idx + 1).trim();
    out[k] = v;
  }
  return out;
}

function cookieSerialize(name, value, opts = {}) {
  const attrs = [];
  attrs.push(`${name}=${value}`);
  attrs.push(`Path=${opts.path || "/"}`);
  if (opts.httpOnly !== false) attrs.push("HttpOnly");
  if (opts.secure !== false) attrs.push("Secure");
  attrs.push(`SameSite=${opts.sameSite || "Lax"}`);
  if (opts.maxAge != null) attrs.push(`Max-Age=${opts.maxAge}`);
  return attrs.join("; ");
}

function isAllowedReturnTo(returnTo, allowlist) {
  if (!returnTo) return false;
  let u;
  try {
    u = new URL(returnTo);
  } catch {
    return false;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return false;
  if (!allowlist || !allowlist.length) return true; // allow all (not recommended)
  return allowlist.includes(u.origin);
}

function buildLineAuthUrl({ clientId, redirectUri, state, nonce }) {
  const u = new URL("https://access.line.me/oauth2/v2.1/authorize");
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", clientId);
  u.searchParams.set("redirect_uri", redirectUri);
  u.searchParams.set("state", state);
  // openid: id_token を受け取り、sub を安定IDとして利用
  u.searchParams.set("scope", "profile openid email");
  u.searchParams.set("nonce", nonce);
  // 追加: 友だち追加など不要なので prompt は指定しない
  return u.toString();
}

async function exchangeLineCode({ code, redirectUri, clientId, clientSecret }) {
  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("code", code);
  body.set("redirect_uri", redirectUri);
  body.set("client_id", clientId);
  body.set("client_secret", clientSecret);

  const res = await fetch("https://api.line.me/oauth2/v2.1/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const json = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error(`LINE token exchange failed: ${res.status} ${JSON.stringify(json)}`);
  }
  return json;
}

async function verifyLineIdToken({ idToken, clientId }) {
  const body = new URLSearchParams();
  body.set("id_token", idToken);
  body.set("client_id", clientId);
  const res = await fetch("https://api.line.me/oauth2/v2.1/verify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const json = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error(`LINE id_token verify failed: ${res.status} ${JSON.stringify(json)}`);
  }
  return json;
}

async function importRsaPrivateKeyFromPem(pem) {
  const clean = pem
    .replace(/\\n/g, "\n")
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s+/g, "");
  const raw = Uint8Array.from(atob(clean), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "pkcs8",
    raw.buffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

async function signJwtRs256({ privateKeyPem, header, payload }) {
  const key = await importRsaPrivateKeyFromPem(privateKeyPem);
  const encHeader = base64UrlEncode(textToBytes(JSON.stringify(header)));
  const encPayload = base64UrlEncode(textToBytes(JSON.stringify(payload)));
  const data = textToBytes(`${encHeader}.${encPayload}`);
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, data);
  const encSig = base64UrlEncode(new Uint8Array(sig));
  return `${encHeader}.${encPayload}.${encSig}`;
}

async function createFirebaseCustomToken({ projectId, clientEmail, privateKeyPem, uid, claims }) {
  const iat = nowSec();
  const exp = iat + 60 * 60; // 1 hour

  // Firebase custom token format:
  // https://firebase.google.com/docs/auth/admin/create-custom-tokens
  const payload = {
    iss: clientEmail,
    sub: clientEmail,
    aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
    iat,
    exp,
    uid,
  };

  if (claims && typeof claims === "object") {
    payload.claims = claims;
  }

  return await signJwtRs256({
    privateKeyPem,
    header: { alg: "RS256", typ: "JWT" },
    payload,
  });
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function redirect(to, headers = {}) {
  return new Response(null, { status: 302, headers: { Location: to, ...headers } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const allowlist = String(env.APP_ORIGIN_ALLOWLIST || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    if (url.pathname === "/") {
      return jsonResponse({
        ok: true,
        endpoints: ["/line/start", "/line/callback"],
        note: "Deploy this worker and set LINE_AUTH_START_URL to https://<worker-domain>/line/start",
      });
    }

    if (url.pathname === "/line/start") {
      const returnTo = url.searchParams.get("returnTo") || "";
      if (!isAllowedReturnTo(returnTo, allowlist)) {
        return jsonResponse(
          {
            ok: false,
            error: "returnTo is not allowed. Set APP_ORIGIN_ALLOWLIST to your site origin(s).",
            returnTo,
            allowlist,
          },
          400,
        );
      }

      const state = randomHex(16);
      const nonce = randomHex(16);

      // callback URL is worker's /line/callback
      const redirectUri = new URL("/line/callback", url.origin).toString();

      // store state/nonce/returnTo in HttpOnly cookie (short-lived)
      const payload = btoa(
        JSON.stringify({
          state,
          nonce,
          returnTo,
          createdAt: Date.now(),
        }),
      )
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");

      const setCookie = cookieSerialize("line_oauth", payload, {
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        path: "/",
        maxAge: 10 * 60, // 10 min
      });

      const authUrl = buildLineAuthUrl({
        clientId: env.LINE_CHANNEL_ID,
        redirectUri,
        state,
        nonce,
      });

      return redirect(authUrl, { "Set-Cookie": setCookie });
    }

    if (url.pathname === "/line/callback") {
      const code = url.searchParams.get("code") || "";
      const state = url.searchParams.get("state") || "";
      if (!code || !state) {
        return jsonResponse({ ok: false, error: "Missing code/state" }, 400);
      }

      const cookies = cookieParse(request.headers.get("Cookie") || "");
      const raw = cookies.line_oauth || "";
      if (!raw) return jsonResponse({ ok: false, error: "Missing session cookie" }, 400);

      let session;
      try {
        const padded = raw.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((raw.length + 3) % 4);
        session = JSON.parse(atob(padded));
      } catch {
        return jsonResponse({ ok: false, error: "Invalid session cookie" }, 400);
      }

      if (session.state !== state) {
        return jsonResponse({ ok: false, error: "State mismatch" }, 400);
      }

      const redirectUri = new URL("/line/callback", url.origin).toString();
      const tokenRes = await exchangeLineCode({
        code,
        redirectUri,
        clientId: env.LINE_CHANNEL_ID,
        clientSecret: env.LINE_CHANNEL_SECRET,
      });

      // Prefer id_token (openid) to get stable user ID (sub)
      const idToken = tokenRes.id_token;
      if (!idToken) {
        return jsonResponse(
          {
            ok: false,
            error: "No id_token returned from LINE. Ensure scope includes openid and that LINE Login is configured.",
            tokenRes,
          },
          400,
        );
      }

      const verified = await verifyLineIdToken({
        idToken,
        clientId: env.LINE_CHANNEL_ID,
      });

      const lineSub = String(verified.sub || "").trim();
      if (!lineSub) {
        return jsonResponse({ ok: false, error: "LINE verify response missing sub", verified }, 400);
      }

      // Firebase UID: prefix to avoid collision
      const firebaseUid = `line:${lineSub}`.slice(0, 128);

      const customToken = await createFirebaseCustomToken({
        projectId: env.FIREBASE_PROJECT_ID,
        clientEmail: env.FIREBASE_CLIENT_EMAIL,
        privateKeyPem: env.FIREBASE_PRIVATE_KEY,
        uid: firebaseUid,
        claims: {
          provider: "line",
          line: {
            sub: lineSub,
            name: verified.name || "",
            picture: verified.picture || "",
            email: verified.email || "",
          },
        },
      });

      // clear cookie
      const clearCookie = cookieSerialize("line_oauth", "", {
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        path: "/",
        maxAge: 0,
      });

      const returnTo = session.returnTo || "";
      if (!isAllowedReturnTo(returnTo, allowlist)) {
        return jsonResponse(
          { ok: false, error: "returnTo not allowed (post-auth)", returnTo, allowlist },
          400,
        );
      }

      const back = new URL(returnTo);
      back.searchParams.set("firebaseCustomToken", customToken);
      return redirect(back.toString(), { "Set-Cookie": clearCookie });
    }

    return jsonResponse({ ok: false, error: "Not Found" }, 404);
  },
};

