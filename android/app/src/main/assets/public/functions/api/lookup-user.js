// functions/api/lookup-user.js
// Cloudflare Pages Function — pre-login (unauthenticated) user lookups.
//
// WHY THIS EXISTS:
// Database rules require auth != null to read the 'users' node (correct —
// otherwise anyone could read everyone's Aadhar/PAN/password hash). But two
// features need to check the 'users' table BEFORE a session exists:
//   1. Registration — duplicate mobile-number check
//   2. "Password bhool gaye" — find account by userId/mobile + email
//
// This function uses the same Firebase service-account access token as
// /api/login (bypasses rules, like Admin SDK would). It ONLY ever returns
// non-sensitive fields (name, userId, mobile, email). It NEVER returns
// aadhar, pan, password, passwordSalt, walletBal, or any other field.

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Access-Control-Allow-Origin": "*", "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function base64url(input) {
  let bytes;
  if (typeof input === "string") {
    bytes = new TextEncoder().encode(input);
  } else {
    bytes = new Uint8Array(input);
  }
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function importPrivateKey(pem) {
  const keyData = pemToArrayBuffer(pem);
  return crypto.subtle.importKey(
    "pkcs8",
    keyData,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

async function signJWT(header, payload, privateKeyPem) {
  const encHeader = base64url(JSON.stringify(header));
  const encPayload = base64url(JSON.stringify(payload));
  const toSign = `${encHeader}.${encPayload}`;
  const key = await importPrivateKey(privateKeyPem);
  const sigBuffer = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(toSign)
  );
  return `${toSign}.${base64url(sigBuffer)}`;
}

async function getGoogleAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: env.FIREBASE_CLIENT_EMAIL,
    scope: "https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };
  const assertion = await signJWT(header, payload, env.FIREBASE_PRIVATE_KEY);
  const resp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${assertion}`,
  });
  const data = await resp.json();
  if (!data.access_token) throw new Error("Google token fetch fail: " + JSON.stringify(data));
  return data.access_token;
}

async function dbFetch(env, path, accessToken, extraQuery = "") {
  const url = `https://${env.FIREBASE_PROJECT_ID}-default-rtdb.firebaseio.com/${path}.json?access_token=${accessToken}${extraQuery}`;
  const resp = await fetch(url);
  return resp.json();
}

async function dbPatch(env, path, accessToken, body) {
  const url = `https://${env.FIREBASE_PROJECT_ID}-default-rtdb.firebaseio.com/${path}.json?access_token=${accessToken}`;
  const resp = await fetch(url, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return resp.json();
}

// Random 48-hex-char token (24 random bytes) — unguessable, used once.
function generateResetToken() {
  const arr = new Uint8Array(24);
  crypto.getRandomValues(arr);
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Strip everything except the safe, non-sensitive fields before it ever
// leaves the server.
function safeFields(record, key) {
  return {
    userId: record.userId || key,
    name: record.name || "",
    mobile: record.mobile || "",
    email: record.email || "",
  };
}

async function findUserByIdOrMobile(env, accessToken, id) {
  let data = await dbFetch(
    env,
    "users",
    accessToken,
    `&orderBy=%22userId%22&equalTo=%22${encodeURIComponent(id)}%22`
  );
  let key = data ? Object.keys(data)[0] : null;
  if (!key) {
    data = await dbFetch(
      env,
      "users",
      accessToken,
      `&orderBy=%22mobile%22&equalTo=%22${encodeURIComponent(id)}%22`
    );
    key = data ? Object.keys(data)[0] : null;
  }
  if (!key) return null;
  return { key, record: data[key] };
}

export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    const body = await request.json();
    const { mode } = body || {};

    if (mode === "duplicate-check") {
      const mobile = String(body.mobile || "").trim();
      if (!mobile) return json({ error: "mobile zaroori hai" }, 400);

      const accessToken = await getGoogleAccessToken(env);
      const data = await dbFetch(
        env,
        "users",
        accessToken,
        `&orderBy=%22mobile%22&equalTo=%22${encodeURIComponent(mobile)}%22`
      );
      const exists = !!(data && Object.keys(data).length > 0);
      return json({ exists });
    }

    if (mode === "forgot-password") {
      const id = String(body.id || "").trim();
      const email = String(body.email || "").trim().toLowerCase();
      if (!id || !email) return json({ error: "id aur email zaroori hain" }, 400);

      const accessToken = await getGoogleAccessToken(env);
      const found = await findUserByIdOrMobile(env, accessToken, id);
      if (!found || (found.record.email || "").toLowerCase() !== email) {
        return json({ found: false });
      }

      // Password abhi change NAHI karte. Sirf ek one-time reset token
      // banao aur alag (public-facing rules se completely bahar) node
      // 'password_resets' mein save karo. User jab link kholke naya
      // password submit karega, tabhi /api/reset-password isi token ko
      // verify karke password badlega. 30 minute mein expire ho jata hai.
      const token = generateResetToken();
      const expiresAt = Date.now() + 30 * 60 * 1000;
      await dbPatch(env, `password_resets/${token}`, accessToken, {
        userId: found.key,
        used: false,
        expiresAt,
      });

      return json({
        found: true,
        user: safeFields(found.record, found.key),
        resetToken: token,
      });
    }

    return json({ error: "Invalid mode" }, 400);
  } catch (err) {
    return json({ error: "Server error: " + err.message }, 500);
  }
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}
