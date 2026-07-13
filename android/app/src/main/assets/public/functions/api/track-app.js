// functions/api/track-app.js
// Cloudflare Pages Function — Android app se "app open" events log karta hai.
//
// WHY THIS EXISTS:
// Admin ko dekhna hai ki (a) app kitne alag phones par install/use ho rahi hai,
// aur (b) un mein se kitne aur kaun log actually login karke use kar rahe hain
// (naam + mobile ke saath). Website ke bina-login visitor bhi count hote hain
// (sirf deviceId ke saath), login karne ke baad wahi record naam/mobile se
// enrich ho jaata hai — isliye ek hi device ka ek hi row rehta hai.
//
// Service-account access token use hota hai (jaisa /api/login mein), isliye
// ye rules bypass karta hai — koi bhi client-side rule change zaroori nahi.
// Sirf non-sensitive fields save hote hain (naam, mobile, userId, timestamps).

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
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

async function dbFetch(env, path, accessToken) {
  const url = `https://${env.FIREBASE_PROJECT_ID}-default-rtdb.firebaseio.com/${path}.json?access_token=${accessToken}`;
  const resp = await fetch(url);
  return resp.json();
}

export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    const body = await request.json();
    const { deviceId, name, mobile, userId, platform } = body || {};
    if (!deviceId || typeof deviceId !== "string") {
      return json({ error: "deviceId zaroori hai" }, 400);
    }

    const accessToken = await getGoogleAccessToken(env);
    const safeId = deviceId.replace(/[.#$\[\]\/]/g, "_").slice(0, 200);
    const path = `admin/app_usage/${safeId}`;

    const existing = await dbFetch(env, path, accessToken);
    const now = Date.now();

    const update = {
      lastSeenAt: now,
      opens: (existing && existing.opens ? existing.opens : 0) + 1,
      platform: platform || (existing && existing.platform) || "android",
    };
    if (!existing) update.installedAt = now;
    // Sirf tab overwrite karo jab value di gayi ho — taaki bina-login open
    // (jisme naam/mobile nahi hota) pehle se pata chala naam/mobile ko mita na de.
    if (name) update.name = name;
    if (mobile) update.mobile = mobile;
    if (userId) update.userId = userId;

    const writeUrl = `https://${env.FIREBASE_PROJECT_ID}-default-rtdb.firebaseio.com/${path}.json?access_token=${accessToken}`;
    await fetch(writeUrl, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(update),
    });

    return json({ ok: true });
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
