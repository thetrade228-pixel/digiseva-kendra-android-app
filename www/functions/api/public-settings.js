// functions/api/public-settings.js
// Public, read-only endpoint for data that index.html (the public website)
// needs — website content settings + maintenance flag.
//
// ✅ WHY THIS FILE EXISTS:
// index.html pehle in paths ('admin/website_settings', 'admin/settings/maintenance')
// ko seedha client-side Firebase SDK se padhta tha. Agar Firebase Rules in
// paths ko sirf logged-in users ke liye allow karte hain, to ek normal
// (bina-login) website visitor ke liye ye read fail ho jaata tha — isliye
// admin ke changes sirf un browsers mein dikhte the jinme pehle se koi
// (admin/user) login karke baitha tha (kyunki Firebase Auth session poore
// browser mein persist hota hai).
//
// Ye endpoint service-account credentials (wahi jo /api/login mein use hote
// hain) se data padhta hai — ye rules ko bypass karta hai (bilkul waise jaise
// Firebase Admin SDK karta hai), isliye HAR visitor ko (login ho ya na ho)
// hamesha latest data milta hai.
//
// Sirf READ-ONLY hai, koi write/sensitive data nahi — website content aur
// maintenance flag public info hi hote hain, isliye ye surakshit hai.

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Content-Type": "application/json",
      // Browser/CDN cache mat karo — hamesha fresh data do taaki admin ka
      // change turant reflect ho.
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

export async function onRequestGet(context) {
  const { env } = context;
  try {
    const accessToken = await getGoogleAccessToken(env);

    const [websiteSettings, maintenance] = await Promise.all([
      dbFetch(env, "admin/website_settings", accessToken),
      dbFetch(env, "admin/settings/maintenance", accessToken),
    ]);

    return json({
      websiteSettings: websiteSettings || {},
      maintenance: maintenance === true,
    });
  } catch (err) {
    return json({ error: "Server error: " + err.message }, 500);
  }
}
