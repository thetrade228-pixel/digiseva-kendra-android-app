// functions/api/reset-password.js
// Cloudflare Pages Function — final step of the "Password bhool gaye" flow.
//
// User email mein mila hua link kholta hai (?reset=TOKEN), naya password
// type karta hai, aur wo yahan POST hota hai. Ye function:
//   1. Token ko 'password_resets/{token}' mein verify karta hai
//      (exists, expire nahi hua, pehle use nahi hua)
//   2. Naye password ko registration jaisa hi salt+hash karke
//      'users/{userId}' mein save karta hai
//   3. Token ko turant "used" mark kar deta hai (dobara use na ho)
//
// Service-account access token use hota hai (jaisa /api/login mein), isliye
// ye rules bypass karta hai — koi bhi client-side rule change zaroori nahi.

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

async function dbFetch(env, path, accessToken) {
  const url = `https://${env.FIREBASE_PROJECT_ID}-default-rtdb.firebaseio.com/${path}.json?access_token=${accessToken}`;
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

async function sha256Hex(str) {
  const data = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function generateSalt() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    const body = await request.json();
    const token = String(body.token || "").trim();
    const newPassword = String(body.newPassword || "");

    if (!token || !newPassword) {
      return json({ error: "Token aur naya password zaroori hain" }, 400);
    }
    if (newPassword.length < 6) {
      return json({ error: "Password kam se kam 6 characters ka hona chahiye" }, 400);
    }

    const accessToken = await getGoogleAccessToken(env);

    const resetRecord = await dbFetch(env, `password_resets/${token}`, accessToken);
    if (!resetRecord) {
      return json({ error: "Ye link invalid ya expire ho chuka hai. Dobara reset request karen." }, 400);
    }
    if (resetRecord.used) {
      return json({ error: "Ye link pehle hi use ho chuka hai. Dobara reset request karen." }, 400);
    }
    if (!resetRecord.expiresAt || Date.now() > resetRecord.expiresAt) {
      return json({ error: "Ye link expire ho chuka hai. Dobara reset request karen." }, 400);
    }

    const userId = resetRecord.userId;
    const userRecord = await dbFetch(env, `users/${userId}`, accessToken);
    if (!userRecord) {
      return json({ error: "Account nahi mila." }, 400);
    }

    const newSalt = generateSalt();
    const newHash = await sha256Hex(newPassword + "::" + newSalt);
    await dbPatch(env, `users/${userId}`, accessToken, {
      password: newHash,
      passwordSalt: newSalt,
    });

    // Token turant use hua mark karo taaki dobara kaam na kare
    await dbPatch(env, `password_resets/${token}`, accessToken, { used: true });

    return json({ success: true });
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
