// functions/api/login.js
// Cloudflare Pages Function — asli login verify karke Firebase Custom Token deta hai.
// Isse database rules ab auth.uid / auth.token.role check kar sakte hain (real security).

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" },
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
    scope: "https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/identitytoolkit",
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

async function mintCustomToken(env, uid, claims) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: env.FIREBASE_CLIENT_EMAIL,
    sub: env.FIREBASE_CLIENT_EMAIL,
    aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
    iat: now,
    exp: now + 3600,
    uid,
    claims,
  };
  return signJWT(header, payload, env.FIREBASE_PRIVATE_KEY);
}

// ✅ Custom claims ko PERMANENTLY us Firebase Auth account pe save karta hai
// (sirf ek baar ke token mein daalne se Firebase kabhi silent refresh ke
// baad claims gira deta hai — isse role hamesha ke liye persist ho jaata hai).
async function persistCustomClaims(env, accessToken, uid, claims) {
  const body = JSON.stringify({ localId: uid, customAttributes: JSON.stringify(claims) });
  let resp = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:update", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + accessToken },
    body,
  });
  if (resp.ok) return;

  // Pehli baar login: Firebase Auth account abhi tak exist nahi karta —
  // usko banao (localId fix karke), phir claims set ho jayenge saath hi.
  const errText = await resp.text().catch(() => "");
  if (errText.includes("USER_NOT_FOUND") || resp.status === 400) {
    const signUpResp = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:signUp", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + accessToken },
      body,
    });
    if (signUpResp.ok) return;
    const signUpErr = await signUpResp.text().catch(() => "");
    throw new Error("Custom claims create fail: " + signUpResp.status + " " + signUpErr);
  }

  throw new Error("Custom claims save fail: " + resp.status + " " + errText);
}

async function dbFetch(env, path, accessToken, extraQuery = "") {
  const url = `https://${env.FIREBASE_PROJECT_ID}-default-rtdb.firebaseio.com/${path}.json?access_token=${accessToken}${extraQuery}`;
  const resp = await fetch(url);
  return resp.json();
}

async function sha256Hex(str) {
  const data = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Same password check logic as the existing frontend (SHA-256 + per-user salt,
// with a fallback for old pre-migration accounts).
async function checkPassword(record, password) {
  if (record.passwordSalt) {
    const hash = await sha256Hex(password + "::" + record.passwordSalt);
    return hash === record.password;
  }
  const legacyHash = await sha256Hex(password + "jsk_salt_2024");
  return record.password === legacyHash || record.password === password;
}

export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    const body = await request.json();
    const { id, password, role } = body || {};

    if (!id || !password || !role) {
      return json({ error: "id, password aur role zaroori hain" }, 400);
    }
    if (!["user", "staff", "admin"].includes(role)) {
      return json({ error: "Invalid role" }, 400);
    }

    const accessToken = await getGoogleAccessToken(env);

    let record = null;
    let uid = null;
    let claims = {};

    if (role === "admin") {
      record = await dbFetch(env, "admin/creds", accessToken);
      if (!record) return json({ error: "Admin account nahi mila" }, 401);
      if ((record.gmail || "").toLowerCase() !== String(id).trim().toLowerCase()) {
        return json({ error: "ID ya password galat hai" }, 401);
      }
      uid = "admin";
      claims = { role: "admin" };
    } else if (role === "staff") {
      record = await dbFetch(env, `staff/${encodeURIComponent(id)}`, accessToken);
      if (!record) return json({ error: "Staff account nahi mila" }, 401);
      if ((record.status || "active") !== "active") {
        return json({ error: "Aapka access band kar diya gaya hai. Admin se sampark karen." }, 403);
      }
      uid = String(id);
      claims = { role: "staff", staffId: String(id) };
    } else {
      // role === "user" — try match by userId, then by mobile
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
      if (!key) return json({ error: "User account nahi mila" }, 401);
      record = data[key];
      uid = key;
      claims = { role: "user", userId: record.userId || key };
    }

    const passOk = await checkPassword(record, password);
    if (!passOk) {
      return json({ error: "ID ya password galat hai" }, 401);
    }

    // Custom claims ko account pe permanently save karo, taaki Firebase ke
    // silent token-refresh ke baad bhi role/permissions bani rahein.
    let claimsPersisted = true;
    let claimsWarning = null;
    try {
      await persistCustomClaims(env, accessToken, uid, claims);
    } catch (persistErr) {
      // Non-fatal: login abhi bhi chalne do (is baar ke session ke liye
      // token mein claims already honge), lekin ab ye warning response mein
      // bhi bhej rahe hain taaki frontend/console pe dikhe — pehle ye sirf
      // server ke background mein chup-chaap log hota tha, kabhi pata nahi
      // chalta tha ki role permanently save nahi ho paya.
      claimsPersisted = false;
      claimsWarning = persistErr.message;
      console.warn("persistCustomClaims warning:", persistErr.message);
    }

    const customToken = await mintCustomToken(env, uid, claims);
    return json({ token: customToken, uid, role: claims.role, claimsPersisted, claimsWarning });
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
