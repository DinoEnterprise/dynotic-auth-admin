import { SignJWT, importPKCS8 } from "jose";

const FIREBASE_SCOPE =
  "https://www.googleapis.com/auth/identitytoolkit";

const FIREBASE_API =
  "https://identitytoolkit.googleapis.com/v1/projects/dynopay-2513c/accounts:update";

export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders,
      });
    }

    if (request.method !== "POST") {
      return json(
        {
          success: false,
          error: "Method Not Allowed",
        },
        405,
        corsHeaders
      );
    }

    try {
      const body = await request.json();

      const uid = String(body.uid || "").trim();
      const newEmail = String(body.newEmail || "").trim().toLowerCase();

      if (!uid || !newEmail) {
        return json(
          {
            success: false,
            error: "UID dan email baru wajib diisi.",
          },
          400,
          corsHeaders
        );
      }

      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) {
        return json(
          {
            success: false,
            error: "Format email tidak valid.",
          },
          400,
          corsHeaders
        );
      }

      const serviceAccount = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);

      const accessToken = await getAccessToken(serviceAccount);

      const firebaseResponse = await fetch(FIREBASE_API, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          localId: uid,
          email: newEmail,
          emailVerified: false,
          targetProjectId: "dynopay-2513c",
        }),
      });

      const result = await firebaseResponse.json();

      if (!firebaseResponse.ok) {
        return json(
          {
            success: false,
            error: result.error?.message || "Firebase Auth gagal diperbarui.",
          },
          firebaseResponse.status,
          corsHeaders
        );
      }

      return json(
        {
          success: true,
          message: "Email akun berhasil diperbarui.",
          uid,
          email: result.email || newEmail,
        },
        200,
        corsHeaders
      );
    } catch (error) {
      return json(
        {
          success: false,
          error: error.message || "Terjadi kesalahan.",
        },
        500,
        corsHeaders
      );
    }
  },
};

async function getAccessToken(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);

  const privateKey = await importPKCS8(
    serviceAccount.private_key,
    "RS256"
  );

  const jwt = await new SignJWT({
    scope: FIREBASE_SCOPE,
  })
    .setProtectedHeader({
      alg: "RS256",
      typ: "JWT",
    })
    .setIssuer(serviceAccount.client_email)
    .setSubject(serviceAccount.client_email)
    .setAudience(serviceAccount.token_uri)
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(privateKey);

  const response = await fetch(serviceAccount.token_uri, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.error_description || data.error || "Gagal mendapatkan access token."
    );
  }

  return data.access_token;
}

function json(data, status, corsHeaders) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders,
    },
  });
}
