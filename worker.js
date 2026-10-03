import { SignJWT, importPKCS8 } from "jose";

const PROJECT_ID = "dynopay-2513c";

const API_KEY =
  "AIzaSyBRSkmZXbTPNupefSmjXvlKLDNsaeQ2zag";

const DATABASE_URL =
  "https://dynopay-2513c-default-rtdb.asia-southeast1.firebasedatabase.app";

const IDENTITY_LOOKUP =
  `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${API_KEY}`;

const AUTH_UPDATE =
  `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT_ID}/accounts:update`;

const GOOGLE_SCOPE =
  "https://www.googleapis.com/auth/cloud-platform";

export default {
  async fetch(request, env) {

    const corsHeaders = {
      "Access-Control-Allow-Origin": "https://dynotic.web.id",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Content-Type": "application/json"
    };

    // ==============================
    // CORS
    // ==============================

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    // ==============================
    // ONLY POST
    // ==============================

    if (request.method !== "POST") {
      return json({
        success: false,
        error: "Method Not Allowed"
      }, 405, corsHeaders);
    }

    try {

      // ==============================
      // 1. GET ADMIN ID TOKEN
      // ==============================

      const authorization =
        request.headers.get("Authorization") || "";

      if (!authorization.startsWith("Bearer ")) {
        return json({
          success: false,
          error: "Authorization token tidak ditemukan."
        }, 401, corsHeaders);
      }

      const adminIdToken =
        authorization.substring(7).trim();

      if (!adminIdToken) {
        return json({
          success: false,
          error: "Token admin kosong."
        }, 401, corsHeaders);
      }


      // ==============================
      // 2. VALIDATE ADMIN TOKEN
      // ==============================

      const lookupResponse = await fetch(
        IDENTITY_LOOKUP,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            idToken: adminIdToken
          })
        }
      );

      const lookupData =
        await lookupResponse.json();

      if (
        !lookupResponse.ok ||
        !lookupData.users ||
        !lookupData.users.length
      ) {
        return json({
          success: false,
          error: "Token admin tidak valid atau sudah expired."
        }, 401, corsHeaders);
      }

      const adminUid =
        lookupData.users[0].localId;


      // ==============================
      // 3. SERVICE ACCOUNT
      // ==============================

      if (!env.FIREBASE_SERVICE_ACCOUNT) {
        return json({
          success: false,
          error: "FIREBASE_SERVICE_ACCOUNT tidak ditemukan."
        }, 500, corsHeaders);
      }

      const serviceAccount =
        JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);

      const accessToken =
        await getAccessToken(serviceAccount);


      // ==============================
      // 4. CHECK ADMIN DATABASE
      // ==============================

      const adminCheckResponse =
  await fetch(
    `${DATABASE_URL}/admins/${encodeURIComponent(adminUid)}.json`,
    {
      method: "GET",
      headers: {
        Authorization:
          `Bearer ${adminIdToken}`
      }
    }
  );

      if (!adminCheckResponse.ok) {

  const errorText =
    await adminCheckResponse.text();

  console.error(
    "Admin check failed:",
    adminCheckResponse.status,
    errorText
  );

  return json({
    success: false,
    error: "Gagal memeriksa status admin.",
    status: adminCheckResponse.status,
    detail: errorText
  }, 500, corsHeaders);
      }

      const adminData =
        await adminCheckResponse.json();

      if (adminData === null) {
        return json({
          success: false,
          error: "Akses ditolak. Akun ini bukan admin."
        }, 403, corsHeaders);
      }


      // ==============================
      // 5. READ REQUEST BODY
      // ==============================

      const body =
        await request.json();

      const uid =
        String(body.uid || "").trim();

      const newEmail =
        String(body.newEmail || "")
          .trim()
          .toLowerCase();


      if (!uid || !newEmail) {
        return json({
          success: false,
          error: "UID dan email baru wajib diisi."
        }, 400, corsHeaders);
      }


      // ==============================
      // 6. VALIDATE EMAIL
      // ==============================

      const emailRegex =
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

      if (!emailRegex.test(newEmail)) {
        return json({
          success: false,
          error: "Format email tidak valid."
        }, 400, corsHeaders);
      }


      // ==============================
      // 7. CHECK USER IN RTDB
      // ==============================

      const userCheckResponse =
        await fetch(
          `${DATABASE_URL}/users/${encodeURIComponent(uid)}.json`,
          {
            method: "GET",
            headers: {
              Authorization:
                `Bearer ${accessToken}`
            }
          }
        );

      if (!userCheckResponse.ok) {
        return json({
          success: false,
          error: "Gagal memeriksa data user."
        }, 500, corsHeaders);
      }

      const userData =
        await userCheckResponse.json();

      if (userData === null) {
        return json({
          success: false,
          error: "User tidak ditemukan di database."
        }, 404, corsHeaders);
      }


      // ==============================
      // 8. UPDATE FIREBASE AUTH
      // ==============================

      const updateResponse =
        await fetch(
          AUTH_UPDATE,
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/json",

              Authorization:
                `Bearer ${accessToken}`
            },

            body: JSON.stringify({
              localId: uid,
              email: newEmail,
              emailVerified: false,
              targetProjectId: PROJECT_ID
            })
          }
        );


      const updateData =
        await updateResponse.json();


      if (!updateResponse.ok) {

        console.error(
          "Firebase Auth update error:",
          updateData
        );

        return json({
          success: false,
          error:
            updateData?.error?.message ||
            "Gagal mengubah email Firebase Auth."
        }, updateResponse.status, corsHeaders);
      }


      // ==============================
      // 9. UPDATE EMAIL DI RTDB
      // ==============================

      const rtdbUpdateResponse =
        await fetch(
          `${DATABASE_URL}/users/${encodeURIComponent(uid)}/email.json`,
          {
            method: "PUT",

            headers: {
              Authorization:
                `Bearer ${accessToken}`,

              "Content-Type":
                "application/json"
            },

            body:
              JSON.stringify(newEmail)
          }
        );


      if (!rtdbUpdateResponse.ok) {

        console.error(
          "RTDB email update failed:",
          await rtdbUpdateResponse.text()
        );

        return json({
          success: true,

          warning:
            "Email Firebase Auth berhasil diubah, tetapi email di database users gagal diperbarui.",

          uid,
          email: newEmail

        }, 200, corsHeaders);
      }


      // ==============================
      // 10. SUCCESS
      // ==============================

      return json({

        success: true,

        message:
          "Email user berhasil diperbarui.",

        uid,

        email: newEmail

      }, 200, corsHeaders);


    } catch (error) {

      console.error(
        "Worker error:",
        error
      );

      return json({

        success: false,

        error:
          error?.message ||
          "Terjadi kesalahan pada server."

      }, 500, corsHeaders);
    }
  }
};


// ==========================================
// CREATE GOOGLE OAUTH ACCESS TOKEN
// ==========================================

async function getAccessToken(serviceAccount) {

  const now =
    Math.floor(Date.now() / 1000);


  const privateKey =
    await importPKCS8(
      serviceAccount.private_key,
      "RS256"
    );


  const jwt =
    await new SignJWT({

      scope:
        GOOGLE_SCOPE

    })

      .setProtectedHeader({

        alg: "RS256",
        typ: "JWT"

      })

      .setIssuer(
        serviceAccount.client_email
      )

      .setSubject(
        serviceAccount.client_email
      )

      .setAudience(
        serviceAccount.token_uri
      )

      .setIssuedAt(now)

      .setExpirationTime(
        now + 3600
      )

      .sign(privateKey);


  const response =
    await fetch(
      serviceAccount.token_uri,
      {

        method: "POST",

        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },

        body:
          new URLSearchParams({

            grant_type:
              "urn:ietf:params:oauth:grant-type:jwt-bearer",

            assertion:
              jwt

          })

      }
    );


  const data =
    await response.json();


  if (!response.ok) {

    throw new Error(
      data.error_description ||
      data.error ||
      "Gagal mendapatkan Google access token."
    );

  }


  return data.access_token;
}


// ==========================================
// JSON RESPONSE
// ==========================================

function json(
  data,
  status,
  corsHeaders
) {

  return new Response(

    JSON.stringify(data),

    {
      status,

      headers:
        corsHeaders
    }

  );
}
