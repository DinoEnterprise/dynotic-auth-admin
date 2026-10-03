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

    // =========================
    // CORS PREFLIGHT
    // =========================

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    // =========================
    // ONLY POST
    // =========================

    if (request.method !== "POST") {
      return json({
        success: false,
        error: "Method Not Allowed"
      }, 405, corsHeaders);
    }

    try {

      // =========================
      // AMBIL AUTHORIZATION HEADER
      // =========================

      const authorization =
        request.headers.get("Authorization") || "";

      if (!authorization.startsWith("Bearer ")) {
        return json({
          success: false,
          error:
            "Authorization token tidak ditemukan."
        }, 401, corsHeaders);
      }

      const adminIdToken =
        authorization.substring(7).trim();

      if (!adminIdToken) {
        return json({
          success: false,
          error:
            "Token admin kosong."
        }, 401, corsHeaders);
      }

      // =========================
      // VALIDASI FIREBASE ID TOKEN
      // =========================

      const lookupResponse =
        await fetch(
          IDENTITY_LOOKUP,
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/json"
            },

            body: JSON.stringify({
              idToken:
                adminIdToken
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

        console.error(
          "Admin token validation failed:",
          lookupResponse.status,
          lookupData
        );

        return json({
          success: false,
          error:
            "Token admin tidak valid atau sudah expired."
        }, 401, corsHeaders);
      }

      const adminUid =
        lookupData.users[0].localId;

      // =========================
      // CEK SERVICE ACCOUNT SECRET
      // =========================

      if (!env.FIREBASE_SERVICE_ACCOUNT) {
        return json({
          success: false,
          error:
            "FIREBASE_SERVICE_ACCOUNT tidak ditemukan."
        }, 500, corsHeaders);
      }

      let serviceAccount;

      try {

        serviceAccount =
          JSON.parse(
            env.FIREBASE_SERVICE_ACCOUNT
          );

      } catch (error) {

        console.error(
          "Service account JSON error:",
          error
        );

        return json({
          success: false,
          error:
            "FIREBASE_SERVICE_ACCOUNT bukan JSON yang valid."
        }, 500, corsHeaders);
      }

      // =========================
      // AMBIL GOOGLE ACCESS TOKEN
      // =========================
      //
      // Token ini dipakai untuk:
      // 1. Cek admins/{adminUid}
      // 2. Cek users/{uid}
      // 3. Update Firebase Auth
      // 4. Update email di RTDB
      //
      // =========================

      const accessToken =
        await getAccessToken(
          serviceAccount
        );

      // =========================
      // CEK DATA ADMIN
      // MENGGUNAKAN SERVICE ACCOUNT
      // =========================

      const adminCheckResponse =
        await fetch(
          `${DATABASE_URL}/admins/${encodeURIComponent(adminUid)}.json`,
          {
            method: "GET",

            headers: {
              Authorization:
                `Bearer ${accessToken}`
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

          error:
            "Gagal memeriksa status admin.",

          status:
            adminCheckResponse.status,

          detail:
            errorText

        }, 500, corsHeaders);
      }

      const adminData =
        await adminCheckResponse.json();

      // =========================
      // USER BUKAN ADMIN
      // =========================

      if (adminData === null) {

        console.warn(
          "Access denied. UID bukan admin:",
          adminUid
        );

        return json({
          success: false,

          error:
            "Akses ditolak. Akun ini bukan admin."

        }, 403, corsHeaders);
      }

      // =========================
      // BACA REQUEST BODY
      // =========================

      let body;

      try {

        body =
          await request.json();

      } catch (error) {

        return json({
          success: false,

          error:
            "Body request bukan JSON yang valid."

        }, 400, corsHeaders);
      }

      // =========================
      // AMBIL UID TARGET
      // =========================

      const uid =
        String(
          body.uid || ""
        ).trim();

      // =========================
      // AMBIL EMAIL BARU
      // =========================

      const newEmail =
        String(
          body.newEmail || ""
        )
          .trim()
          .toLowerCase();

      // =========================
      // VALIDASI INPUT
      // =========================

      if (!uid || !newEmail) {

        return json({
          success: false,

          error:
            "UID dan email baru wajib diisi."

        }, 400, corsHeaders);
      }

      // =========================
      // VALIDASI FORMAT EMAIL
      // =========================

      const emailRegex =
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

      if (!emailRegex.test(newEmail)) {

        return json({
          success: false,

          error:
            "Format email tidak valid."

        }, 400, corsHeaders);
      }

      // =========================
      // CEK USER DI RTDB
      // =========================

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

        const errorText =
          await userCheckResponse.text();

        console.error(
          "User check failed:",
          userCheckResponse.status,
          errorText
        );

        return json({
          success: false,

          error:
            "Gagal memeriksa data user.",

          status:
            userCheckResponse.status,

          detail:
            errorText

        }, 500, corsHeaders);
      }

      const userData =
        await userCheckResponse.json();

      // =========================
      // USER TIDAK DITEMUKAN
      // =========================

      if (userData === null) {

        return json({
          success: false,

          error:
            "User tidak ditemukan di database."

        }, 404, corsHeaders);
      }

      // =========================
      // UPDATE EMAIL FIREBASE AUTH
      // =========================

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

              localId:
                uid,

              email:
                newEmail,

              emailVerified:
                false,

              targetProjectId:
                PROJECT_ID

            })
          }
        );

      const updateData =
        await updateResponse.json();

      // =========================
      // AUTH UPDATE GAGAL
      // =========================

      if (!updateResponse.ok) {

        console.error(
          "Firebase Auth update error:",
          updateResponse.status,
          updateData
        );

        return json({
          success: false,

          error:
            updateData?.error?.message ||
            "Gagal mengubah email Firebase Auth.",

          status:
            updateResponse.status,

          detail:
            updateData

        }, updateResponse.status, corsHeaders);
      }

      // =========================
      // UPDATE EMAIL DI RTDB
      // =========================

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
              JSON.stringify(
                newEmail
              )
          }
        );

      // =========================
      // RTDB UPDATE GAGAL
      // =========================

      if (!rtdbUpdateResponse.ok) {

        const errorText =
          await rtdbUpdateResponse.text();

        console.error(
          "RTDB email update failed:",
          rtdbUpdateResponse.status,
          errorText
        );

        return json({

          success: true,

          warning:
            "Email Firebase Auth berhasil diubah, tetapi email di database users gagal diperbarui.",

          uid:
            uid,

          email:
            newEmail,

          rtdbStatus:
            rtdbUpdateResponse.status,

          rtdbDetail:
            errorText

        }, 200, corsHeaders);
      }

      // =========================
      // BERHASIL
      // =========================

      return json({

        success: true,

        message:
          "Email user berhasil diperbarui.",

        uid:
          uid,

        email:
          newEmail

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


// ======================================
// GOOGLE SERVICE ACCOUNT ACCESS TOKEN
// ======================================

async function getAccessToken(
  serviceAccount
) {

  const now =
    Math.floor(
      Date.now() / 1000
    );

  // =========================
  // VALIDASI SERVICE ACCOUNT
  // =========================

  if (
    !serviceAccount.private_key ||
    !serviceAccount.client_email ||
    !serviceAccount.token_uri
  ) {

    throw new Error(
      "Data service account tidak lengkap."
    );
  }

  // =========================
  // IMPORT PRIVATE KEY
  // =========================

  const privateKey =
    await importPKCS8(
      serviceAccount.private_key,
      "RS256"
    );

  // =========================
  // BUAT JWT
  // =========================

  const jwt =
    await new SignJWT({

      scope:
        GOOGLE_SCOPE

    })

      .setProtectedHeader({

        alg:
          "RS256",

        typ:
          "JWT"

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

      .setIssuedAt(
        now
      )

      .setExpirationTime(
        now + 3600
      )

      .sign(
        privateKey
      );

  // =========================
  // REQUEST GOOGLE ACCESS TOKEN
  // =========================

  const response =
    await fetch(
      serviceAccount.token_uri,
      {

        method:
          "POST",

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

  // =========================
  // TOKEN GAGAL
  // =========================

  if (!response.ok) {

    console.error(
      "Google access token error:",
      response.status,
      data
    );

    throw new Error(

      data.error_description ||
      data.error ||
      "Gagal mendapatkan Google access token."

    );
  }

  // =========================
  // TOKEN BERHASIL
  // =========================

  return data.access_token;
}


// ======================================
// JSON RESPONSE HELPER
// ======================================

function json(
  data,
  status,
  corsHeaders
) {

  return new Response(

    JSON.stringify(data),

    {
      status:
        status,

      headers:
        corsHeaders
    }

  );
}
