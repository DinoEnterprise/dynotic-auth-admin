export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
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

      if (!newEmail.includes("@")) {
        return json(
          {
            success: false,
            error: "Format email tidak valid.",
          },
          400,
          corsHeaders
        );
      }

      /*
       * Untuk sementara endpoint ini belum melakukan
       * perubahan Firebase.
       *
       * Kita tes koneksi Worker terlebih dahulu.
       */

      return json(
        {
          success: true,
          message: "Worker aktif.",
          uid,
          newEmail,
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

function json(data, status, corsHeaders) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders,
    },
  });
}
