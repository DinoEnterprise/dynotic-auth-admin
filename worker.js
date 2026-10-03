export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Content-Type": "application/json",
    };

    // Tes apakah Worker bisa membaca Secret
    if (request.method === "GET") {
      return new Response(
        JSON.stringify({
          success: true,
          worker: "online",
          firebaseSecret: !!env.FIREBASE_SERVICE_ACCOUNT,
          message: env.FIREBASE_SERVICE_ACCOUNT
            ? "Firebase Secret terbaca oleh Worker."
            : "Firebase Secret TIDAK ditemukan."
        }),
        {
          status: 200,
          headers: corsHeaders,
        }
      );
    }

    return new Response(
      JSON.stringify({
        success: false,
        error: "Method Not Allowed"
      }),
      {
        status: 405,
        headers: corsHeaders,
      }
    );
  },
};
