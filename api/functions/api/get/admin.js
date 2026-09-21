export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const base = env.WORKER_BASE || env.WORKER_ADMIN_URL || "https://nibbu.arabba.workers.dev";
    const workerAdminUrl = `${base.replace(/\/$/, "")}/api/get/admin${url.search}`;

    const reqHeaders = new Headers(request.headers);
    reqHeaders.set("User-Agent", request.headers.get("User-Agent") || "Cloudflare-Worker");
    reqHeaders.delete("Host"); // Critical for cross-domain fetch in Cloudflare

    const reqOptions = {
        method: request.method,
        headers: reqHeaders,
        redirect: "manual"
    };

    if (request.method === "POST" || request.method === "PUT" || request.method === "PATCH") {
        reqOptions.body = await request.arrayBuffer();
    }

    try {
        const response = await fetch(workerAdminUrl, reqOptions);
        const resHeaders = new Headers(response.headers);
        resHeaders.set("Access-Control-Allow-Origin", "*");
        resHeaders.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        resHeaders.set("Access-Control-Allow-Headers", "*");

        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: resHeaders
        });
    } catch (err) {
        return new Response(JSON.stringify({ error: "Admin proxy error", detail: err.message }), {
            status: 502,
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
    }
}
