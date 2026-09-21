export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const workerBase = env.WORKER_BASE || "https://nibbu.arabba.workers.dev";

    const targetUrl = new URL(url.pathname + url.search, workerBase);

    if (request.method === "OPTIONS") {
        return new Response(null, {
            status: 204,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS, DELETE",
                "Access-Control-Allow-Headers": "*",
            }
        });
    }

    const reqHeaders = new Headers(request.headers);
    reqHeaders.set("User-Agent", request.headers.get("User-Agent") || "Cloudflare-Worker");
    reqHeaders.delete("Host");

    const reqOptions = {
        method: request.method,
        headers: reqHeaders,
        redirect: "manual"
    };

    if (request.method === "POST" || request.method === "PUT" || request.method === "PATCH" || request.method === "DELETE") {
        reqOptions.body = await request.arrayBuffer();
    }

    try {
        const response = await fetch(targetUrl.toString(), reqOptions);
        const resHeaders = new Headers(response.headers);
        resHeaders.set("Access-Control-Allow-Origin", "*");
        resHeaders.set("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS, DELETE");
        resHeaders.set("Access-Control-Allow-Headers", "*");

        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: resHeaders
        });
    } catch (err) {
        return new Response(JSON.stringify({ error: "API proxy failed", detail: err.message }), {
            status: 502,
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
    }
}
