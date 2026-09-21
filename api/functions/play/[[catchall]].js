export async function onRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const workerBase = env.WORKER_BASE || "https://nibbu.arabba.workers.dev";

    const catchall = params.catchall;
    let streamId = "";
    if (Array.isArray(catchall) && catchall.length > 0) {
        streamId = catchall.join('/');
    } else if (typeof catchall === "string") {
        streamId = catchall;
    }

    // Build target URL on worker with ?id=<streamId>
    const searchParams = new URLSearchParams(url.search);
    if (streamId && !searchParams.has("id")) {
        searchParams.set("id", streamId);
    }
    const targetUrl = `${workerBase}/?${searchParams.toString()}`;

    const reqHeaders = new Headers(request.headers);
    reqHeaders.set("User-Agent", request.headers.get("User-Agent") || "Cloudflare-Worker");
    reqHeaders.delete("Host");

    const reqOptions = {
        method: request.method,
        headers: reqHeaders,
        redirect: "manual"
    };

    if (request.method === "POST" || request.method === "PUT" || request.method === "PATCH") {
        reqOptions.body = await request.arrayBuffer();
    }

    try {
        const response = await fetch(targetUrl, reqOptions);
        const resHeaders = new Headers(response.headers);
        resHeaders.set("Access-Control-Allow-Origin", "*");
        resHeaders.set("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS");
        resHeaders.set("Access-Control-Allow-Headers", "*");

        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: resHeaders
        });
    } catch (err) {
        return new Response(JSON.stringify({ error: "Play proxy failed", detail: err.message }), {
            status: 502,
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
    }
}
