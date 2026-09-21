export async function onRequest(context) {
    const { request, env } = context;

    // The sonyproxy.js worker is deployed at sony.rabba.workers.dev
    const sonyBase = env.SONY_WORKER_URL || "https://sony.rabba.workers.dev";
    const workerUrl = `${sonyBase}/?action=api&password=match_valverdeae`;
    
    try {
        const response = await fetch(workerUrl, {
            headers: { 
                "User-Agent": "Cloudflare-Worker",
                "Origin": "https://nibbu.pages.dev"
            }
        });

        if (!response.ok) {
            const errorText = await response.text();
            return new Response(JSON.stringify({ 
                error: `Backend returned status ${response.status}`,
                detail: errorText,
                status: response.status
            }), { status: response.status, headers: { "Content-Type": "application/json" } });
        }

        const data = await response.json();

        return new Response(JSON.stringify(data, null, 2), {
            headers: { 
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            }
        });

    } catch (err) {
        return new Response(JSON.stringify({ error: "Internal error fetching sony links", detail: err.message }), { 
            status: 500,
            headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            }
        });
    }
}
