export async function onRequest(context) {
    const { request, env } = context;
    
    // Block direct browsing
    const fetchMode = request.headers.get("Sec-Fetch-Mode");
    const fetchDest = request.headers.get("Sec-Fetch-Dest");
    if (fetchMode === "navigate" || fetchDest === "document") {
        return new Response(JSON.stringify({ error: "403 Forbidden - Direct browsing is not allowed" }), { status: 403 });
    }

    const url = new URL(request.url);
    const channelId = url.searchParams.get("id");

    if (!channelId) {
        return new Response(JSON.stringify({ error: "Missing channel ID" }), { status: 400 });
    }

    const viewerIp = request.headers.get('CF-Connecting-IP') || 'unknown';
    const secretKey = env.SECRET_KEY || 'xQ#9vL2$pM8@kR4*jT6!nW7^yC3(hF1&';
    const encryptionKeyStr = env.ENCRYPTION_KEY || 'wD@4jB9!vN2$xP7*kM5^qL8#cT3(hF1&';
    const workerDomain = env.WORKER_DOMAIN || 'ziotv.movieszonemedia.workers.dev';

    try {
        // Generate HMAC token directly — no need to fetch all channels!
        const timeBlock = Math.floor(Date.now() / (1000 * 60 * 60 * 24));
        const dataToSign = `${workerDomain}|${timeBlock}|${channelId}|${viewerIp}`;

        const encoder = new TextEncoder();
        const hmacKey = await crypto.subtle.importKey(
            "raw", encoder.encode(secretKey),
            { name: "HMAC", hash: "SHA-256" },
            false, ["sign"]
        );
        const signature = await crypto.subtle.sign("HMAC", hmacKey, encoder.encode(dataToSign));
        const token = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');

        // Encrypt the id+token payload
        const payload = JSON.stringify({ i: channelId, t: token });

        const cryptoKey = await crypto.subtle.importKey(
            "raw", encoder.encode(encryptionKeyStr),
            { name: "AES-GCM" },
            false, ["encrypt"]
        );

        const encIv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedPayloadBuf = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: encIv },
            cryptoKey,
            encoder.encode(payload)
        );

        const encBytes = new Uint8Array(encryptedPayloadBuf);
        const combined = new Uint8Array(encIv.length + encBytes.length);
        combined.set(encIv, 0);
        combined.set(encBytes, encIv.length);
        
        const binaryString = Array.from(combined).map(b => String.fromCharCode(b)).join('');
        const base64Payload = btoa(binaryString)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');

        const finalUrl = `https://${workerDomain}/?e=${base64Payload}`;

        return new Response(JSON.stringify({ url: finalUrl }), {
            headers: { "Content-Type": "application/json" }
        });

    } catch (err) {
        const errorDetails = err ? (err.stack || err.toString() || JSON.stringify(err)) : "Unknown Error";
        return new Response(JSON.stringify({ 
            error: "Token generation failed", 
            detail: errorDetails 
        }), { status: 500 });
    }
}

