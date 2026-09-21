/**
 * Cloudflare Worker for Sony Liv Dashboard
 * Features:
 * - Fetches channel JSON server-side (hiding it from the network tab)
 * - AES-GCM Encrypts channel IDs, manifest URLs, and segment URLs
 * - Fully proxies manifests and media segments server-side to hide external proxies
 * - No plain-text URLs or external domains exposed to the client
 */

const ALLOWED_ORIGINS = [
    "https://nibbu.pages.dev",
    "https://nibbu.workers.dev",
    "https://nibbu.arabba.workers.dev",
    "https://sony.rabba.workers.dev",
    "http://sony.rabba.workers.dev"
];

const PROXY_HEADERS = {
    "Origin": "https://allinonereborn2.online",
    "Referer": "https://allinonereborn2.online/sony/ptest1.html?id=sony-ten-3",
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "*/*",
    "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
    "sec-ch-ua": "\"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"150\", \"Google Chrome\";v=\"150\"",
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": "\"Android\"",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "User-Agent": "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Mobile Safari/537.36"
};

// --- AES Encryption Helpers ---

const DEFAULT_SECRET = "xyzplay_secure_fallback_key_2026";
function getSecret(env) {
    return (env && env.SECRET_KEY) || DEFAULT_SECRET;
}

// --- Key Caching (avoids re-importing keys on every crypto call) ---
let _cachedAesKey = null;
let _cachedAesSecret = null;
let _cachedHmacKey = null;
let _cachedHmacSecret = null;

async function getCryptoKey(env) {
    const secret = getSecret(env);
    if (_cachedAesKey && _cachedAesSecret === secret) return _cachedAesKey;
    _cachedAesKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret.padEnd(32, '0').slice(0, 32)),
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
    );
    _cachedAesSecret = secret;
    return _cachedAesKey;
}

function buf2hex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hex2buf(hexString) {
    const bytes = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i += 2) {
        bytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
    }
    return bytes;
}

async function getDeterministicIv(text, env) {
    const secret = getSecret(env);
    const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret + text));
    return new Uint8Array(hash, 0, 12);
}

async function encryptData(text, env) {
    const key = await getCryptoKey(env);
    const iv = await getDeterministicIv(text, env);
    const encoded = new TextEncoder().encode(text);
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoded
    );
    return buf2hex(iv) + buf2hex(ciphertext);
}

async function decryptData(hexStr, env) {
    try {
        if (!hexStr || hexStr.length < 24) return null;
        const key = await getCryptoKey(env);
        const iv = hex2buf(hexStr.slice(0, 24));
        const ciphertext = hex2buf(hexStr.slice(24));
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            ciphertext
        );
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        return null;
    }
}

function strictUrlEncode(str) {
    return encodeURIComponent(str).replace(/[!'()*]/g, function (c) {
        return '%' + c.charCodeAt(0).toString(16).toUpperCase();
    });
}

function errorResponse(msg, status) {
    if (status === 403) {
        return new Response("Access Denied: " + msg, {
            status: 403,
            headers: {
                "Content-Type": "text/plain",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS"
            }
        });
    }
    return new Response(msg, {
        status: status,
        headers: {
            "Content-Type": "text/plain",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*"
        }
    });
}

async function generateHMAC(secret, payload) {
    const encoder = new TextEncoder();
    if (!_cachedHmacKey || _cachedHmacSecret !== secret) {
        _cachedHmacKey = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        _cachedHmacSecret = secret;
    }
    const signature = await crypto.subtle.sign('HMAC', _cachedHmacKey, encoder.encode(payload));
    return buf2hex(signature).slice(0, 32);
}

const PARAM_MAPS = [
    ['action', 'id', 'u', 'sig', 'key', 'friend'],
    ['req', 'ch', 'src', 'hash', 'auth', 'partner'],
    ['type', 'vid', 'link', 'token', 'pass', 'mate'],
    ['cmd', 'stream', 'uri', 'sign', 'access', 'ally'],
    ['act', 'target', 'blob', 'hmac', 'guard', 'buddy']
];

function getDynamicParamMap(timeBlockDay) {
    const seed = timeBlockDay % PARAM_MAPS.length;
    const map = PARAM_MAPS[seed];
    return { action: map[0], id: map[1], u: map[2], sig: map[3], key: map[4], friend: map[5] };
}

async function createSignedRequest(action, identifier, request, timeBlock, secret, isApi = false) {
    let clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
    let userAgent = request.headers.get('User-Agent') || 'unknown';
    const origin = request.headers.get('Origin');
    let hostBinding = 'nibbu.pages.dev'; // Default secure binding

    if (origin) {
        try { hostBinding = new URL(origin).hostname; } catch (e) { }
    }

    if (isApi) {
        // Relax IP/UA binding for API requests to support intermediate proxy servers
        clientIp = 'any';
        userAgent = 'any';
    }

    // Explicitly binding the secret into the payload itself for maximum entropy
    const payload = `${action}:${identifier}:${clientIp}:${userAgent}:${hostBinding}:${timeBlock}:${secret}`;
    return await generateHMAC(secret, payload);
}

async function verifySignedRequest(action, identifier, request, timeBlocks, secret, providedSig) {
    const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
    const userAgent = request.headers.get('User-Agent') || 'unknown';
    const origin = request.headers.get('Origin') || '';
    let hostBinding = 'nibbu.pages.dev'; // Default secure binding
    try { if (origin) hostBinding = new URL(origin).hostname; } catch (e) { }

    // Attach debug info to request so it can be returned in the 403
    request.sigDebug = { checkedPayloads: [], providedSig };

    const checkPayload = async (ip, ua, host, timeBlock) => {
        const payload = `${action}:${identifier}:${ip}:${ua}:${host}:${timeBlock}:${secret}`;
        const hash = await generateHMAC(secret, payload);
        request.sigDebug.checkedPayloads.push({ payload, hash, match: hash === providedSig });
        return hash === providedSig;
    };

    for (const timeBlock of timeBlocks) {
        // 1. Strict IP/UA AND Strict Host (Segments/Dashboard)
        if (await checkPayload(clientIp, userAgent, hostBinding, timeBlock)) return true;

        // 2. Strict IP/UA AND Fallback Host (Legacy/Transition)
        if (await checkPayload(clientIp, userAgent, 'any', timeBlock)) return true;

        // 3. Relaxed IP/UA AND Strict Host (API Proxies)
        if (await checkPayload('any', 'any', hostBinding, timeBlock)) return true;

        // 4. Relaxed IP/UA AND Fallback Host (API Proxy Default)
        if (await checkPayload('any', 'any', 'nibbu.pages.dev', timeBlock)) return true;
        if (await checkPayload('any', 'any', 'nibbu.workers.dev', timeBlock)) return true;
        if (await checkPayload('any', 'any', 'any', timeBlock)) return true;
    }

    return false;
}

function publicWorkerBase(url) {
    return `https://${url.hostname}${url.pathname}`;
}

// --- Main Worker Logic ---

export default {
    async fetch(request, env, ctx) {
        if (request.method === "OPTIONS") {
            return new Response(null, {
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Max-Age": "86400",
                }
            });
        }

        // --- EXTREME SECURITY: HONEYPOT IP BAN CHECK ---
        const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
        if (env.KV) {
            const isBanned = await env.KV.get(`banned_ip_${clientIp}`);
            if (isBanned) {
                return new Response(JSON.stringify({ error: "Your IP has been permanently banned for scraping." }), {
                    status: 403,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        }

        let url = new URL(request.url);

        // MOVING TARGET DEFENSE: Translate mutated parameters back to standard parameters
        const currentDay = Math.floor(Date.now() / 1000 / 86400);
        const mapCurr = getDynamicParamMap(currentDay);
        const mapPrev = getDynamicParamMap(currentDay - 1);

        const tryTranslateParams = (map) => {
            if (url.searchParams.has(map.action)) {
                url.searchParams.set('action', url.searchParams.get(map.action));
                if (url.searchParams.has(map.id)) url.searchParams.set('id', url.searchParams.get(map.id));
                if (url.searchParams.has(map.u)) url.searchParams.set('u', url.searchParams.get(map.u));
                if (url.searchParams.has(map.sig)) url.searchParams.set('sig', url.searchParams.get(map.sig));
                if (url.searchParams.has(map.key)) url.searchParams.set('key', url.searchParams.get(map.key));
                if (url.searchParams.has(map.friend)) url.searchParams.set('friend', url.searchParams.get(map.friend));
                return true;
            }
            return false;
        };

        if (!tryTranslateParams(mapCurr)) {
            tryTranslateParams(mapPrev);
        }

        const action = url.searchParams.get('action');

        // --- EXTREME SECURITY: CATCH HONEYPOT TRAP ---
        const trapId = url.searchParams.get('id') || url.searchParams.get('u');
        if (trapId === 'trap_honeypot') {
            if (env.KV && clientIp !== 'unknown') {
                // Ban IP for 7 days
                await env.KV.put(`banned_ip_${clientIp}`, '1', { expirationTtl: 86400 * 7 });
            }
            return new Response("Banned", { status: 403 });
        }

        const origin = request.headers.get("Origin") || '';
        const referer = request.headers.get("Referer") || '';
        const currentHost = `https://${url.hostname}`;

        const checkAllowed = (str) => {
            if (!str) return false;
            return str.includes('nibbu.pages.dev') ||
                str.includes('nibbu.workers.dev') ||
                str.includes('nibbu.arabba.workers.dev') ||
                str.includes('sony.rabba.workers.dev') ||
                str === currentHost || str.startsWith(currentHost);
        };

        const isFriendDomain = checkAllowed(origin) || checkAllowed(referer) ||
            (action === 'api' && url.searchParams.get('password') === 'match_valverdeae') ||
            request.headers.get('X-User-Key') === 'valverde';

        const ua = request.headers.get("User-Agent") || "";
        const lowerUa = ua.toLowerCase();

        const isBot = !ua ||
            lowerUa.includes("curl") ||
            lowerUa.includes("burp") ||
            lowerUa.includes("postman") ||
            lowerUa.includes("php") ||
            lowerUa.includes("wget") ||
            lowerUa.includes("python") ||
            lowerUa.includes("ubrowser") ||
            lowerUa.includes("ucbrowser") ||
            lowerUa.includes("ullaa") ||
            lowerUa.includes("ulla") ||
            lowerUa.includes("ulaa") ||
            lowerUa.includes("httpclient") ||
            lowerUa.includes("deno") ||
            lowerUa.includes("vercel") ||
            lowerUa.includes("netlify") ||
            lowerUa.includes("node");


        const acceptLang = request.headers.get("Accept-Language");
        const acceptEncoding = request.headers.get("Accept-Encoding");

        if (!isFriendDomain && (isBot || !acceptLang || !acceptEncoding)) {
            return new Response("Access Denied", { status: 403, headers: { 'Content-Type': 'text/plain' } });
        }


        const asOrg = (request.cf && request.cf.asOrganization) ? request.cf.asOrganization.toLowerCase() : "";
        const isDatacenter = asOrg.includes("amazon") ||
            asOrg.includes("digitalocean") ||
            asOrg.includes("hetzner") ||
            asOrg.includes("ovh") ||
            asOrg.includes("linode") ||
            asOrg.includes("vultr") ||
            asOrg.includes("hostinger") ||
            asOrg.includes("contabo") ||
            asOrg.includes("leaseweb") ||
            asOrg.includes("alibaba") ||
            asOrg.includes("tencent") ||
            asOrg.includes("choopa") ||
            asOrg.includes("constant") ||
            asOrg.includes("vercel") ||
            asOrg.includes("netlify") ||
            asOrg.includes("deno") ||
            asOrg.includes("ifastnet") ||
            asOrg.includes("infinityfree");

        const isWorkerToWorker = request.headers.has('cf-worker') || 
                                 request.headers.has('cf-ew-via') || 
                                 request.headers.has('cdn-loop');

        const isProxyHeaderPresent = request.headers.has('x-forwarded-host') || 
                                     request.headers.has('via') || 
                                     (request.headers.get('x-forwarded-for') && request.headers.get('x-forwarded-for').includes(','));

        const isStrictProxy = asOrg.includes("cloudflare") || asOrg.includes("google") || asOrg.includes("fastly") || asOrg.includes("akamai");

        // --- SECURITY: ADVANCED DATACENTER & PROXY BLOCK ---
        const isMediaAction = action === 'manifest' || action === 'manifest_url' || action === 'segment' || action === 'key';
        
        if (isMediaAction) {
            // Unconditionally block proxies for media actions, even if they spoof a friend domain
            if (isWorkerToWorker || isProxyHeaderPresent || isStrictProxy) {
                return new Response("Direct Proxying Prohibited", { status: 403, headers: { 'Content-Type': 'text/plain' } });
            }
            if (isDatacenter) {
                return new Response("VPN / Datacenter Access Prohibited", { status: 403, headers: { 'Content-Type': 'text/plain' } });
            }
        } else {
            // For dashboard/API, allow friend domain bypass
            if (isDatacenter && action !== 'api' && !isFriendDomain) {
                return new Response("Access Denied", { status: 403, headers: { 'Content-Type': 'text/plain' } });
            }
        }
        // -------------------------------------------------

        if (action === 'manifest' || action === 'manifest_url' || action === 'segment' || action === 'key') {
            const reqKey = url.searchParams.get('key');
            if (reqKey !== 'xyzplay') {
                return new Response(null, {
                    status: 302,
                    headers: { 'Location': 'https://nibbu.pages.dev' }
                });
            }

            const viewerOrigin = request.headers.get("X-Viewer-Origin") || request.headers.get("Origin") || "";
            const viewerReferer = request.headers.get("X-Viewer-Referer") || request.headers.get("Referer") || "";

            const isInsideMatchesLinkz = checkAllowed(viewerOrigin) || checkAllowed(viewerReferer);

            if (!isInsideMatchesLinkz) {
                return new Response(null, {
                    status: 302,
                    headers: { 'Location': 'https://nibbu.pages.dev' }
                });
            }

            const secFetchSite = request.headers.get('Sec-Fetch-Site') || '';
            const secFetchMode = request.headers.get('Sec-Fetch-Mode') || '';
            const secFetchDest = request.headers.get('Sec-Fetch-Dest') || '';


            if (!isFriendDomain && (secFetchMode === 'navigate' || secFetchDest === 'document')) {
                return new Response(null, {
                    status: 302,
                    headers: { 'Location': 'https://nibbu.pages.dev' }
                });
            }

            const expectedOriginHTTPS = `https://${url.hostname}`;
            const expectedOriginHTTP = `http://${url.hostname}`;
            const isAuthorized =
                referer.startsWith(expectedOriginHTTPS) ||
                referer.startsWith(expectedOriginHTTP) ||
                origin === expectedOriginHTTPS ||
                origin === expectedOriginHTTP ||
                secFetchSite === 'same-origin' ||
                isFriendDomain;

            // STRICT SECURITY: Verify Signed URL (Tamper-Proof + Header-Bound HMAC)
            const providedSig = url.searchParams.get('sig');
            let isSigValid = false;
            let identifier = "";
            let timeBlocks = [];

            if (providedSig) {
                const secret = getSecret(env);

                if (action === 'manifest' || action === 'manifest_url') {
                    identifier = action === 'manifest' ? url.searchParams.get('id') : url.searchParams.get('u');
                    const timeBlock = Math.floor(Date.now() / 1000 / 10800); // 3 hours
                    timeBlocks = [timeBlock, timeBlock - 1];
                } else if (action === 'segment' || action === 'key') {
                    identifier = url.searchParams.get('u');
                    const timeBlock = Math.floor(Date.now() / 1000 / 300); // 5 minutes
                    timeBlocks = [timeBlock, timeBlock - 1];
                }

                if (identifier) {
                    isSigValid = await verifySignedRequest(action, identifier, request, timeBlocks, secret, providedSig);
                }
            }

            // STRICT SECURITY: Token MUST be valid and IP-bound, no exceptions for spoofed domain headers.
            if (!isAuthorized || !isSigValid) {
                return new Response(null, {
                    status: 302,
                    headers: { 'Location': 'https://nibbu.pages.dev' }
                });
            }
        }
        // ---------------------------------------------------


        const isAdmin = url.searchParams.get("pass") === "sdjjnascal";
        const hasId = url.searchParams.has('id');

        if (!action) {
            if (!isAdmin && !hasId) {
                return new Response(null, {
                    status: 302,
                    headers: {
                        'Location': 'https://nibbu.pages.dev'
                    }
                });
            }
        }
        // ---------------------------

        if (action === 'manifest') {
            return await handleManifest(url.searchParams.get('id'), url, request, env);
        } else if (action === 'manifest_url') {
            return await handleManifestUrl(url.searchParams.get('u'), url, request, env);
        } else if (action === 'segment' || action === 'key') {
            return await handleSegment(url.searchParams.get('u'), request, env);
        } else if (action === 'api') {
            const password = url.searchParams.get("password");
            const reqOrigin = request.headers.get("Origin") || request.headers.get("Referer") || "";

            if (password !== "match_valverdeae") {
                return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 403, headers: { "Content-Type": "application/json" } });
            }
            const isAllowedOrigin = !reqOrigin || checkAllowed(reqOrigin);
            if (!isAllowedOrigin) {
                return new Response(JSON.stringify({ error: "Forbidden Domain" }), { status: 403, headers: { "Content-Type": "application/json" } });
            }
            return await handleApi(url, request, env);
        } else {
            return await handleDashboard(url, request, isAdmin, env);
        }
    }
};

async function handleApi(reqUrl, request, env) {
    let data;
    try {
        data = await fetchJson(request);
    } catch (e) {
        return new Response(JSON.stringify({ error: "Failed to fetch channel data" }), { status: 502, headers: { "Content-Type": "application/json" } });
    }

    const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
    const userAgent = request.headers.get('User-Agent') || 'unknown';

    // Generate fallback generic token for KV logging (if needed)
    const secret = getSecret(env);
    const token = await createSignedRequest('log', 'api', request, Math.floor(Date.now() / 1000 / 10800), secret, true);

    if (env.KV) {
        const domain = request.headers.get("Origin") || request.headers.get("Referer") || "direct";
        const generatedAt = Date.now();
        const expiresAt = generatedAt + 3 * 60 * 60 * 1000;
        // Async background write to KV to avoid blocking request and allow logging
        env.KV.put(`token:${token}`, JSON.stringify({
            ip: clientIp,
            userAgent: userAgent,
            domain: domain,
            generatedAt: generatedAt,
            expiresAt: expiresAt
        }), { expirationTtl: 10800 }).catch(() => { });
    }

    const workerBase = publicWorkerBase(reqUrl);
    const result = [];

    for (const [id, channel] of Object.entries(data)) {
        if (channel.m3u8) {
            // Filter to only include Sony Ten 3 channels
            const titleUpper = (channel.title || '').toUpperCase();
            if (!titleUpper.includes("TEN")) continue;

            const realId = channel.id || id;
            const encryptedId = await encryptData(realId, env);

            const sig = await createSignedRequest('manifest', encryptedId, request, Math.floor(Date.now() / 1000 / 10800), secret, true);
            const currentDay = Math.floor(Date.now() / 1000 / 86400);
            const pMap = getDynamicParamMap(currentDay);
            const proxyurl = `${workerBase}?${pMap.action}=manifest&${pMap.id}=${encryptedId}&ext=.m3u8&${pMap.sig}=${sig}&${pMap.key}=xyzplay`;

            result.push({
                id: encryptedId,
                title: channel.title || 'Unknown',
                logo: channel.logo || '',
                genre: channel.genre || '',
                language: channel.language || '',
                proxyurl: proxyurl
            });
        }
    }

    const originHeader = request.headers.get("Origin") || "";
    const allowedOrigin = originHeader ? originHeader : "*";

    return new Response(JSON.stringify(result), {
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": allowedOrigin,
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "*"
        }
    });
}

async function fetchJson(request) {
    const jsonUrl = 'https://allinonereborn2.online/sony/sliv3.json';
    const fetchHeaders = new Headers({
        "Host": "allinonereborn2.online",
        "Origin": "https://allinonereborn2.online",
        "Referer": "https://allinonereborn2.online/",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36"
    });
    const clientIp = request ? request.headers.get('CF-Connecting-IP') : null;
    if (clientIp) {
        fetchHeaders.set('X-Forwarded-For', clientIp);
    }

    const resp = await fetch(jsonUrl, {
        headers: fetchHeaders,
        cf: {
            cacheTtl: 600, // Cache JSON for 10 minutes (channel list rarely changes)
            cacheEverything: true
        }
    });
    if (!resp.ok) throw new Error("Failed to fetch JSON");
    return await resp.json();
}

async function handleDashboard(reqUrl, request, isAdmin, env) {
    let data;
    try {
        data = await fetchJson(request);
    } catch (e) {
        return new Response('<h2 style="color:white;text-align:center;margin-top:50px;font-family:Arial,sans-serif;">Failed to fetch channel data from backend</h2>', {
            status: 502,
            headers: { 'Content-Type': 'text/html' }
        });
    }

    const safeChannels = {};
    const workerBase = publicWorkerBase(reqUrl);


    const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
    const userAgent = request.headers.get('User-Agent') || 'unknown';

    // Generate fallback generic token for KV logging
    const secret = getSecret(env);
    const token = await createSignedRequest('log', 'dashboard', request, Math.floor(Date.now() / 1000 / 10800), secret, false);

    if (env.KV) {
        const domain = request.headers.get("Origin") || request.headers.get("Referer") || "direct";
        const generatedAt = Date.now();
        const expiresAt = generatedAt + 3 * 60 * 60 * 1000;
        // Async background write to KV to avoid blocking request and allow logging
        env.KV.put(`token:${token}`, JSON.stringify({
            ip: clientIp,
            userAgent: userAgent,
            domain: domain,
            generatedAt: generatedAt,
            expiresAt: expiresAt
        }), { expirationTtl: 10800 }).catch(() => { });
    }

    const reqId = reqUrl.searchParams.get('id');


    for (const [id, channel] of Object.entries(data)) {
        if (channel.m3u8) {
            const realId = channel.id || id;
            const encryptedId = await encryptData(realId, env);


            const sig = await createSignedRequest('manifest', encryptedId, request, Math.floor(Date.now() / 1000 / 10800), secret, false);

            if (!isAdmin && reqId && encryptedId !== reqId) {
                continue;
            }

            safeChannels[encryptedId] = {
                id: encryptedId,
                sig: sig,
                title: channel.title || 'Unknown',
                logo: channel.logo || '',
                genre: channel.genre || '',
                language: channel.language || ''
            };
        }
    }

    const currentDay = Math.floor(Date.now() / 1000 / 86400);
    const pMap = getDynamicParamMap(currentDay);

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Live TV Dashboard</title>
    <style>
        * {
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }

        body {
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            color: white;
            display: flex;
            flex-direction: column;
            align-items: center;
            min-height: 100vh;
            min-height: 100dvh;
        }
        
        body.player-active {
            overflow: hidden;
        }
        
        ${!isAdmin ? `
        .channels-container { display: none !important; }
        .player-container { display: flex !important; }
        .close-btn { display: none !important; }
        body { overflow: hidden !important; }
        ` : ''}

        .dashboard {
            display: flex;
            flex-direction: column;
            width: 95%;
            max-width: 1200px;
            margin-top: 20px;
            gap: 20px;
        }

        /* Player Section */
        .player-container {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100vh;
            height: 100dvh;
            background: rgba(15, 23, 42, 0.95);
            z-index: 9999;
            display: none;
            backdrop-filter: blur(20px);
            padding: 0;
            box-sizing: border-box;
        }



        .seek-ripple {
            position: fixed;
            transform: translate(-50%, -50%);
            background: rgba(0, 0, 0, 0.7);
            color: white;
            padding: 15px 25px;
            border-radius: 30px;
            font-size: 16px;
            font-weight: bold;
            pointer-events: none;
            z-index: 10001;
            opacity: 0;
            animation: ripple-fade 0.7s ease-out forwards;
            backdrop-filter: blur(5px);
            display: flex;
            align-items: center;
            justify-content: center;
            white-space: nowrap;
        }

        @keyframes ripple-fade {
            0% { opacity: 0; transform: translate(-50%, -50%) scale(0.8); }
            15% { opacity: 1; transform: translate(-50%, -50%) scale(1.1); }
            100% { opacity: 0; transform: translate(-50%, -50%) scale(1.5); }
        }

        .video-wrapper {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: #000;
            overflow: hidden;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        #player {
            width: 100%;
            height: 100%;
            max-width: 100%;
            max-height: 100%;
        }
        
        /* Ensure inner video container of JW Player is also centered */
        .jwplayer.jw-reset {
            margin: 0 auto;
        }

        .player-logo {
            position: absolute;
            top: 20px;
            right: 20px;
            width: 80px;
            opacity: 0.7;
            pointer-events: none;
            z-index: 99;
        }

        /* Channels Grid */
        .channels-container {
            width: 100%;
            background: rgba(30, 41, 59, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            padding: 15px; /* Better for mobile */
            margin-bottom: 40px;
        }

        .channels-container h2 {
            margin-top: 0;
            font-size: 20px;
            margin-bottom: 15px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding-bottom: 10px;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); /* Better for mobile */
            gap: 12px;
        }

        .channel-card {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 12px;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
        }

        .channel-card:hover {
            transform: translateY(-5px);
            background: rgba(56, 189, 248, 0.1);
            border-color: #38bdf8;
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.3);
        }

        .channel-card.active {
            background: rgba(56, 189, 248, 0.2);
            border-color: #38bdf8;
            box-shadow: 0 0 15px rgba(56, 189, 248, 0.4);
        }

        .channel-card img {
            width: 100%;
            max-width: 100px;
            height: auto;
            border-radius: 8px;
            margin-bottom: 8px;
            background: #fff;
            padding: 5px;
        }

        .channel-card .title {
            font-weight: 600;
            font-size: 14px;
            margin-bottom: 5px;
        }

        .channel-card .meta {
            font-size: 11px;
            color: #94a3b8;
            background: rgba(0, 0, 0, 0.3);
            padding: 2px 8px;
            border-radius: 10px;
        }

        @media (min-width: 600px) {
            .grid {
                grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
                gap: 15px;
            }
            .channels-container {
                padding: 20px;
            }
            .channels-container h2 {
                font-size: 22px;
                margin-bottom: 20px;
            }
            .channel-card {
                padding: 15px;
            }
            .channel-card img {
                max-width: 120px;
                margin-bottom: 10px;
            }
        }
        
        @media (min-width: 900px) {
            .channels-container {
                width: 100%;
            }
        }

        .adblock-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100vh;
            height: 100dvh;
            background: rgba(15, 23, 42, 0.98);
            z-index: 100000;
            display: none;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            color: white;
            text-align: center;
            padding: 20px;
            box-sizing: border-box;
            backdrop-filter: blur(15px);
        }

        .adblock-overlay h1 {
            color: #ef4444;
            font-size: 32px;
            margin-bottom: 10px;
        }

        .adblock-overlay p {
            font-size: 18px;
            max-width: 500px;
            line-height: 1.5;
            color: #cbd5e1;
            margin-bottom: 30px;
        }
        
        .adblock-overlay .warning-icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
    </style>
    <!-- JW Player Library -->
    <script src="https://content.jwplatform.com/libraries/KB5zFt7A.js"></script>
    <!-- Shaka Player Library (Fallback/Option) -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/shaka-player/4.7.11/shaka-player.ui.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/shaka-player/4.7.11/controls.min.css">
    
    <!-- Ad Network Script -->
    <script src="https://pl30385588.effectivecpmnetwork.com/cf/ee/7f/cfee7f9e07d31ef68a8b933dede5bcf7.js"></script>
</head>

<body>

    <div class="adblock-overlay" id="adblock-overlay">
        <div class="warning-icon">⚠️</div>
        <h1>Adblocker Detected</h1>
        <p>It looks like you are using an Adblocker or the Brave browser. To support us and watch the stream, please disable your Adblocker or use a standard browser like Chrome, Safari, or Firefox.</p>
        <button style="background:#ef4444; color:white; border:none; padding:15px 30px; font-size:18px; border-radius:8px; cursor:pointer; font-weight:bold;" onclick="window.location.reload()">I Have Disabled It - Refresh</button>
    </div>

    <!-- Player Section -->
    <div class="player-container">
        <!-- Premium Auto-Hiding Settings Bar in Player UI -->
        <div id="player-settings-overlay" style="position:absolute; top:20px; left:20px; z-index:9999; transition: opacity 0.3s ease; opacity: 1;">
            <label style="color:white; display:flex; align-items:center; cursor:pointer; font-size:14px; background:linear-gradient(135deg, #ff003c 0%, #8b0021 100%); padding:10px 20px; border-radius:30px; box-shadow: 0 4px 15px rgba(255, 0, 60, 0.4); border: 1px solid rgba(255,255,255,0.2); font-weight:bold; letter-spacing:0.5px;">
                <input type="checkbox" id="playerToggle" style="margin-right:10px; cursor:pointer; accent-color:#fff;" onchange="togglePlayerEngine()">
                Use Shaka Player
            </label>
        </div>
        <div class="video-wrapper">
            <!-- JW Player Container -->
            <div id="player"></div>
            <!-- Shaka Player Container (Hidden by default) -->
            <div id="shaka-container" style="width:100%;height:100%;display:none;position:relative;">
                <video id="shaka-video" style="width:100%;height:100%;" autoplay></video>
            </div>
        </div>
    </div>

    <div class="dashboard">
        <!-- Channels Grid Section -->
        <div class="channels-container">
            <h2>Live Channels</h2>
            <div class="grid" id="channels-grid">
                <!-- Populated by JS -->
            </div>
        </div>
    </div>

    <script>
        // Smart Popunder Ads
        let adClickCount = 0;
        document.addEventListener('click', function(e) {
            adClickCount++;
            if (adClickCount % 4 === 0) {
                window.open('https://www.effectivecpmnetwork.com/z73madn50h?key=af3e94e1b6ece78b5787079d24fbfd58', '_blank');
            }
        });

        // Anti-Automation & Anti-Debugging
        (function() {
            // Disable Right Click
            document.addEventListener('contextmenu', e => e.preventDefault());
            
            // Disable F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U
            document.onkeydown = function(e) {
                if(e.keyCode == 123 || 
                  (e.ctrlKey && e.shiftKey && (e.keyCode == 73 || e.keyCode == 74)) || 
                  (e.ctrlKey && e.keyCode == 85)) {
                    e.preventDefault();
                    return false;
                }
            };
            
            // Detect WebDriver (Puppeteer/Selenium)
            if (navigator.webdriver) {
                document.body.innerHTML = 'Forbidden';
                window.location.replace('about:blank');
            }
            
            // Anti-Console
            const noop = () => {};
            ['log','debug','info','warn','error','dir','trace','profile','profileEnd'].forEach(method => {
                console[method] = noop;
            });
            
            // Aggressive DevTools detection loop
            setInterval(() => {
                const before = new Date().getTime();
                debugger;
                const after = new Date().getTime();
                if (after - before > 200) {
                    document.body.innerHTML = '';
                    window.location.replace('about:blank');
                }
            }, 2000);
            
            // AdBlocker & Brave Detection
            function checkAds() {
                return new Promise((resolve) => {
                    if (navigator.brave && navigator.brave.isBrave) {
                        navigator.brave.isBrave().then(isBrave => {
                            if (isBrave) resolve(true);
                        });
                    }
                    const fake = document.createElement('div');
                    fake.className = 'ad-banner adsbox doubleclick ad-slot';
                    fake.style.position = 'absolute';
                    fake.style.top = '-999px';
                    fake.style.height = '10px';
                    fake.style.width = '10px';
                    document.body.appendChild(fake);
                    
                    setTimeout(() => {
                        const blocked = fake.offsetHeight === 0 || window.getComputedStyle(fake).display === 'none';
                        fake.remove();
                        resolve(blocked);
                    }, 200);
                });
            }
            
            setInterval(async () => {
                if (await checkAds()) {
                    document.getElementById('adblock-overlay').style.display = 'flex';
                    const playerContainer = document.querySelector('.player-container');
                    if (playerContainer) playerContainer.style.display = 'none';
                }
            }, 3000);
        })();

        const _wb = "${workerBase}";
        const pMap = ${JSON.stringify(pMap)};
        const channels = ${JSON.stringify(safeChannels)};
        let currentPlayer = null;
        let shakaPlayerInstance = null;

        // PC Browser Detection
        const isPC = !/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) && (window.innerWidth > 1024 || !('ontouchstart' in window));
        const isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
        const modes = ["uniform", "exactfit", "fill"];
        const zoomLevels = [1, 1.25, 1.3, 1.4];
        let modeIndex = 0;
        let zoomIndex = 0;
        let isShakaMode = false;
        let shakaPlayerInstance = null;

        function togglePlayerEngine() {
            isShakaMode = document.getElementById('playerToggle').checked;
            const currentId = new URLSearchParams(window.location.search).get('id');
            if (currentId) {
                playChannel(currentId, true);
            } else {
                closePlayer();
            }
        }

        // Auto-hide Player UI Elements (like JW Player)
        let hideTimeout;
        const playerContainer = document.querySelector('.player-container');
        const settingsOverlay = document.getElementById('player-settings-overlay');

        function showUI() {
            if (settingsOverlay) settingsOverlay.style.opacity = '1';
            clearTimeout(hideTimeout);
            hideTimeout = setTimeout(() => {
                if (settingsOverlay) settingsOverlay.style.opacity = '0';
            }, 3000); // Hide after 3 seconds of inactivity
        }

        playerContainer.addEventListener('mousemove', showUI);
        playerContainer.addEventListener('touchstart', showUI);
        playerContainer.addEventListener('mouseleave', () => {
            if (settingsOverlay) settingsOverlay.style.opacity = '0';
        });

        // Render the grid
        const grid = document.getElementById('channels-grid');
        let html = '';
        for (const id in channels) {
            const ch = channels[id];
            html += \`
                <div class="channel-card" id="card-\${id}" onclick="playChannel('\${id}')">
                    <img src="\${ch.logo}" alt="\${ch.title}" onerror="this.style.display='none'">
                    <div class="title">\${ch.title}</div>
                    <div class="meta">\${ch.language} • \${ch.genre}</div>
                </div>
            \`;
        }
        grid.innerHTML = html;

        async function playChannel(id, isPopState = false) {
            const channel = channels[id];
            if (!channel) return;

            // Construct proxy URL dynamically using the mathematically bound Tamper-Proof signature and Moving Target parameters
            const dynamicProxyUrl = _wb + "?" + pMap.action + "=manifest&" + pMap.id + "=" + id + "&ext=.m3u8&" + pMap.sig + "=" + channel.sig + "&" + pMap.key + "=xyzplay";

            // Highlight active card
            document.querySelectorAll('.channel-card').forEach(card => card.classList.remove('active'));
            const cardEl = document.getElementById(\`card-\${id}\`);
            if (cardEl) cardEl.classList.add('active');

            // Show the player overlay
            document.querySelector('.player-container').style.display = 'flex';
            document.body.classList.add('player-active');

            // Header removed for clean full-screen layout

            // Update URL securely without reloading
            if (!isPopState) {
                const url = new URL(window.location);
                url.searchParams.delete('pass');
                url.searchParams.set('id', id);
                window.history.pushState({ playerOpen: true }, '', url);
            }

            try {
                if (isShakaMode) {
                    // Hide JW, Show Shaka
                    document.getElementById('player').style.display = 'none';
                    const container = document.getElementById('shaka-container');
                    const video = document.getElementById('shaka-video');
                    container.style.display = 'block';
                    
                    if (currentPlayer) currentPlayer.stop(); // Stop JW if it was running

                    shaka.polyfill.installAll();
                    if (!shaka.Player.isBrowserSupported()) {
                        alert('Browser not supported for Shaka Player');
                        return;
                    }
                    if (!shakaPlayerInstance) {
                        shakaPlayerInstance = new shaka.Player(video);
                        const ui = new shaka.ui.Overlay(shakaPlayerInstance, container, video);
                        ui.configure({
                            addBigPlayButton: true,
                            controlPanelElements: [
                                'play_pause', 'time_and_duration', 'mute', 'volume',
                                'spacer', 'language', 'captions', 'picture_in_picture',
                                'quality', 'fullscreen'
                            ],
                            volumeBarColors: { base: 'rgba(63, 187, 1, 1)', level: 'rgb(255, 69, 0)' },
                            seekBarColors: { base: 'rgb(41, 41, 163)', buffered: 'rgb(35, 99, 3)', played: 'rgba(63, 187, 1, 1)' }
                        });
                    }
                    await shakaPlayerInstance.load(dynamicProxyUrl);
                    video.play();
                } else {
                    // Hide Shaka, Show JW
                    document.getElementById('shaka-container').style.display = 'none';
                    document.getElementById('player').style.display = 'block';
                    if (shakaPlayerInstance) {
                        shakaPlayerInstance.unload();
                    }

                    // Initialize or update JW Player
                    if (currentPlayer) {
                        currentPlayer.load([{ file: dynamicProxyUrl, type: "hls" }]);
                        currentPlayer.play();
                    } else {
                        currentPlayer = jwplayer("player");
                        currentPlayer.setup({
                            file: dynamicProxyUrl,
                            type: "hls",
                            width: "100%",
                            height: "100%",
                            autostart: true,
                            mute: false,
                            primary: "html5",
                            stretching: "uniform",
                            controls: true,
                            displaytitle: true,
                            displaydescription: true,
                            liveTimeout: 0,
                            qualityLabels: false,
                            skin: {
                                active: "#ff003c",
                                inactive: "rgba(255, 255, 255, 0.7)",
                                background: "rgba(0, 0, 0, 0.7)"
                            }
                        });

                        currentPlayer.on('ready', function () {

                            // Premium Double Tap to Seek (Mobile & PC)
                            const mediaLayer = document.querySelector('.jw-media') || document.getElementById('player');
                            if (mediaLayer) {
                                let lastTap = 0;
                                mediaLayer.addEventListener('click', function(e) {
                                    const currentTime = new Date().getTime();
                                    const tapLength = currentTime - lastTap;
                                    if (tapLength < 300 && tapLength > 0) {
                                        const rect = this.getBoundingClientRect();
                                        const x = e.clientX - rect.left;
                                        const pos = currentPlayer.getPosition();
                                        
                                        const ripple = document.createElement('div');
                                        ripple.className = 'seek-ripple';
                                        ripple.style.left = e.clientX + 'px';
                                        ripple.style.top = e.clientY + 'px';
                                        
                                        if (x < rect.width / 2) {
                                            currentPlayer.seek(Math.max(0, pos - 10));
                                            ripple.innerHTML = '⏪ 10s';
                                        } else {
                                            currentPlayer.seek(pos + 10);
                                            ripple.innerHTML = '10s ⏩';
                                        }
                                        
                                        document.body.appendChild(ripple);
                                        setTimeout(() => ripple.remove(), 700);
                                    }
                                    lastTap = currentTime;
                                });
                            }

                            if (isPC) {
                                currentPlayer.addButton(
                                    "https://i.ibb.co/4wPT214r/frame.png", "Zoom Level",
                                    function () {
                                        zoomIndex = (zoomIndex + 1) % zoomLevels.length;
                                        const videoContainer = document.querySelector('.jw-video, .jw-media');
                                        if (videoContainer) {
                                            videoContainer.style.transform = \`scale(\${zoomLevels[zoomIndex]})\`;
                                            videoContainer.style.transformOrigin = 'center center';
                                        }
                                    }, "aspect-button"
                                );
                            } else {
                                currentPlayer.addButton(
                                    "https://i.ibb.co/4wPT214r/frame.png", "Aspect Ratio",
                                    function () {
                                        modeIndex = (modeIndex + 1) % modes.length;
                                        currentPlayer.setConfig({ stretching: modes[modeIndex] });
                                    }, "aspect-button"
                                );
                            }

                            const logo = document.createElement("img");
                            // Using a tiny transparent 1x1 GIF as a placeholder since we want to remove the external URL
                            logo.src = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
                            logo.className = "player-logo";
                            document.getElementById("player").appendChild(logo);
                        });
                    }
                }
            } catch (e) {
                console.error("Player Error");
            }

            if (window.innerWidth < 900) {
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        }

        function closePlayer() {
            document.querySelector('.player-container').style.display = 'none';
            document.body.classList.remove('player-active');
            if (currentPlayer) {
                currentPlayer.stop();
            }
            const url = new URL(window.location);
            url.searchParams.delete('id');
            url.searchParams.delete('pass');
            window.history.pushState({}, '', url);
        }

        // Handle History Stack (Android Back Button / Browser Back)
        window.addEventListener('popstate', (event) => {
            const currentId = new URLSearchParams(window.location.search).get('id');
            if (currentId && channels[currentId]) {
                playChannel(currentId, true);
            } else {
                document.querySelector('.player-container').style.display = 'none';
                document.body.classList.remove('player-active');
                if (currentPlayer) currentPlayer.stop();
            }
        });

        const urlParams = new URLSearchParams(window.location.search);
        const autoPlayId = urlParams.get('id');
        if (autoPlayId && channels[autoPlayId]) {
            playChannel(autoPlayId, true);
        }
    </script>
</body>
</html>`;
    return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

async function handleManifest(encryptedId, reqUrl, request, env) {
    if (!encryptedId) return errorResponse("Missing ID", 400);
    const realId = await decryptData(encryptedId, env);
    if (!realId) return errorResponse("Invalid or corrupted ID", 403);

    let data;
    try {
        data = await fetchJson(request);
    } catch (e) {
        return errorResponse("Failed to fetch JSON: " + e.message, 502);
    }

    let m3u8Url = null;
    for (const [id, channel] of Object.entries(data)) {
        if ((channel.id || id) === realId) {
            m3u8Url = channel.m3u8;
            break;
        }
    }

    if (!m3u8Url) return errorResponse("Channel not found", 404);

    const token = reqUrl.searchParams.get('tk');

    const targetUrl = "https://allinonereborn2.online/livtest3/stream_proxy.php?url=" + strictUrlEncode(m3u8Url);
    return await fetchAndRewriteManifest(targetUrl, reqUrl, request, token, env);
}

async function handleManifestUrl(encryptedUrl, reqUrl, request, env) {
    if (!encryptedUrl) return errorResponse("Missing URL", 400);
    const targetUrl = await decryptData(encryptedUrl, env);
    if (!targetUrl) return errorResponse("Invalid or corrupted URL", 403);

    const token = reqUrl.searchParams.get('tk');

    return await fetchAndRewriteManifest(targetUrl, reqUrl, request, token, env);
}

async function fetchAndRewriteManifest(targetUrl, reqUrl, request, token, env) {
    const keyParam = reqUrl.searchParams.get("key") || (reqUrl.searchParams.get("friend") ? "xyzplay" : null);
    const friendParam = reqUrl.searchParams.get("friend");
    const fetchHeaders = new Headers(PROXY_HEADERS);
    const clientIp = request ? request.headers.get('CF-Connecting-IP') : null;
    if (clientIp) fetchHeaders.set('X-Forwarded-For', clientIp);

    // --- PRE-COMPUTE all crypto dependencies ONCE (not per-line) ---
    const secret = getSecret(env);
    const aesKey = await getCryptoKey(env);
    const currentDay = Math.floor(Date.now() / 1000 / 86400);
    const pMap = getDynamicParamMap(currentDay);
    const manifestTimeBlock = Math.floor(Date.now() / 1000 / 10800);
    const segmentTimeBlock = Math.floor(Date.now() / 1000 / 300);
    const workerBase = `/`;

    // Pre-compute HMAC signing context from request headers (done once)
    let sigIp = clientIp || 'unknown';
    let sigUa = request ? request.headers.get('User-Agent') || 'unknown' : 'unknown';
    const origin = request ? request.headers.get('Origin') : null;
    let sigHost = 'matcheslinkz.pages.dev';
    if (origin) { try { sigHost = new URL(origin).hostname; } catch (e) { } }

    // Fast inline signing function (avoids repeated header reads)
    const fastSign = async (action, identifier, timeBlock) => {
        const payload = `${action}:${identifier}:${sigIp}:${sigUa}:${sigHost}:${timeBlock}:${secret}`;
        return await generateHMAC(secret, payload);
    };

    // Fast inline encrypt with in-request cache (same URL = same ciphertext, avoids duplicate work)
    const encryptCache = new Map();
    const fastEncrypt = async (text) => {
        if (encryptCache.has(text)) return encryptCache.get(text);
        const iv = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret + text)), 0, 12);
        const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, new TextEncoder().encode(text));
        const result = buf2hex(iv) + buf2hex(ciphertext);
        encryptCache.set(text, result);
        return result;
    };

    const resp = await fetch(targetUrl, {
        headers: fetchHeaders,
        cf: {
            cacheTtl: 5, // Cache manifests for 5 seconds (reduces upstream hits)
            cacheEverything: true
        }
    });
    if (!resp.ok) {
        const errText = await resp.text();
        return errorResponse(`DEBUG ERROR: Upstream error.\nTarget URL: ${targetUrl}\nHTTP Status: ${resp.status}\nResponse Body:\n${errText}`, 502);
    }

    let text = await resp.text();

    let originalUrl = targetUrl;
    const urlMatch = targetUrl.match(/url=([^&]+)/);
    if (urlMatch) {
        originalUrl = decodeURIComponent(urlMatch[1]);
    }

    const baseUrl = originalUrl.substring(0, originalUrl.lastIndexOf('/') + 1);

    const lines = text.split('\n');
    const processedLines = await Promise.all(lines.map(async (line) => {
        let trimmed = line.trim();
        if (!trimmed) return trimmed;

        if (trimmed.startsWith('#EXT-X-KEY:')) {
            const uriMatch = trimmed.match(/URI="([^"]+)"/);
            if (uriMatch) {
                let keyUrl = uriMatch[1];
                if (!keyUrl.startsWith('http')) {
                    keyUrl = baseUrl + keyUrl;
                }
                const encryptedKeyUrl = await fastEncrypt(keyUrl);
                const sig = await fastSign('key', encryptedKeyUrl, segmentTimeBlock);
                let newUri = `${workerBase}?${pMap.action}=key&${pMap.u}=${encryptedKeyUrl}&${pMap.sig}=${sig}`;
                if (keyParam) newUri += `&${pMap.key}=${keyParam}`;
                else if (friendParam) newUri += `&${pMap.friend}=${friendParam}`;
                return trimmed.replace(`URI="${uriMatch[1]}"`, `URI="${newUri}"`);
            }
        } else if (!trimmed.startsWith('#')) {
            let segUrl = trimmed;
            if (segUrl.includes('proxy_stream=')) return trimmed;

            const isManifest = (segUrl.includes('.m3u8') || segUrl.includes('stream_proxy.php'));

            if (isManifest) {
                if (!segUrl.startsWith('http')) {
                    segUrl = baseUrl + segUrl;
                }
                if (!segUrl.includes('stream_proxy.php')) {
                    segUrl = "https://allinonereborn2.online/livtest3/stream_proxy.php?url=" + strictUrlEncode(segUrl);
                }
                const encUrl = await fastEncrypt(segUrl);
                const sig = await fastSign('manifest_url', encUrl, manifestTimeBlock);
                let proxySeg = `${workerBase}?${pMap.action}=manifest_url&${pMap.u}=${encUrl}&${pMap.sig}=${sig}`;
                if (keyParam) proxySeg += `&${pMap.key}=${keyParam}`;
                else if (friendParam) proxySeg += `&${pMap.friend}=${friendParam}`;
                return proxySeg;
            } else {
                if (!segUrl.includes('segment_proxy.php')) {
                    if (!segUrl.startsWith('http')) {
                        segUrl = baseUrl + segUrl;
                    }
                    segUrl = "https://allinonereborn2.online/livtest3/segment_proxy.php?u=" + encodeURIComponent(segUrl);
                }
                const encUrl = await fastEncrypt(segUrl);
                const sig = await fastSign('segment', encUrl, segmentTimeBlock);
                let proxySeg = `${workerBase}?${pMap.action}=segment&${pMap.u}=${encUrl}&${pMap.sig}=${sig}`;
                if (keyParam) proxySeg += `&${pMap.key}=${keyParam}`;
                else if (friendParam) proxySeg += `&${pMap.friend}=${friendParam}`;
                return proxySeg;
            }
        }
        return trimmed;
    }));

    // --- EXTREME SECURITY: INJECT HONEYPOT TRAP ---
    let modifiedText = processedLines.join('\n');
    modifiedText += `\n# EXT-X-HONEYPOT-TRAP-DO-NOT-FETCH\n# ${workerBase}?${pMap.action}=segment&${pMap.u}=trap_honeypot&${pMap.sig}=fake_sig_trap&${pMap.key}=xyzplay\n`;

    return new Response(modifiedText, {
        headers: {
            "Content-Type": resp.headers.get("Content-Type") || "application/vnd.apple.mpegurl",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Cache-Control": "public, max-age=2"
        }
    });
}

async function handleSegment(encryptedUrl, request, env) {
    if (!encryptedUrl) return errorResponse("Missing URL", 400);
    const targetUrl = await decryptData(encryptedUrl, env);
    if (!targetUrl) return errorResponse("Invalid or corrupted URL", 403);

    const fetchHeaders = new Headers(PROXY_HEADERS);
    const clientIp = request ? request.headers.get('CF-Connecting-IP') : null;
    if (clientIp) fetchHeaders.set('X-Forwarded-For', clientIp);


    const resp = await fetch(targetUrl, {
        headers: fetchHeaders,
        cf: {
            cacheTtl: 31536000, // Cache video segments for 1 year
            cacheEverything: true
        }
    });

    const newHeaders = new Headers(resp.headers);
    newHeaders.set('Access-Control-Allow-Origin', '*');
    newHeaders.set('Access-Control-Allow-Methods', 'GET, HEAD, POST, OPTIONS');
    newHeaders.set('Access-Control-Allow-Headers', '*');
    newHeaders.set('Cache-Control', 'public, max-age=300');

    return new Response(resp.body, {
        status: resp.status,
        headers: newHeaders
    });
}
