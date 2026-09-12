const SECRET_KEY = "xQ#9vL2$pM8@kR4*jT6!nW7^yC3(hF1&";
const API_SECRET_KEY = "G5*bN#8zK2@vX9$mP1^qL4!cH7&yR3(t";
const ENCRYPTION_KEY = "wD@4jB9!vN2$xP7*kM5^qL8#cT3(hF1&";
const DRM_MASK_KEY = "zK9#vL2$pM8@kR4*jT6!nW7^yC3(hF1&";
const ALLOWED_CHANNELS = ['1106', '1108', '1109', '1114', '1122', '1123', '1124', '1141', '1142', '1389', '155', '162', '1650', '1651', '1774', '1775', '1984', '1985', '1998', '2852', '2853', '3273', '3274', '3277', '3278', '3372', '3373', '3374', '3397', '3398', '3399', '3528', '362', '460', '461', '514', '523', '524', '525', '891', '892'];
const CRICKESTER_CHANNELS = ['so1', 'so3', 'TNT4', 'wbyc'];
const BROBP_CHANNELS = ['1106', '1108', '1109', '1114', '1122', '1123', '1124', '1141', '1142', '1389', '155', '162', '1650', '1651', '1774', '1775', '1984', '1985', '1998', '2852', '2853', '3273', '3274', '3277', '3278', '3372', '3373', '3374', '3397', '3398', '3399', '3528', '362', '460', '461', '514', '523', '524', '525', '891', '892'];

const ALLOWED_DOMAINS = [
    "fanxzone.pages.dev",
    "ziotv.movieszonemedia.workers.dev"

];

function isAllowedDomain(originOrReferer) {
    if (!originOrReferer) return false;
    try {
        const urlObj = new URL(originOrReferer);
        return ALLOWED_DOMAINS.some(domain => urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain));
    } catch (e) {
        return ALLOWED_DOMAINS.some(domain => originOrReferer.includes(domain));
    }
}

const BOT_TOOL_USER_AGENTS = [
    "curl", "wget", "python", "node-fetch", "axios", "got", "undici",
    "burp", "zap", "postman", "insomnia", "fiddler", "java", "go-http-client",
    "okhttp", "httpclient", "urllib", "scrapy", "libwww", "phar", "httpx",
    "puppeteer", "playwright", "selenium", "phantomjs", "headlesschrome"
];

const RATE_LIMIT_MAP = new Map();

function isAutomatedClient(request) {
    const url = new URL(request.url);
    if (url.pathname === '/api/get/channels' || url.pathname === '/api/channels' || url.pathname === '/api/get/admin' || url.pathname === '/admin' || url.pathname.startsWith('/api/admin')) {
        return false; // Unconditionally allow access to channels and admin portal
    }

    const referer = request.headers.get("Referer") || "";
    const origin = request.headers.get("Origin") || "";
    const apiKey = request.headers.get("X-API-Key") || "";
    const ua = (request.headers.get("User-Agent") || "").toLowerCase();

    if ((apiKey && apiKey === API_SECRET_KEY) || ua === "cloudflare-worker") {
        return false;
    }

    if (request.method === "OPTIONS") {
        return false;
    }

    // Block known bot user agents or missing User-Agent
    if (!ua || BOT_TOOL_USER_AGENTS.some(tool => ua.includes(tool))) {
        return true;
    }

    const isAllowedRef = isAllowedDomain(referer) || isAllowedDomain(origin);
    const fetchMode = request.headers.get("Sec-Fetch-Mode");
    const fetchDest = request.headers.get("Sec-Fetch-Dest");
    const fetchSite = request.headers.get("Sec-Fetch-Site");

    // Allow iframe embed requests or requests with valid referer/origin
    if (isAllowedRef || fetchDest === "iframe" || fetchMode === "nested-navigate") {
        return false;
    }

    // Block direct address bar navigation when no allowed referer is present
    if (fetchSite === "none" || (fetchMode === "navigate" && fetchDest === "document") || (!referer && !origin)) {
        return true;
    }

    return false;
}



async function createAuthCookieToken(clientIp, userAgent) {
    const payload = JSON.stringify({
        ip: clientIp || "",
        ua: userAgent ? userAgent.substring(0, 50) : "",
        exp: Date.now() + 4 * 60 * 60 * 1000
    });

    const encoder = new TextEncoder();
    const rawKey = encoder.encode(ENCRYPTION_KEY);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const cryptoKey = await crypto.subtle.importKey(
        "raw", rawKey,
        { name: "AES-GCM" },
        false, ["encrypt"]
    );

    const encryptedBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        cryptoKey,
        encoder.encode(payload)
    );

    const encryptedBytes = new Uint8Array(encryptedBuffer);
    const combinedBuffer = new Uint8Array(iv.length + encryptedBytes.length);
    combinedBuffer.set(iv, 0);
    combinedBuffer.set(encryptedBytes, iv.length);

    let binaryStr = "";
    const chunkSize = 0x8000;
    for (let i = 0; i < combinedBuffer.length; i += chunkSize) {
        binaryStr += String.fromCharCode.apply(null, combinedBuffer.subarray(i, i + chunkSize));
    }
    return btoa(binaryStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function decryptAuthCookieToken(tokenStr) {
    if (!tokenStr) return null;
    try {
        let base64 = tokenStr.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) { base64 += '='; }
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        const iv = bytes.slice(0, 12);
        const encryptedData = bytes.slice(12);

        const encoder = new TextEncoder();
        const cryptoKey = await crypto.subtle.importKey(
            "raw", encoder.encode(ENCRYPTION_KEY),
            { name: "AES-GCM" },
            false, ["decrypt"]
        );

        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            cryptoKey,
            encryptedData
        );

        const jsonText = new TextDecoder().decode(decryptedBuffer);
        const data = JSON.parse(jsonText);
        if (!data || !data.ip || (data.exp && Date.now() > data.exp)) {
            return null;
        }
        return data;
    } catch (err) {
        return null;
    }
}

const BROBP_WORKER = 'https://as-brobp.rabba.workers.dev';

function getBrobpWorker(id) {
    return BROBP_WORKER;
}

async function generateHMAC(data, secret) {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        "raw", encoder.encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false, ["sign"]
    );
    const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
    return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function createStreamSessionToken(channelData, clientIp) {
    const cleanUrl = (channelData.streamUrl || "").trim().replace(/[\r\n\t\s]/g, '');
    const payload = JSON.stringify({
        u: cleanUrl,
        ki: (channelData.keyId || "").trim(),
        k: (channelData.key || "").trim(),
        t: (channelData.token || "").trim(),
        ft: (channelData.fallback_token || channelData.fallback_cookie || channelData.jtvplusfallbackcookie || channelData.jtvfallbackcookie || "").trim(),
        ac: !!(channelData.isAdminCustom || isJioUrl(cleanUrl)),
        ip: clientIp || "",
        exp: Date.now() + 4 * 60 * 60 * 1000
    });

    const encoder = new TextEncoder();
    const rawKey = encoder.encode(ENCRYPTION_KEY);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const cryptoKey = await crypto.subtle.importKey(
        "raw", rawKey,
        { name: "AES-GCM" },
        false, ["encrypt"]
    );

    const encryptedBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        cryptoKey,
        encoder.encode(payload)
    );

    const encryptedBytes = new Uint8Array(encryptedBuffer);
    const combinedBuffer = new Uint8Array(iv.length + encryptedBytes.length);
    combinedBuffer.set(iv, 0);
    combinedBuffer.set(encryptedBytes, iv.length);

    let binaryStr = "";
    const chunkSize = 0x8000;
    for (let i = 0; i < combinedBuffer.length; i += chunkSize) {
        binaryStr += String.fromCharCode.apply(null, combinedBuffer.subarray(i, i + chunkSize));
    }
    return btoa(binaryStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function decryptStreamSessionToken(tokenStr, clientIp) {
    if (!tokenStr) return null;
    try {
        let base64 = tokenStr.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) { base64 += '='; }
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        const iv = bytes.slice(0, 12);
        const encryptedData = bytes.slice(12);

        const encoder = new TextEncoder();
        const cryptoKey = await crypto.subtle.importKey(
            "raw", encoder.encode(ENCRYPTION_KEY),
            { name: "AES-GCM" },
            false, ["decrypt"]
        );

        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            cryptoKey,
            encryptedData
        );

        const jsonText = new TextDecoder().decode(decryptedBuffer);
        const session = JSON.parse(jsonText);

        if (!session || !session.u || (session.exp && Date.now() > session.exp)) {
            return null;
        }
        return session;
    } catch (err) {
        return null;
    }
}

async function createProxyToken(type, sessionToken, targetUrl) {
    const payload = JSON.stringify({
        t: type,
        s: sessionToken,
        u: targetUrl || ""
    });

    const encoder = new TextEncoder();
    const rawKey = encoder.encode(ENCRYPTION_KEY);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const cryptoKey = await crypto.subtle.importKey(
        "raw", rawKey,
        { name: "AES-GCM" },
        false, ["encrypt"]
    );

    const encryptedBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        cryptoKey,
        encoder.encode(payload)
    );

    const encryptedBytes = new Uint8Array(encryptedBuffer);
    const combinedBuffer = new Uint8Array(iv.length + encryptedBytes.length);
    combinedBuffer.set(iv, 0);
    combinedBuffer.set(encryptedBytes, iv.length);

    let binaryStr = "";
    const chunkSize = 0x8000;
    for (let i = 0; i < combinedBuffer.length; i += chunkSize) {
        binaryStr += String.fromCharCode.apply(null, combinedBuffer.subarray(i, i + chunkSize));
    }
    return btoa(binaryStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function decryptProxyToken(tokenStr) {
    if (!tokenStr) return null;
    try {
        let base64 = tokenStr.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) { base64 += '='; }
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        const iv = bytes.slice(0, 12);
        const encryptedData = bytes.slice(12);

        const encoder = new TextEncoder();
        const cryptoKey = await crypto.subtle.importKey(
            "raw", encoder.encode(ENCRYPTION_KEY),
            { name: "AES-GCM" },
            false, ["decrypt"]
        );

        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            cryptoKey,
            encryptedData
        );

        const jsonText = new TextDecoder().decode(decryptedBuffer);
        return JSON.parse(jsonText);
    } catch (err) {
        return null;
    }
}

function isJioUrl(urlStr) {
    if (!urlStr) return false;
    const lower = String(urlStr).toLowerCase();
    return lower.includes("jio") || lower.includes("jiotv") || lower.includes("jiotvpllive") || lower.includes("bpk-tv") || lower.includes("amagi.tv") || lower.includes("sportstribal") || lower.includes("willow.tv");
}

function attachJioTokenToUrl(urlStr, tokenStr) {
    if (!urlStr) return urlStr;
    if (urlStr.includes("__hdnea__=") || urlStr.includes("hdnea=")) return urlStr;
    if (!tokenStr) return urlStr;

    let cleanToken = tokenStr.trim();
    if (cleanToken.startsWith("hdnea=")) {
        cleanToken = cleanToken.substring(6);
    } else if (cleanToken.startsWith("__hdnea__=")) {
        cleanToken = cleanToken.substring(10);
    }

    const separator = urlStr.includes("?") ? "&" : "?";
    return `${urlStr}${separator}__hdnea__=${cleanToken}`;
}

async function rewriteHlsManifestUniversal(manifestText, baseUrl, sessionToken, domain, parentQuery, isAdminCustom) {
    if (isAdminCustom || isJioUrl(baseUrl)) {
        return manifestText;
    }
    const lines = manifestText.split(/\r?\n/);
    const rewritten = [];

    for (let i = 0; i < lines.length; i++) {
        let line = lines[i].trim();
        if (!line) {
            rewritten.push(line);
            continue;
        }

        if (line.startsWith('#')) {
            if (line.includes('URI=')) {
                line = line.replace(/URI=["']([^"']+)["']/gi, (match, p1) => {
                    try {
                        const cleanMediaUri = p1.trim().replace(/[\r\n\t\s]/g, '');
                        const absUri = new URL(cleanMediaUri, baseUrl).href;
                        return `URI="${absUri}"`;
                    } catch (e) {
                        return match;
                    }
                });
            }
            rewritten.push(line);
            continue;
        }

        try {
            const cleanLine = line.trim().replace(/[\r\n\t\s]/g, '');
            const absUri = new URL(cleanLine, baseUrl).href;
            rewritten.push(absUri);
        } catch (e) {
            rewritten.push(line);
        }
    }

    return rewritten.join('\n');
}

async function rewriteDashManifestUniversal(mpdXml, baseDir, sessionToken, domain, isAdminCustom) {
    if (isAdminCustom || isJioUrl(baseDir)) {
        return mpdXml;
    }

    const proxySegmentToken = await createProxyToken(2, sessionToken, baseDir);
    const proxyBase = `https://${domain}/api/proxy/${proxySegmentToken}/`;

    if (mpdXml.includes('<BaseURL>')) {
        mpdXml = mpdXml.replace(/<BaseURL>[^<]*<\/BaseURL>/gi, `<BaseURL>${proxyBase}</BaseURL>`);
    } else {
        mpdXml = mpdXml.replace(/<MPD([^>]*)>/i, `<MPD$1>\n<BaseURL>${proxyBase}</BaseURL>`);
    }

    return mpdXml;
}

function getCookieValue(request, cookieName) {
    const cookieHeader = request.headers.get("Cookie");
    if (!cookieHeader) return null;
    const cookies = cookieHeader.split(';');
    for (let c of cookies) {
        const [name, ...valParts] = c.trim().split('=');
        if (name === cookieName) {
            return valParts.join('=');
        }
    }
    return null;
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

async function handleAdminRoute(request, domain) {
    const url = new URL(request.url);
    const FIREBASE_API_KEY = "AIzaSyD-nUtWeFqHLCWPOQaFDCgmHfCGjf7L6Mo";
    const FIREBASE_CUSTOM_URL = `https://firestore.googleapis.com/v1/projects/sports-zone-ed3a9/databases/(default)/documents/fanxzone_custom?key=${FIREBASE_API_KEY}`;

    let reqPassword = url.searchParams.get("pass") || url.searchParams.get("password") || request.headers.get("X-Admin-Password");
    let cookiePass = getCookieValue(request, "__sz_admin_pass");

    let bodyData = {};
    if (request.method === "POST") {
        try {
            const contentType = request.headers.get("Content-Type") || "";
            if (contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data")) {
                const formData = await request.formData();
                for (const [key, value] of formData.entries()) {
                    bodyData[key] = value;
                }
            } else if (contentType.includes("application/json")) {
                bodyData = await request.json();
            }
        } catch (e) { }
    }

    if (bodyData.password) {
        reqPassword = bodyData.password;
    }

    const authenticated = (reqPassword === "admin@123" || cookiePass === "admin@123");

    if (!authenticated) {
        let errorNotice = (reqPassword && reqPassword !== "admin@123") ? `<div class="error-msg">Incorrect Password! Please try again.</div>` : "";
        const loginHtml = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FanxZone Admin Login</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }
body { background: #0b0f19; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
.login-card { background: #161e2e; padding: 40px; border-radius: 16px; width: 100%; max-width: 420px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); border: 1px solid #233044; }
.title { font-size: 26px; font-weight: 700; color: #38bdf8; margin-bottom: 8px; text-align: center; }
.subtitle { font-size: 14px; color: #94a3b8; margin-bottom: 24px; text-align: center; }
.input-group { margin-bottom: 20px; }
label { display: block; font-size: 14px; color: #cbd5e1; margin-bottom: 6px; font-weight: 500; }
input[type="password"] { width: 100%; padding: 12px 16px; background: #0b0f19; border: 1px solid #334155; border-radius: 8px; color: #fff; font-size: 15px; outline: none; transition: border-color 0.2s; }
input[type="password"]:focus { border-color: #38bdf8; }
button { width: 100%; padding: 12px; background: linear-gradient(135deg, #0284c7, #2563eb); border: none; border-radius: 8px; color: #fff; font-size: 16px; font-weight: 600; cursor: pointer; transition: opacity 0.2s; }
button:hover { opacity: 0.9; }
.error-msg { background: #7f1d1d; color: #fca5a5; padding: 10px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; text-align: center; }
</style>
</head>
<body>
<div class="login-card">
  <div class="title">⚡ FanxZone Admin</div>
  <div class="subtitle">Enter password to access match stream management</div>
  ${errorNotice}
  <form method="POST" action="/api/get/admin">
    <div class="input-group">
      <label for="password">Admin Password</label>
      <input type="password" id="password" name="password" placeholder="Enter Password" required autofocus>
    </div>
    <button type="submit">Unlock Dashboard</button>
  </form>
</div>
</body>
</html>`;
        return new Response(loginHtml, {
            status: 200,
            headers: { "Content-Type": "text/html;charset=UTF-8" }
        });
    }
    const action = bodyData.action || url.searchParams.get("action");

    if (action === "get_token") {
        const targetSsid = url.searchParams.get("ssid") || "";
        const targetDom = url.searchParams.get("target_domain") || domain;
        const timeBlock = Math.floor(Date.now() / (1000 * 60 * 60 * 24));
        const dataToSign = `${targetDom}|${timeBlock}|${targetSsid}|unknown`;
        const token = await generateHMAC(dataToSign, SECRET_KEY);
        const playUrl = `https://${targetDom}/?id=${encodeURIComponent(targetSsid)}&token=${token}`;
        return new Response(JSON.stringify({ token, playUrl, domain: targetDom }), {
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Set-Cookie": "__sz_admin_pass=admin@123; Path=/; HttpOnly; Secure; SameSite=Lax" }
        });
    }

    if (action === "cron_update_st") {
        try {
            const stRes = await fetch("https://as-stflx.rabba.workers.dev/update", { cf: { cacheTtl: 0, cacheEverything: false } }).catch(() => null);
            const stData = (stRes && stRes.ok) ? await stRes.json() : null;

            return new Response(JSON.stringify({
                success: true,
                message: "ST Worker (as-stflx) cron update executed successfully",
                updated_at: new Date().toISOString(),
                stflx_status: stData ? "success" : "skipped/failed",
                data: stData
            }), {
                headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Set-Cookie": "__sz_admin_pass=admin@123; Path=/; HttpOnly; Secure; SameSite=Lax" }
            });
        } catch (e) {
            return new Response(JSON.stringify({ success: false, error: e.message }), {
                headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
            });
        }
    }

    if (action === "cron_list") {
        try {
            const targetIds = ["144", "1109"];

            const [cj144Res, cj1109Res, test144Res, test1109Res, jtvPlusRes, jtvRes] = await Promise.all([
                fetch("https://as-cjbp.yinave4095.workers.dev/?id=144", { cf: { cacheTtl: 0, cacheEverything: false } }).catch(() => null),
                fetch("https://as-cjbp.yinave4095.workers.dev/?id=1109", { cf: { cacheTtl: 0, cacheEverything: false } }).catch(() => null),
                fetch("https://as-test.rabba.workers.dev/?id=144", { cf: { cacheTtl: 0, cacheEverything: false } }).catch(() => null),
                fetch("https://as-test.rabba.workers.dev/?id=1109", { cf: { cacheTtl: 0, cacheEverything: false } }).catch(() => null),
                fetch("https://as-brobp.rabba.workers.dev/jtvplus", { cf: { cacheTtl: 0, cacheEverything: false } }).catch(() => null),
                fetch("https://as-brobp.rabba.workers.dev/jtv", { cf: { cacheTtl: 0, cacheEverything: false } }).catch(() => null)
            ]);

            const parseTimesFromToken = (tok) => {
                let expStr = "Live Active Token";
                let genStr = "Live Generated Token";

                if (tok && tok.includes("exp=")) {
                    try {
                        const m = tok.match(/exp=(\d+)/);
                        if (m) expStr = new Date(parseInt(m[1]) * 1000).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }) + " IST";
                    } catch (e) { }
                }
                if (tok && tok.includes("st=")) {
                    try {
                        const m = tok.match(/st=(\d+)/);
                        if (m) genStr = new Date(parseInt(m[1]) * 1000).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }) + " IST";
                    } catch (e) { }
                }

                return { expStr, genStr };
            };

            const processItem = (item, sourceName, fallbackName) => {
                if (!item) return null;
                const tok = (item.cookie || item.token || item.fallback_cookie || item.key || "").trim();
                if (!tok || tok.length < 10) return null;

                const { expStr, genStr } = parseTimesFromToken(tok);
                return {
                    id: String(item.id || item.ssid || ""),
                    name: item.name || item.title || fallbackName,
                    cookie: tok,
                    url: item.mpd || item.url || item.streamUrl || "",
                    expires_at: expStr,
                    cookie_generated_at: genStr,
                    source_worker: sourceName
                };
            };

            const listData = [];

            // 1. as-cjbp live items for 144 & 1109
            if (cj144Res && cj144Res.ok) {
                const json = await cj144Res.json();
                const item = processItem(Array.isArray(json) ? json[0] : json, "as-cjbp", "Colors HD");
                if (item) listData.push(item);
            }
            if (cj1109Res && cj1109Res.ok) {
                const json = await cj1109Res.json();
                const item = processItem(Array.isArray(json) ? json[0] : json, "as-cjbp", "Star Sports 2 HD");
                if (item) listData.push(item);
            }

            // 2. as-test live items for 144 & 1109
            if (test144Res && test144Res.ok) {
                const json = await test144Res.json();
                const item = processItem(Array.isArray(json) ? json[0] : json, "as-test", "Colors HD");
                if (item) listData.push(item);
            }
            if (test1109Res && test1109Res.ok) {
                const json = await test1109Res.json();
                const item = processItem(Array.isArray(json) ? json[0] : json, "as-test", "Star Sports 2 HD");
                if (item) listData.push(item);
            }

            // 3. as-brobp (jtvplus) for 144 & 1109
            if (jtvPlusRes && jtvPlusRes.ok) {
                const jpList = await jtvPlusRes.json();
                if (Array.isArray(jpList)) {
                    targetIds.forEach(targetId => {
                        const raw = jpList.find(c => String(c.id || c.ssid) === targetId);
                        if (raw) {
                            const item = processItem(raw, "as-brobp (jtvplus)", targetId === "144" ? "Colors HD" : "Star Sports 2 HD");
                            if (item) listData.push(item);
                        }
                    });
                }
            }

            // 4. as-brobp (jtv) for 144 & 1109
            if (jtvRes && jtvRes.ok) {
                const jList = await jtvRes.json();
                if (Array.isArray(jList)) {
                    targetIds.forEach(targetId => {
                        const raw = jList.find(c => String(c.id || c.ssid) === targetId);
                        if (raw) {
                            const item = processItem(raw, "as-brobp (jtv)", targetId === "144" ? "Colors HD" : "Star Sports 2 HD");
                            if (item) listData.push(item);
                        }
                    });
                }
            }

            return new Response(JSON.stringify(listData), {
                headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Set-Cookie": "__sz_admin_pass=admin@123; Path=/; HttpOnly; Secure; SameSite=Lax" }
            });
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), {
                headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
            });
        }
    }

    if (action === "dry_run") {
        const testTargets = [
            { source: "as-cksbp", name: "Willow Cricket HLS", url: "https://as-cksbp.rabba.workers.dev/?id=willowhls" },
            { source: "as-cxfiosbp", name: "iOS Stream (Willow)", url: "https://as-cxfiosbp.rabba.workers.dev/?id=S2" },
            { source: "as-brobp (jtv)", name: "Sony Ten 1 HD (Jio)", url: "https://as-brobp.rabba.workers.dev/?id=Ten_HD_MOB" },
            { source: "as-brobp (jtvplus)", name: "Star Sports Select 1", url: "https://as-brobp.rabba.workers.dev/?id=Star_Sports_Select_HD_1_BTS" },
            { source: "as-cjbp", name: "Sports Channel (as-cjbp)", url: "https://as-cjbp.yinave4095.workers.dev/?id=1106" },
            { source: "as-test", name: "Test Endpoint", url: "https://as-test.rabba.workers.dev/?id=1106" }
        ];

        const results = await Promise.all(testTargets.map(async (t) => {
            const startTime = Date.now();
            try {
                const res = await fetch(t.url, {
                    headers: { "User-Agent": "Cloudflare-Worker" },
                    cf: { cacheTtl: 0, cacheEverything: false }
                });
                const latencyMs = Date.now() - startTime;
                let streamUrl = "";
                let hasCookie = false;
                if (res.ok) {
                    try {
                        const json = await res.json();
                        const item = Array.isArray(json) ? json[0] : json;
                        if (item) {
                            streamUrl = item.mpd || item.url || item.streamUrl || "";
                            hasCookie = !!(item.cookie || item.token || item.key);
                        }
                    } catch (e) { }
                }

                let streamStatus = res.status;
                let streamOk = res.ok;

                if (streamUrl && streamUrl.startsWith("http")) {
                    try {
                        const sHead = await fetch(streamUrl, {
                            method: "HEAD",
                            headers: { "User-Agent": "Mozilla/5.0" }
                        });
                        streamStatus = sHead.status;
                        streamOk = sHead.ok || sHead.status === 200 || sHead.status === 206 || sHead.status === 302;
                    } catch (e) { }
                }

                return {
                    source: t.source,
                    name: t.name,
                    workerUrl: t.url,
                    streamUrl: streamUrl,
                    hasCookie: hasCookie,
                    status: streamStatus,
                    ok: streamOk,
                    latencyMs: latencyMs
                };
            } catch (e) {
                return {
                    source: t.source,
                    name: t.name,
                    workerUrl: t.url,
                    streamUrl: "",
                    hasCookie: false,
                    status: 500,
                    ok: false,
                    latencyMs: Date.now() - startTime,
                    error: e.message
                };
            }
        }));

        const totalPass = results.filter(r => r.ok).length;
        const totalFail = results.length - totalPass;

        return new Response(JSON.stringify({
            timestamp: new Date().toISOString(),
            summary: { total: results.length, pass: totalPass, fail: totalFail },
            results: results
        }), {
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Set-Cookie": "__sz_admin_pass=admin@123; Path=/; HttpOnly; Secure; SameSite=Lax" }
        });
    }

    if (action === "create" || (request.method === "POST" && bodyData.title && bodyData.ssid)) {
        const title = (bodyData.title || url.searchParams.get("title") || "").trim();
        const ssid = (bodyData.ssid || url.searchParams.get("ssid") || "").trim();
        const streamUrl = (bodyData.streamUrl || url.searchParams.get("streamUrl") || "").trim();
        const keys = (bodyData.keys || bodyData.key || url.searchParams.get("keys") || url.searchParams.get("key") || "").trim();
        const cookie = (bodyData.cookie || bodyData.token || url.searchParams.get("cookie") || url.searchParams.get("token") || "").trim();
        const streamType = bodyData.streamType || url.searchParams.get("streamType");
        let isHls = false;
        let isMpd = false;
        if (streamType === "hls") {
            isHls = true;
        } else if (streamType === "mpd") {
            isMpd = true;
        } else {
            const rawHls = bodyData.isHls ?? url.searchParams.get("isHls");
            const rawMpd = bodyData.isMpd ?? url.searchParams.get("isMpd");
            if (rawHls === "true" || rawHls === true || rawHls === "on") {
                isHls = true;
                isMpd = false;
            } else if (rawMpd === "true" || rawMpd === true || rawMpd === "on") {
                isHls = false;
                isMpd = true;
            } else {
                isHls = streamUrl.includes(".m3u8");
                isMpd = streamUrl.includes(".mpd");
            }
        }

        if (title && ssid && streamUrl) {
            try {
                const fbPostRes = await fetch(FIREBASE_CUSTOM_URL, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        fields: {
                            title: { stringValue: title },
                            ssid: { stringValue: ssid },
                            streamUrl: { stringValue: streamUrl },
                            keys: { stringValue: keys },
                            cookie: { stringValue: cookie },
                            isHls: { booleanValue: !!isHls },
                            isMpd: { booleanValue: !!isMpd },
                            status: { stringValue: "Live" },
                            createdAt: { stringValue: new Date().toISOString() }
                        }
                    })
                });

                if (request.headers.get("Accept")?.includes("application/json")) {
                    return new Response(JSON.stringify({ success: fbPostRes.ok, status: fbPostRes.status }), {
                        headers: { "Content-Type": "application/json", "Set-Cookie": "__sz_admin_pass=admin@123; Path=/; HttpOnly; Secure; SameSite=Lax" }
                    });
                }
            } catch (e) {
                console.error("Error creating match in Firestore", e);
            }
        }
    } else if (action === "delete") {
        const docId = bodyData.docId || url.searchParams.get("docId");
        if (docId) {
            try {
                const deleteUrl = `https://firestore.googleapis.com/v1/projects/sports-zone-ed3a9/databases/(default)/documents/fanxzone_custom/${encodeURIComponent(docId)}?key=${FIREBASE_API_KEY}`;
                await fetch(deleteUrl, { method: "DELETE" });
                if (request.headers.get("Accept")?.includes("application/json")) {
                    return new Response(JSON.stringify({ success: true }), {
                        headers: { "Content-Type": "application/json", "Set-Cookie": "__sz_admin_pass=admin@123; Path=/; HttpOnly; Secure; SameSite=Lax" }
                    });
                }
            } catch (e) {
                console.error("Error deleting match in Firestore", e);
            }
        }
    }

    let matchesList = [];
    try {
        const fbRes = await fetch(FIREBASE_CUSTOM_URL, { cf: { cacheTtl: 0, cacheEverything: false } });
        if (fbRes.ok) {
            const fbData = await fbRes.json();
            if (fbData.documents) {
                const timeBlock = Math.floor(Date.now() / (1000 * 60 * 60 * 24));
                for (const doc of fbData.documents) {
                    const docId = doc.name ? doc.name.split('/').pop() : "";
                    const fields = doc.fields || {};
                    const title = fields.title ? fields.title.stringValue : "";
                    const ssid = fields.ssid ? fields.ssid.stringValue : "";
                    const streamUrl = fields.streamUrl ? fields.streamUrl.stringValue : "";
                    const keys = fields.keys ? fields.keys.stringValue : "";
                    const cookie = fields.cookie ? fields.cookie.stringValue : "";
                    const isHls = fields.isHls ? (typeof fields.isHls.booleanValue === 'boolean' ? fields.isHls.booleanValue : fields.isHls.stringValue === "true") : streamUrl.includes(".m3u8");
                    const createdAt = fields.createdAt ? fields.createdAt.stringValue : (doc.createTime || "");

                    let playUrl = "";
                    if (ssid) {
                        const dataToSign = `${domain}|${timeBlock}|${ssid}|unknown`;
                        const token = await generateHMAC(dataToSign, SECRET_KEY);
                        playUrl = `https://${domain}/?id=${encodeURIComponent(ssid)}&token=${token}`;
                    }

                    matchesList.push({
                        docId, title, ssid, streamUrl, keys, cookie, isHls, createdAt, playUrl
                    });
                }
            }
        }
    } catch (e) {
        console.error("Error fetching matches for admin page", e);
    }

    const page = Math.max(1, parseInt(url.searchParams.get("page") || "1", 10));
    const pageSize = 10;
    const totalMatches = matchesList.length;
    const totalPages = Math.ceil(totalMatches / pageSize) || 1;
    const currentPage = Math.min(page, totalPages);

    const startIndex = (currentPage - 1) * pageSize;
    const paginatedMatches = matchesList.slice(startIndex, startIndex + pageSize);

    let rowsHtml = "";
    if (paginatedMatches.length === 0) {
        rowsHtml = `<tr><td colspan="7" style="text-align:center; padding: 24px; color: #64748b;">No matches created yet in fanxzone_custom table.</td></tr>`;
    } else {
        for (const m of paginatedMatches) {
            rowsHtml += `
            <tr style="border-bottom: 1px solid #1e293b;">
              <td style="padding: 12px; font-weight: 600; color: #f8fafc; font-size: 13px;">${escapeHtml(m.title)}</td>
              <td style="padding: 12px; color: #38bdf8; font-family: monospace; font-weight: 600; white-space: nowrap; font-size: 13px;">${escapeHtml(m.ssid)}</td>
              <td style="padding: 12px; color: #cbd5e1; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px;">${escapeHtml(m.streamUrl)}</td>
              <td style="padding: 12px; color: #94a3b8; font-family: monospace; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px;">${escapeHtml(m.keys || '-')}</td>
              <td style="padding: 12px; color: #94a3b8; max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px;">${escapeHtml(m.cookie || '-')}</td>
              <td style="padding: 12px; white-space: nowrap;"><span style="background: ${m.isHls ? '#065f46; color: #34d399' : '#1e3a8a; color: #60a5fa'}; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; display: inline-block; white-space: nowrap;">${m.isHls ? 'HLS' : 'MPD'}</span></td>
              <td style="padding: 12px; white-space: nowrap;">
                <div style="display: flex; gap: 6px; align-items: center; flex-wrap: nowrap;">
                  <button onclick="openIframeModal('${escapeHtml(m.ssid)}', '${m.playUrl}')" style="background: #0284c7; color: #fff; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; transition: background 0.2s; white-space: nowrap;">🖼️ iFrame</button>
                  <button onclick="deleteMatch('${m.docId}', '${escapeHtml(m.title)}')" style="background: #dc2626; color: #fff; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; transition: background 0.2s; white-space: nowrap;">🗑️ Delete</button>
                </div>
              </td>
            </tr>`;
        }
    }

    let paginationHtml = "";
    if (totalPages > 1) {
        paginationHtml = `<div style="display: flex; justify-content: space-between; align-items: center; margin-top: 18px; padding-top: 14px; border-top: 1px solid #1e293b;">
            <div style="font-size: 13px; color: #94a3b8;">Showing ${startIndex + 1} - ${Math.min(startIndex + pageSize, totalMatches)} of ${totalMatches} matches</div>
            <div style="display: flex; gap: 6px;">`;

        if (currentPage > 1) {
            paginationHtml += `<a href="/api/get/admin?page=${currentPage - 1}" style="background: #1e293b; color: #38bdf8; padding: 6px 12px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 600;">← Previous</a>`;
        }

        for (let p = 1; p <= totalPages; p++) {
            const activeStyle = p === currentPage ? "background: #0284c7; color: #fff;" : "background: #1e293b; color: #94a3b8;";
            paginationHtml += `<a href="/api/get/admin?page=${p}" style="${activeStyle} padding: 6px 12px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 600;">${p}</a>`;
        }

        if (currentPage < totalPages) {
            paginationHtml += `<a href="/api/get/admin?page=${currentPage + 1}" style="background: #1e293b; color: #38bdf8; padding: 6px 12px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 600;">Next →</a>`;
        }

        paginationHtml += `</div></div>`;
    }

    const dashboardHtml = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FanxZone Match Stream Admin</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }
body { background: #0b0f19; color: #f8fafc; padding: clamp(8px, 3vw, 24px); min-height: 100vh; font-size: clamp(12px, 2.5vw, 15px); word-break: break-word; }
.container { max-width: 1100px; width: 100%; margin: 0 auto; }
.header { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; margin-bottom: clamp(16px, 3vw, 24px); padding-bottom: 12px; border-bottom: 1px solid #1e293b; gap: 10px; }
.title { font-size: clamp(16px, 4vw, 26px); font-weight: 700; color: #38bdf8; display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.badge { background: #0284c7; color: #fff; font-size: clamp(10px, 2vw, 12px); padding: 4px 8px; border-radius: 12px; font-weight: 600; white-space: nowrap; }
.sub-tabs { display: flex; flex-wrap: wrap; gap: clamp(6px, 2vw, 12px); margin-bottom: clamp(16px, 3vw, 24px); border-bottom: 1px solid #1e293b; padding-bottom: 12px; }
.tab-btn { background: #161e2e; color: #94a3b8; border: 1px solid #233044; padding: clamp(8px, 2vw, 10px) clamp(10px, 2.5vw, 20px); border-radius: clamp(4px, 1.5vw, 8px); font-size: clamp(11px, 2.5vw, 15px); font-weight: 600; cursor: pointer; transition: all 0.2s; white-space: nowrap; display: inline-flex; align-items: center; justify-content: center; gap: 6px; -webkit-tap-highlight-color: transparent; }
.tab-btn.active { background: #0284c7; color: #fff; border-color: #0284c7; }
.card { background: #161e2e; border-radius: clamp(8px, 2vw, 14px); padding: clamp(12px, 3vw, 24px); margin-bottom: clamp(16px, 3vw, 28px); border: 1px solid #233044; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.3); }
.card-title { font-size: clamp(13px, 3vw, 18px); font-weight: 600; color: #f1f5f9; margin-bottom: clamp(12px, 2.5vw, 18px); border-bottom: 1px solid #1e293b; padding-bottom: 8px; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 8px; }
.form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(clamp(140px, 45vw, 300px), 1fr)); gap: clamp(10px, 2.5vw, 18px); margin-bottom: 18px; }
.input-group { display: flex; flex-direction: column; gap: 4px; }
.full-width-input { grid-column: span 2; }
label { font-size: clamp(10px, 2.2vw, 13px); color: #94a3b8; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
input[type="text"], textarea { background: #0b0f19; border: 1px solid #233044; border-radius: clamp(4px, 1.5vw, 8px); padding: clamp(6px, 2vw, 10px) clamp(8px, 2vw, 14px); color: #fff; font-size: clamp(11px, 2.5vw, 14px); outline: none; transition: border-color 0.2s; width: 100%; }
input[type="text"]:focus, textarea:focus { border-color: #38bdf8; }
.checkbox-group { display: flex; align-items: center; gap: 8px; margin-top: 6px; cursor: pointer; font-size: clamp(11px, 2.2vw, 13px); }
.checkbox-group input { width: clamp(14px, 3vw, 18px); height: clamp(14px, 3vw, 18px); accent-color: #38bdf8; cursor: pointer; }
.btn-submit { background: linear-gradient(135deg, #0284c7, #2563eb); color: #fff; border: none; padding: clamp(8px, 2vw, 12px) clamp(12px, 2.5vw, 24px); border-radius: clamp(4px, 1.5vw, 8px); font-size: clamp(11px, 2.5vw, 15px); font-weight: 600; cursor: pointer; transition: opacity 0.2s; white-space: nowrap; display: inline-flex; align-items: center; justify-content: center; gap: 6px; -webkit-tap-highlight-color: transparent; }
.btn-submit:hover { opacity: 0.9; }
.table-responsive { width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; }
table { width: 100%; border-collapse: collapse; text-align: left; min-width: 200px; }
th { padding: clamp(6px, 2vw, 12px); color: #64748b; font-size: clamp(10px, 2vw, 12px); font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #1e293b; white-space: nowrap; }
td { padding: clamp(6px, 2vw, 12px); font-size: clamp(11px, 2.2vw, 14px); }
.modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.8); z-index: 99999; align-items: center; justify-content: center; padding: clamp(8px, 3vw, 20px); }
.modal-card { background: #161e2e; border: 1px solid #334155; border-radius: clamp(8px, 2vw, 16px); width: 100%; max-width: 650px; max-height: 90vh; overflow-y: auto; padding: clamp(14px, 3vw, 28px); box-shadow: 0 25px 50px -12px rgba(0,0,0,0.7); }
@media (max-width: 600px) {
  .full-width-input { grid-column: span 1 !important; }
  .form-actions-row { flex-direction: column; align-items: stretch !important; gap: 12px; }
  .btn-submit { width: 100%; }
  .sub-tabs { flex-direction: column; }
  .tab-btn { width: 100%; text-align: center; }
  #cron-search { width: 100% !important; margin-top: 8px; }
}
@media (max-width: 300px) {
  body { padding: 4px; }
  .card { padding: 8px; }
  th, td { padding: 4px; font-size: 10px; }
  .badge { font-size: 9px; padding: 2px 4px; }
  .btn-submit, .tab-btn { padding: 6px 8px; font-size: 10px; }
}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="title">⚡ FanxZone Admin <span class="badge">Firebase: fanxzone_custom</span></div>
  </div>

  <div class="sub-tabs">
    <button id="tab-btn-matches" onclick="switchTab('matches')" class="tab-btn active">📺 Matches Management</button>
    <button id="tab-btn-cron" onclick="switchTab('cron')" class="tab-btn">⏰ Cron & Cookie Update</button>
  </div>

  <div id="tab-content-matches">
    <div class="card">
      <div class="card-title">➕ Create New Stream Match</div>
      <form method="POST" action="/api/get/admin">
        <input type="hidden" name="action" value="create">
        <div class="form-grid">
          <div class="input-group">
            <label>Match Title</label>
            <input type="text" name="title" placeholder="e.g. IND vs PAK T20 Live" required>
          </div>
          <div class="input-group">
            <label>Fixed SSID (Channel ID)</label>
            <input type="text" name="ssid" placeholder="e.g. fz1 or star1" required>
          </div>
          <div class="input-group full-width-input">
            <label>Stream URL</label>
            <input type="text" name="streamUrl" placeholder="e.g. https://domain.com/live/index.m3u8" required>
          </div>
          <div class="input-group">
            <label>Keys (DRM keyId:key)</label>
            <input type="text" name="keys" placeholder="e.g. 1234567890abcdef:fedcba0987654321">
          </div>
          <div class="input-group">
            <label style="display: flex; align-items: center; justify-content: space-between;">
              <span>Cookie / Authorization Token</span>
              <span onclick="showCookieFormatModal()" style="cursor: pointer; display: inline-flex; align-items: center; justify-content: center; width: 18px; height: 18px; border-radius: 50%; background: #0284c7; color: #fff; font-size: 11px; font-weight: bold;" title="Click to view supported cookie formats" onmouseover="this.style.transform='scale(1.15)'" onmouseout="this.style.transform='scale(1)'">ℹ</span>
            </label>
            <input type="text" name="cookie" placeholder="e.g. hdnea=st=... or Bearer token">
          </div>
        </div>
        <div class="form-actions-row" style="display: flex; justify-content: space-between; align-items: center; margin-top: 10px;">
          <div style="display: flex; align-items: center; gap: 18px; flex-wrap: wrap;">
            <span style="font-size: 12px; color: #94a3b8; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">Stream Format:</span>
            <label class="checkbox-group">
              <input type="checkbox" id="chk-hls" name="isHls" value="true" checked onclick="selectStreamType('hls')">
              <span>HLS (.m3u8)</span>
            </label>
            <label class="checkbox-group">
              <input type="checkbox" id="chk-mpd" name="isMpd" value="true" onclick="selectStreamType('mpd')">
              <span>MPD (.mpd)</span>
            </label>
          </div>
          <button type="submit" class="btn-submit">🚀 Create Match</button>
        </div>
      </form>
    </div>

    <div class="card">
      <div class="card-title">📺 Created Matches (${totalMatches})</div>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>Title</th>
              <th>SSID</th>
              <th>Stream URL</th>
              <th>Keys</th>
              <th>Cookie</th>
              <th>Type</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${rowsHtml}
          </tbody>
        </table>
      </div>
      ${paginationHtml}
    </div>
  </div>

  <div id="tab-content-cron" style="display: none;">
    <div class="card">
      <div class="card-title" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
        <span>⏰ Multi-Worker Cron & Cookie Manager</span>
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          <button id="btn-update-st" onclick="runStWorkerUpdate()" class="btn-submit" style="padding: 8px 16px; font-size: 13px; background: linear-gradient(135deg, #0284c7, #2563eb);">⚡ Update ST Worker</button>
          <button id="btn-run-dryrun" onclick="runDryRunTest()" class="btn-submit" style="padding: 8px 16px; font-size: 13px; background: linear-gradient(135deg, #059669, #10b981);">🧪 Run Live Stream Dry Run</button>
        </div>
      </div>
      <p style="font-size: 14px; color: #94a3b8; margin-bottom: 12px;">Trigger multi-worker cookie update endpoint, run live stream dry-run simulations across worker pools, and inspect aggregated channel cookies.</p>
      <div id="cron-status-box"></div>
      <div id="dryrun-results-box" style="display: none; margin-top: 14px;"></div>
    </div>

    <div class="card">
      <div class="card-title" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
        <span>🔑 Aggregated Channel Cookies Across Workers</span>
        <div style="display: flex; gap: 6px; flex-wrap: wrap;">
          <button id="cron-subtab-all" onclick="setCronCategory('all')" style="background: #0284c7; color: #fff; border: 1px solid #0284c7; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600;">All (2-3/type)</button>
          <button id="cron-subtab-jp" onclick="setCronCategory('jp')" style="background: #1e293b; color: #94a3b8; border: 1px solid #334155; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600;">JP (JioTV Plus)</button>
          <button id="cron-subtab-j" onclick="setCronCategory('j')" style="background: #1e293b; color: #94a3b8; border: 1px solid #334155; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600;">J (JioTV)</button>
          <button id="cron-subtab-cj" onclick="setCronCategory('cj')" style="background: #1e293b; color: #94a3b8; border: 1px solid #334155; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600;">CJ (CJBP)</button>
          <button id="cron-subtab-st" onclick="setCronCategory('st')" style="background: #1e293b; color: #94a3b8; border: 1px solid #334155; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600;">ST (Star Sports)</button>
          <button id="cron-subtab-normal" onclick="setCronCategory('normal')" style="background: #1e293b; color: #94a3b8; border: 1px solid #334155; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600;">Normal</button>
        </div>
      </div>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>Worker Source</th>
              <th>SSID / ID</th>
              <th>Channel Name</th>
              <th>Expires At</th>
              <th>Cookie Generated At</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="cron-table-body">
            <tr><td colspan="6" style="text-align:center; padding: 20px; color: #94a3b8;">Click "Run Cron Update" or "Run Live Stream Dry Run" to fetch multi-worker channels.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<div id="cookie-modal" class="modal-overlay">
  <div class="modal-card">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h3 id="modal-title" style="color: #38bdf8; font-size: 18px;">Channel Cookie Details</h3>
      <button onclick="closeCookieModal()" style="background: transparent; border: none; color: #94a3b8; font-size: 20px; cursor: pointer;">✖</button>
    </div>
    <div style="margin-bottom: 16px;">
      <label style="display: block; margin-bottom: 6px;">Updated Cookie Token</label>
      <div style="position: relative;">
        <pre id="modal-cookie" style="background: #0b0f19; border: 1px solid #334155; padding: 12px; border-radius: 8px; color: #34d399; font-size: 12px; white-space: pre-wrap; word-break: break-all; max-height: 140px; overflow-y: auto;"></pre>
        <button onclick="copyModalCookie()" style="position: absolute; top: 8px; right: 8px; background: #0284c7; color: #fff; border: none; padding: 4px 8px; border-radius: 4px; font-size: 11px; cursor: pointer;">📋 Copy</button>
      </div>
    </div>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 16px;">
      <div>
        <label>Expires At</label>
        <div id="modal-expiry" style="color: #f8fafc; font-size: 14px; margin-top: 4px; font-weight: 500;"></div>
      </div>
      <div>
        <label>Cookie Generated At</label>
        <div id="modal-gen" style="color: #f8fafc; font-size: 14px; margin-top: 4px; font-weight: 500;"></div>
      </div>
    </div>
    <div style="margin-bottom: 20px;">
      <label>Stream URL</label>
      <div id="modal-url" style="color: #94a3b8; font-size: 12px; font-family: monospace; word-break: break-all; margin-top: 4px;"></div>
    </div>
    <div style="text-align: right;">
      <button onclick="closeCookieModal()" style="background: #334155; color: #fff; border: none; padding: 8px 18px; border-radius: 6px; cursor: pointer; font-weight: 600;">Close</button>
    </div>
  </div>
</div>

<div id="iframe-modal" class="modal-overlay">
  <div class="modal-card">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h3 id="iframe-modal-title" style="color: #38bdf8; font-size: 18px;">Embed iFrame Code</h3>
      <button onclick="closeIframeModal()" style="background: transparent; border: none; color: #94a3b8; font-size: 20px; cursor: pointer;">✖</button>
    </div>
    <div style="margin-bottom: 16px;">
      <label style="display: block; margin-bottom: 6px; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 12px;">🌐 Select Authorized Domain for iFrame</label>
      <select id="iframe-domain-select" onchange="updateIframeCodeForSelectedDomain()" style="width: 100%; background: #0b0f19; border: 1px solid #334155; border-radius: 8px; padding: 10px 14px; color: #38bdf8; font-size: 14px; font-weight: 600; outline: none; cursor: pointer;">
      </select>
    </div>
    <div style="margin-bottom: 16px;">
      <label style="display: block; margin-bottom: 6px; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 12px;">HTML iFrame Embed Code</label>
      <div style="position: relative;">
        <pre id="iframe-code-text" style="background: #0b0f19; border: 1px solid #334155; padding: 14px; border-radius: 8px; color: #38bdf8; font-size: 13px; font-family: monospace; white-space: pre-wrap; word-break: break-all; max-height: 140px; overflow-y: auto;"></pre>
        <button onclick="copyIframeCodeText()" style="position: absolute; top: 8px; right: 8px; background: #0284c7; color: #fff; border: none; padding: 6px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; cursor: pointer;">📋 Copy Code</button>
      </div>
    </div>
    <div style="background: #1e293b; border-left: 4px solid #38bdf8; padding: 12px; border-radius: 6px; font-size: 13px; color: #cbd5e1; margin-bottom: 20px;">
      🛡️ <strong>Authorized Domain Protection Active:</strong><br>
      This stream iframe will only play when embedded inside the selected authorized domain. Direct address bar navigation to the raw iframe URL is automatically blocked with 403 Forbidden.
    </div>
    <div style="text-align: right;">
      <button onclick="closeIframeModal()" style="background: #334155; color: #fff; border: none; padding: 8px 18px; border-radius: 6px; cursor: pointer; font-weight: 600;">Close</button>
    </div>
  </div>
</div>

<div id="cookie-format-info-modal" class="modal-overlay">
  <div class="modal-card" style="max-width: 580px;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid #334155; padding-bottom: 12px;">
      <h3 style="color: #38bdf8; font-size: 18px; display: flex; align-items: center; gap: 8px;">ℹ️ Supported Cookie & Token Formats</h3>
      <button onclick="closeCookieFormatModal()" style="background: transparent; border: none; color: #94a3b8; font-size: 20px; cursor: pointer;">✖</button>
    </div>
    <div style="font-size: 13px; color: #cbd5e1; line-height: 1.6; max-height: 380px; overflow-y: auto; padding-right: 6px;">
      
      <div style="margin-bottom: 14px; background: #0b0f19; padding: 12px; border-radius: 8px; border: 1px solid #233044;">
        <strong style="color: #38bdf8; display: block; margin-bottom: 4px;">1. JioTV / Akamai 'hdnea' Token</strong>
        <span style="color: #94a3b8;">Used for JioTV, JioTV+, and Akamai CDN streams. Automatically injected into all segment requests.</span>
        <code style="display: block; background: #161e2e; padding: 6px 10px; border-radius: 6px; color: #34d399; font-family: monospace; font-size: 11px; margin-top: 6px; word-break: break-all;">hdnea=st=1700000000~exp=1700086400~acl=/*~hmac=abcdef...</code>
        <code style="display: block; background: #161e2e; padding: 6px 10px; border-radius: 6px; color: #34d399; font-family: monospace; font-size: 11px; margin-top: 4px; word-break: break-all;">__hdnea__=st=1700000000~exp=1700086400~acl=/*~hmac=abcdef...</code>
      </div>

      <div style="margin-bottom: 14px; background: #0b0f19; padding: 12px; border-radius: 8px; border: 1px solid #233044;">
        <strong style="color: #38bdf8; display: block; margin-bottom: 4px;">2. Standard HTTP Cookie Header</strong>
        <span style="color: #94a3b8;">Multiple key-value pairs separated by semicolons for CloudFront or custom auth nodes.</span>
        <code style="display: block; background: #161e2e; padding: 6px 10px; border-radius: 6px; color: #34d399; font-family: monospace; font-size: 11px; margin-top: 6px; word-break: break-all;">CloudFront-Key-Pair-Id=K12345; CloudFront-Signature=...; CloudFront-Policy=...</code>
      </div>

      <div style="margin-bottom: 14px; background: #0b0f19; padding: 12px; border-radius: 8px; border: 1px solid #233044;">
        <strong style="color: #38bdf8; display: block; margin-bottom: 4px;">3. Bearer Authorization Token</strong>
        <span style="color: #94a3b8;">Standard OAuth / JWT tokens for API authorized streams.</span>
        <code style="display: block; background: #161e2e; padding: 6px 10px; border-radius: 6px; color: #34d399; font-family: monospace; font-size: 11px; margin-top: 6px; word-break: break-all;">Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6...</code>
      </div>

      <div style="background: #0b0f19; padding: 12px; border-radius: 8px; border: 1px solid #233044;">
        <strong style="color: #38bdf8; display: block; margin-bottom: 4px;">4. Raw Token Parameter</strong>
        <span style="color: #94a3b8;">Plain token string appended directly to manifest and media segment URLs.</span>
        <code style="display: block; background: #161e2e; padding: 6px 10px; border-radius: 6px; color: #34d399; font-family: monospace; font-size: 11px; margin-top: 6px; word-break: break-all;">st=1700000000~exp=1700086400~acl=/*~hmac=abcdef...</code>
      </div>

    </div>
    <div style="text-align: right; margin-top: 16px;">
      <button onclick="closeCookieFormatModal()" style="background: #0284c7; color: #fff; border: none; padding: 8px 20px; border-radius: 6px; cursor: pointer; font-weight: 600;">Got It!</button>
    </div>
  </div>
</div>

<script>
function showCookieFormatModal() {
  document.getElementById('cookie-format-info-modal').style.display = 'flex';
}

function closeCookieFormatModal() {
  document.getElementById('cookie-format-info-modal').style.display = 'none';
}

function switchTab(tabName) {
  document.getElementById('tab-content-matches').style.display = tabName === 'matches' ? 'block' : 'none';
  document.getElementById('tab-content-cron').style.display = tabName === 'cron' ? 'block' : 'none';
  
  const matchesBtn = document.getElementById('tab-btn-matches');
  const cronBtn = document.getElementById('tab-btn-cron');
  
  if (tabName === 'matches') {
    matchesBtn.classList.add('active');
    cronBtn.classList.remove('active');
  } else {
    cronBtn.classList.add('active');
    matchesBtn.classList.remove('active');
    if (cronChannelsData.length === 0) {
      loadCronChannels();
    }
  }
}

let cronChannelsData = [];

async function runStWorkerUpdate() {
  const statusBox = document.getElementById('cron-status-box');
  const updateBtn = document.getElementById('btn-update-st');
  updateBtn.disabled = true;
  updateBtn.innerText = '⏳ Updating ST Worker...';
  statusBox.innerHTML = '<div style="color: #38bdf8; font-size: 14px; padding: 8px 0;">🔄 Contacting ST worker update endpoint (as-stflx)...</div>';

  try {
    const res = await fetch('/api/get/admin?action=cron_update_st', {
      headers: { 'Accept': 'application/json' }
    });
    const data = await res.json();
    if (data && (data.success || data.message)) {
      statusBox.innerHTML = '<div style="background: #065f46; color: #34d399; padding: 12px; border-radius: 8px; margin-top: 10px; font-size: 14px;">' +
        '✅ <strong>' + (data.message || 'ST Worker updated successfully') + '</strong><br>' +
        '📅 Last Updated: ' + (data.updated_at || 'Just now') +
        '</div>';
      await loadCronChannels();
    } else {
      statusBox.innerHTML = '<div style="background: #7f1d1d; color: #fca5a5; padding: 12px; border-radius: 8px; margin-top: 10px;">❌ Failed to update ST worker cache.</div>';
    }
  } catch (e) {
    statusBox.innerHTML = '<div style="background: #7f1d1d; color: #fca5a5; padding: 12px; border-radius: 8px; margin-top: 10px;">❌ Error: ' + e.message + '</div>';
  } finally {
    updateBtn.disabled = false;
    updateBtn.innerText = '⚡ Update ST Worker';
  }
}

async function runDryRunTest() {
  const box = document.getElementById('dryrun-results-box');
  const btn = document.getElementById('btn-run-dryrun');
  box.style.display = 'block';
  btn.disabled = true;
  btn.innerText = '⏳ Running Dry Run...';
  box.innerHTML = '<div style="color: #38bdf8; padding: 14px; background: #0b0f19; border-radius: 8px; border: 1px solid #334155;">⚡ Executing live dry run simulation across all worker pools (as-cjbp, as-brobp, as-cksbp, as-cxfiosbp, as-test)...</div>';

  try {
    const res = await fetch('/api/get/admin?action=dry_run', { headers: { 'Accept': 'application/json' } });
    const data = await res.json();
    
    let html = '<div style="background: #161e2e; padding: 16px; border-radius: 12px; border: 1px solid #233044;">' +
      '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:8px;">' +
        '<span style="font-weight:700; color:#38bdf8; font-size:15px;">📊 Live Worker & Stream Dry Run Summary</span>' +
        '<span style="font-size:12px; color:#94a3b8;">Tested At: ' + new Date(data.timestamp).toLocaleTimeString() + '</span>' +
      '</div>' +
      '<div style="display:flex; gap:12px; margin-bottom:14px; flex-wrap:wrap;">' +
        '<span style="background:#065f46; color:#34d399; padding:4px 12px; border-radius:20px; font-weight:700; font-size:12px;">✅ Passing: ' + data.summary.pass + '</span>' +
        '<span style="background:#7f1d1d; color:#fca5a5; padding:4px 12px; border-radius:20px; font-weight:700; font-size:12px;">❌ Failing: ' + data.summary.fail + '</span>' +
        '<span style="background:#1e293b; color:#94a3b8; padding:4px 12px; border-radius:20px; font-weight:700; font-size:12px;">Total Pool: ' + data.summary.total + '</span>' +
      '</div>' +
      '<div style="overflow-x:auto;">' +
        '<table style="width:100%; border-collapse:collapse; font-size:12px;">' +
          '<thead><tr style="border-bottom:1px solid #334155; color:#94a3b8; text-align:left;">' +
            '<th style="padding:8px;">Worker Source</th>' +
            '<th style="padding:8px;">Test Stream Name</th>' +
            '<th style="padding:8px;">Latency</th>' +
            '<th style="padding:8px;">Cookie Token</th>' +
            '<th style="padding:8px;">Stream Health</th>' +
          '</tr></thead><tbody>';

    data.results.forEach(r => {
      const badgeStyle = r.ok ? 'background:#065f46; color:#34d399;' : 'background:#7f1d1d; color:#fca5a5;';
      const badgeText = r.ok ? '✅ HTTP ' + r.status + ' (ONLINE)' : '❌ HTTP ' + r.status + ' (FAIL/EXPIRED)';
      const cookieBadge = r.hasCookie ? '<span style="color:#34d399; font-weight:600;">🔑 Active</span>' : '<span style="color:#94a3b8;">⚪ None</span>';
      
      html += '<tr style="border-bottom:1px solid #233044;">' +
        '<td style="padding:8px; font-weight:700; color:#38bdf8; white-space:nowrap;">' + r.source + '</td>' +
        '<td style="padding:8px; color:#f8fafc;">' + r.name + '</td>' +
        '<td style="padding:8px; color:#cbd5e1; white-space:nowrap;">⚡ ' + r.latencyMs + 'ms</td>' +
        '<td style="padding:8px; white-space:nowrap;">' + cookieBadge + '</td>' +
        '<td style="padding:8px; white-space:nowrap;"><span style="padding:3px 8px; border-radius:4px; font-weight:600; ' + badgeStyle + '">' + badgeText + '</span></td>' +
      '</tr>';
    });

    html += '</tbody></table></div></div>';
    box.innerHTML = html;
  } catch (e) {
    box.innerHTML = '<div style="background: #7f1d1d; color: #fca5a5; padding: 12px; border-radius: 8px;">❌ Dry run failed: ' + e.message + '</div>';
  } finally {
    btn.disabled = false;
    btn.innerText = '🧪 Run Live Stream Dry Run';
  }
}

async function loadCronChannels() {
  const tbody = document.getElementById('cron-table-body');
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 20px; color: #94a3b8;">⏳ Aggregating channel cookies across all workers...</td></tr>';
  try {
    const res = await fetch('/api/get/admin?action=cron_list', {
      headers: { 'Accept': 'application/json' }
    });
    cronChannelsData = await res.json();
    renderCronChannels(cronChannelsData);
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 20px; color: #f87171;">Failed to load aggregated cron channel list.</td></tr>';
  }
}

let activeCronCategory = 'all';

function setCronCategory(cat) {
  activeCronCategory = cat;
  ['all', 'jp', 'j', 'cj', 'st', 'normal'].forEach(c => {
    const btn = document.getElementById('cron-subtab-' + c);
    if (btn) {
      if (c === cat) {
        btn.style.background = '#0284c7';
        btn.style.color = '#ffffff';
        btn.style.borderColor = '#0284c7';
      } else {
        btn.style.background = '#1e293b';
        btn.style.color = '#94a3b8';
        btn.style.borderColor = '#334155';
      }
    }
  });
  renderCronChannels(cronChannelsData);
}

function getChannelCategory(ch, idx) {
  const name = (ch.name || '').toLowerCase();
  const idStr = String(ch.id || idx).toLowerCase();
  if (idStr.startsWith('jp') || name.includes('jtvplus') || name.includes('jio plus') || ch.isJp) return 'jp';
  if (idStr.startsWith('j') || name.includes('jiotv') || name.includes('jio') || ch.isJio) return 'j';
  if (idStr.startsWith('cj') || name.includes('cjbp') || ch.isCj) return 'cj';
  if (idStr.startsWith('st') || name.includes('star sports') || name.includes('sports') || ch.isStar) return 'st';
  return 'normal';
}

function renderCronChannels(items) {
  const tbody = document.getElementById('cron-table-body');
  if (!items || items.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 20px; color: #64748b;">No channel cookies found across workers. Click "Run Cron Update" or "Run Live Stream Dry Run".</td></tr>';
    return;
  }

  const groups = { jp: [], j: [], cj: [], st: [], normal: [] };

  items.forEach((ch, idx) => {
    const cat = getChannelCategory(ch, idx);
    groups[cat].push({ ch, idx });
  });

  let selected = [];
  if (activeCronCategory === 'all') {
    items.forEach((ch, idx) => selected.push({ ch, idx }));
  } else {
    items.forEach((ch, idx) => {
      const cat = getChannelCategory(ch, idx);
      if (cat === activeCronCategory) selected.push({ ch, idx });
    });
  }

  if (selected.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 20px; color: #64748b;">No live tokens found for channel IDs 144 or 1109 in selected category.</td></tr>';
    return;
  }

  let html = '';
  selected.forEach(({ ch, idx }) => {
    const cat = getChannelCategory(ch, idx);
    const ssid = cat + '-' + (ch.id || idx);
    const expTime = ch.expires_at || (ch.expire_time ? new Date(parseInt(ch.expire_time) * 1000).toLocaleString() : 'N/A');
    const genTime = ch.cookie_generated_at || ch.cookiegenerate_at || (ch.created_at ? new Date(ch.created_at).toLocaleString() : 'N/A');
    const workerSource = ch.source_worker || 'as-cjbp';

    html += '<tr style="border-bottom: 1px solid #1e293b;">' +
      '<td style="padding: 12px; color: #38bdf8; font-weight: 700; font-size: 11px; white-space: nowrap;">' + workerSource + '</td>' +
      '<td style="padding: 12px; color: #34d399; font-family: monospace; font-weight: 600; white-space: nowrap;">' + ssid + ' (' + (ch.id || '') + ')</td>' +
      '<td style="padding: 12px; color: #f8fafc; font-weight: 500;">' + (ch.name || 'Channel') + '</td>' +
      '<td style="padding: 12px; color: #34d399; font-size: 13px; white-space: nowrap;">' + expTime + '</td>' +
      '<td style="padding: 12px; color: #94a3b8; font-size: 13px; white-space: nowrap;">' + genTime + '</td>' +
      '<td style="padding: 12px; white-space: nowrap;">' +
        '<div style="display: flex; gap: 8px; align-items: center;">' +
          '<button onclick="openCookieModal(' + idx + ')" style="background: #1e293b; color: #38bdf8; border: 1px solid #0284c7; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 4px;">👁️ View Cookie</button>' +
          '<button onclick="runCronUpdate()" style="background: #0284c7; color: #fff; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 4px;">🔄 Update</button>' +
        '</div>' +
      '</td>' +
    '</tr>';
  });

  tbody.innerHTML = html;
}

function filterCronChannels() {
  renderCronChannels(cronChannelsData);
}

function openCookieModal(idx) {
  const ch = cronChannelsData[idx];
  if (!ch) return;
  document.getElementById('modal-title').innerText = (ch.name || 'Channel') + ' (SSID: cj-' + (ch.id || '') + ')';
  document.getElementById('modal-cookie').innerText = ch.cookie || 'No cookie available';
  document.getElementById('modal-expiry').innerText = ch.expires_at || (ch.expire_time ? new Date(parseInt(ch.expire_time) * 1000).toLocaleString() : 'N/A');
  document.getElementById('modal-gen').innerText = ch.cookie_generated_at || ch.cookiegenerate_at || 'N/A';
  document.getElementById('modal-url').innerText = ch.url || 'N/A';
  document.getElementById('cookie-modal').style.display = 'flex';
}

function closeCookieModal() {
  document.getElementById('cookie-modal').style.display = 'none';
}

function selectStreamType(type) {
  const chkHls = document.getElementById('chk-hls');
  const chkMpd = document.getElementById('chk-mpd');
  if (!chkHls || !chkMpd) return;
  if (type === 'hls') {
    chkHls.checked = true;
    chkMpd.checked = false;
  } else if (type === 'mpd') {
    chkMpd.checked = true;
    chkHls.checked = false;
  }
}

function copyModalCookie() {
  const text = document.getElementById('modal-cookie').innerText;
  navigator.clipboard.writeText(text).then(() => {
    alert('Cookie copied to clipboard!');
  });
}

const ALLOWED_DOMAINS_LIST = ["fanxzone.pages.dev", "ziotv.movieszonemedia.workers.dev"];
let currentIframeSsid = '';

function openIframeModal(ssid, playUrl) {
  currentIframeSsid = ssid;
  
  const selectEl = document.getElementById('iframe-domain-select');
  if (selectEl && ALLOWED_DOMAINS_LIST && ALLOWED_DOMAINS_LIST.length > 0) {
    selectEl.innerHTML = '';
    ALLOWED_DOMAINS_LIST.forEach(dom => {
      const opt = document.createElement('option');
      opt.value = dom;
      opt.innerText = dom;
      selectEl.appendChild(opt);
    });
  }
  
  updateIframeCodeForSelectedDomain();
  document.getElementById('iframe-modal').style.display = 'flex';
}

function updateIframeCodeForSelectedDomain() {
  const selectEl = document.getElementById('iframe-domain-select');
  const selectedDomain = selectEl ? selectEl.value : (ALLOWED_DOMAINS_LIST[0] || window.location.hostname);
  
  document.getElementById('iframe-modal-title').innerText = 'Embed iFrame Code for SSID: ' + currentIframeSsid;
  document.getElementById('iframe-code-text').innerText = '⏳ Generating iFrame code for ' + selectedDomain + '...';
  
  fetch('/api/get/admin?action=get_token&ssid=' + encodeURIComponent(currentIframeSsid) + '&target_domain=' + encodeURIComponent(selectedDomain), {
    headers: { 'Accept': 'application/json' }
  }).then(res => res.json()).then(data => {
    const playUrl = data.playUrl || ('https://' + selectedDomain + '/?id=' + encodeURIComponent(currentIframeSsid) + '&token=' + data.token);
    const embedCode = '<iframe src="' + playUrl + '" width="100%" height="100%" frameborder="0" allowfullscreen></iframe>';
    document.getElementById('iframe-code-text').innerText = embedCode;
  }).catch(err => {
    const embedCode = '<iframe src="https://' + selectedDomain + '/?id=' + encodeURIComponent(currentIframeSsid) + '" width="100%" height="100%" frameborder="0" allowfullscreen></iframe>';
    document.getElementById('iframe-code-text').innerText = embedCode;
  });
}

function closeIframeModal() {
  document.getElementById('iframe-modal').style.display = 'none';
}

function copyIframeCodeText() {
  const text = document.getElementById('iframe-code-text').innerText;
  navigator.clipboard.writeText(text).then(() => {
    alert('iFrame embed code copied to clipboard!');
  });
}

async function deleteMatch(docId, matchTitle) {
  if (!confirm('Are you sure you want to delete match "' + matchTitle + '"?')) return;
  try {
    const res = await fetch('/api/get/admin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ action: 'delete', docId: docId, password: 'admin@123' })
    });
    const result = await res.json();
    if (result && result.success) {
      window.location.reload();
    } else {
      alert('Failed to delete match stream. Please try again.');
    }
  } catch (e) {
    alert('Error deleting match stream: ' + e.message);
  }
}
</script>
</body>
</html>`;

    return new Response(dashboardHtml, {
        status: 200,
        headers: {
            "Content-Type": "text/html;charset=UTF-8",
            "Set-Cookie": "__sz_admin_pass=admin@123; Path=/; HttpOnly; Secure; SameSite=Lax"
        }
    });
}

export default {
    async fetch(request, env, ctx) {

        if (request.method === "OPTIONS") {
            return new Response(null, {
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, X-API-Key, Range, Accept, Origin, Referer",
                }
            });
        }

        if (isAutomatedClient(request)) {
            return new Response("403 Forbidden", { status: 403 });
        }



        const url = new URL(request.url);

        let clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
        if (url.pathname === '/api/channels' && url.searchParams.has('client_ip')) {
            clientIp = url.searchParams.get('client_ip');
        }

        const now = Date.now();
        const isProxyRoute = url.pathname.startsWith('/api/proxy/');
        const maxLimit = isProxyRoute ? 2000 : 120;
        const windowMs = 10000;

        let rateRecord = RATE_LIMIT_MAP.get(clientIp);
        if (!rateRecord || now > rateRecord.resetTime) {
            rateRecord = { count: 1, resetTime: now + windowMs };
            RATE_LIMIT_MAP.set(clientIp, rateRecord);
        } else {
            rateRecord.count++;
        }

        if (rateRecord.count > maxLimit) {
            const retryAfterSec = Math.ceil((rateRecord.resetTime - now) / 1000);
            return new Response(`429 Too Many Requests - Rate limit exceeded. Try again in ${retryAfterSec} seconds.`, {
                status: 429,
                headers: {
                    "Retry-After": String(retryAfterSec),
                    "Access-Control-Allow-Origin": "*"
                }
            });
        }

        if (RATE_LIMIT_MAP.size > 5000) {
            for (const [ip, rec] of RATE_LIMIT_MAP.entries()) {
                if (now > rec.resetTime) RATE_LIMIT_MAP.delete(ip);
            }
        }

        const domain = url.hostname;
        const timeBlock = Math.floor(Date.now() / (1000 * 60 * 60 * 24));

        if (url.pathname === '/api/get/admin' || url.pathname === '/admin' || url.pathname.startsWith('/api/admin')) {
            return handleAdminRoute(request, domain);
        }

        if (url.pathname === '/api/channels' || url.pathname === '/api/get/channels') {
            const apiKey = request.headers.get("X-API-Key");
            const ua = request.headers.get("User-Agent") || "";
            if (apiKey !== API_SECRET_KEY && ua !== "Cloudflare-Worker") {
                return new Response("403 Forbidden", { status: 403 });
            }

            const responseData = {};

            const getInitials = (name) => {
                if (!name) return "";
                const words = name.split(' ').filter(Boolean);
                return words.map(w => {
                    const lower = w.toLowerCase();
                    if (lower === "hindi") return "hin";
                    if (lower === "tamil") return "tam";
                    if (lower === "telugu") return "tel";
                    if (lower === "kannada") return "kan";
                    if (lower === "marathi") return "mar";
                    if (lower === "bengali") return "ben";
                    if (lower === "gujarati") return "guj";
                    if (lower === "select") return "sel";
                    return w[0].toLowerCase();
                }).join('');
            };

            const addChannelItem = (key, rawLink, isHls, isMpd, name = "", extraData = {}) => {
                if (!key) return;
                const itemObj = {
                    ssid: key,
                    name: name || key,
                    link: rawLink,
                    type: isMpd ? "mpd" : isHls ? "hls" : "unknown"
                };
                responseData[key] = itemObj;
                return itemObj;
            };

            try {
                const [jRes, pRes] = await Promise.all([
                    fetch(`${BROBP_WORKER}/jtv`, {
                        headers: { "User-Agent": "Cloudflare-Worker" },
                        cf: { cacheTtl: 300, cacheEverything: true }
                    }).catch(() => null),
                    fetch(`${BROBP_WORKER}/jtvplus`, {
                        headers: { "User-Agent": "Cloudflare-Worker" },
                        cf: { cacheTtl: 300, cacheEverything: true }
                    }).catch(() => null)
                ]);

                if (jRes && jRes.ok) {
                    const jData = await jRes.json();
                    for (const channelData of jData) {
                        const id = channelData.id ? channelData.id.toString() : null;
                        if (id && BROBP_CHANNELS.includes(id) && channelData.name) {
                            const rawInitials = getInitials(channelData.name);
                            const chStreamUrl = channelData.mpd || channelData.url || channelData.streamUrl || "";
                            const chIsHls = !!chStreamUrl.includes('.m3u8');
                            const chIsMpd = !!(channelData.mpd || chStreamUrl.includes('.mpd'));
                            const jKey = 'j' + rawInitials;
                            const dataToSignJ = `${domain}|${timeBlock}|${jKey}|unknown`;
                            const tokenJ = await generateHMAC(dataToSignJ, SECRET_KEY);
                            const linkJ = `https://${domain}/?id=${encodeURIComponent(jKey)}&token=${tokenJ}`;
                            addChannelItem(jKey, linkJ, chIsHls, chIsMpd, channelData.name);
                        }
                    }
                }

                if (pRes && pRes.ok) {
                    const pData = await pRes.json();
                    for (const channelData of pData) {
                        const id = channelData.id ? channelData.id.toString() : null;
                        if (id && BROBP_CHANNELS.includes(id) && channelData.name) {
                            const rawInitials = getInitials(channelData.name);
                            const chStreamUrl = channelData.mpd || channelData.url || channelData.streamUrl || "";
                            const chIsHls = !!chStreamUrl.includes('.m3u8');
                            const chIsMpd = !!(channelData.mpd || chStreamUrl.includes('.mpd'));
                            const jpKey = 'jp' + rawInitials;
                            const dataToSignJP = `${domain}|${timeBlock}|${jpKey}|unknown`;
                            const tokenJP = await generateHMAC(dataToSignJP, SECRET_KEY);
                            const linkJP = `https://${domain}/?id=${encodeURIComponent(jpKey)}&token=${tokenJP}`;
                            addChannelItem(jpKey, linkJP, chIsHls, chIsMpd, channelData.name);
                        }
                    }
                }
            } catch (e) {
                console.error("BROBP Bulk API Error", e);
            }

            try {
                const FIREBASE_API_KEY = "AIzaSyD-nUtWeFqHLCWPOQaFDCgmHfCGjf7L6Mo";
                const FIREBASE_URL = `https://firestore.googleapis.com/v1/projects/sports-zone-ed3a9/databases/(default)/documents/matches?key=${FIREBASE_API_KEY}`;
                const fbRes = await fetch(FIREBASE_URL, { cf: { cacheTtl: 60, cacheEverything: true } }).catch(() => null);

                if (fbRes && fbRes.ok) {
                    const fbData = await fbRes.json();
                    if (fbData.documents) {
                        for (const doc of fbData.documents) {
                            const match = doc.fields;
                            if (match.status && match.status.stringValue === "Live") {
                                const matchName = match.matchName ? match.matchName.stringValue : "";
                                if (match.servers && match.servers.arrayValue && match.servers.arrayValue.values) {
                                    for (const srv of match.servers.arrayValue.values) {
                                        const server = srv.mapValue.fields;
                                        const channelName = server.channelName ? server.channelName.stringValue : "";

                                        const matchInitials = matchName.split(' ').filter(Boolean).map(w => w[0]).join('').toLowerCase();
                                        const channelInitials = channelName.split(' ').filter(Boolean).map(w => w[0]).join('').toLowerCase();
                                        const customId = matchInitials + channelInitials;
                                        const dataToSign = `${domain}|${timeBlock}|${customId}|unknown`;
                                        const token = await generateHMAC(dataToSign, SECRET_KEY);

                                        let formattedTime = "";
                                        if (doc.createTime) {
                                            try {
                                                const d = new Date(doc.createTime);
                                                formattedTime = d.toLocaleString("en-IN", { timeZone: "Asia/Kolkata" });
                                            } catch (e) { formattedTime = doc.createTime; }
                                        }

                                        const fbMpd = server.mpd ? server.mpd.stringValue : "";
                                        const fbUrl = server.url ? server.url.stringValue : "";
                                        const fbTypeStr = server.type ? server.type.stringValue.toLowerCase() : "";
                                        const fbStreamUrl = fbMpd || fbUrl;
                                        const fbIsHls = fbTypeStr === "hls" || fbStreamUrl.includes('.m3u8');
                                        const fbIsMpd = fbTypeStr === "mpd" || fbTypeStr === "dash" || fbStreamUrl.includes('.mpd');
                                        const linkFb = `https://${domain}/?id=${encodeURIComponent(customId)}&token=${token}`;

                                        const displayName = matchName + (channelName ? ' (' + channelName + ')' : '');
                                        addChannelItem(customId, linkFb, fbIsHls, fbIsMpd, displayName);
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (e) {
                console.error("Firebase API Error", e);
            }

            try {
                const FIREBASE_API_KEY = "AIzaSyD-nUtWeFqHLCWPOQaFDCgmHfCGjf7L6Mo";
                const FIREBASE_CUSTOM_URL = `https://firestore.googleapis.com/v1/projects/sports-zone-ed3a9/databases/(default)/documents/fanxzone_custom?key=${FIREBASE_API_KEY}`;
                const customFbRes = await fetch(FIREBASE_CUSTOM_URL, { cf: { cacheTtl: 10, cacheEverything: false } }).catch(() => null);

                if (customFbRes && customFbRes.ok) {
                    const customFbData = await customFbRes.json();
                    if (customFbData.documents) {
                        for (const doc of customFbData.documents) {
                            const match = doc.fields || {};
                            const title = match.title ? match.title.stringValue : (match.matchName ? match.matchName.stringValue : "");
                            const ssid = match.ssid ? match.ssid.stringValue : "";
                            const streamUrl = match.streamUrl ? match.streamUrl.stringValue : (match.url ? match.url.stringValue : "");
                            const keys = match.keys ? match.keys.stringValue : (match.key ? match.key.stringValue : "");
                            const cookie = match.cookie ? match.cookie.stringValue : "";
                            const isHls = match.isHls ? (typeof match.isHls.booleanValue === 'boolean' ? match.isHls.booleanValue : match.isHls.stringValue === "true") : streamUrl.includes(".m3u8");
                            const isMpd = !isHls;

                            if (ssid) {
                                const customId = ssid;
                                const dataToSign = `${domain}|${timeBlock}|${customId}|unknown`;
                                const token = await generateHMAC(dataToSign, SECRET_KEY);

                                let formattedTime = "";
                                if (doc.createTime) {
                                    try {
                                        const d = new Date(doc.createTime);
                                        formattedTime = d.toLocaleString("en-IN", { timeZone: "Asia/Kolkata" });
                                    } catch (e) { formattedTime = doc.createTime; }
                                }

                                const linkCustom = `https://${domain}/?id=${encodeURIComponent(customId)}&token=${token}`;
                                addChannelItem(customId, linkCustom, isHls, isMpd, title || customId);
                            }
                        }
                    }
                }
            } catch (e) {
                console.error("Firebase custom collection fetch error in /api/get/channels", e);
            }

            try {
                responseData["as-test"] = {};
                const tPromises = ALLOWED_CHANNELS.map(async (id) => {
                    try {
                        const tRes = await fetch(`https://as-test.rabba.workers.dev/?id=${id}`, { cf: { cacheTtl: 300, cacheEverything: true } }).catch(() => null);
                        if (tRes && tRes.ok) {
                            const tJson = await tRes.json();
                            const tData = Array.isArray(tJson) ? tJson[0] : tJson;
                            if (tData && tData.name) {
                                const rawInitials = getInitials(tData.name);
                                const tStreamUrl = tData.mpd || tData.url || tData.streamUrl || "";
                                const tIsHls = !!tStreamUrl.includes('.m3u8');
                                const tIsMpd = !!(tData.mpd || tStreamUrl.includes('.mpd'));
                                const dataToSignId = `${domain}|${timeBlock}|${rawInitials}|unknown`;
                                const tokenId = await generateHMAC(dataToSignId, SECRET_KEY);
                                const linkTest = `https://${domain}/?id=${encodeURIComponent(rawInitials)}&token=${tokenId}`;
                                return {
                                    key: rawInitials,
                                    item: {
                                        ssid: rawInitials,
                                        link: linkTest,
                                        type: tIsMpd ? "mpd" : tIsHls ? "hls" : "unknown"
                                    }
                                };
                            }
                        }
                    } catch (e) { }
                    return null;
                });

                const tResults = await Promise.all(tPromises);
                for (const res of tResults) {
                    if (res && res.key) {
                        responseData["as-test"][res.key] = res.item;
                        responseData[res.key] = res.item;
                    }
                }
            } catch (e) {
                console.error("Error fetching as-test channels for API", e);
            }

            try {
                const cxRes = await fetch("https://as-cxblbp.rabba.workers.dev/api/channels/all", { cf: { cacheTtl: 300, cacheEverything: true } }).catch(() => null);
                if (cxRes && cxRes.ok) {
                    const cxJson = await cxRes.json();
                    if (cxJson && cxJson.data) {
                        for (const realId of Object.keys(cxJson.data)) {
                            const mhInfo = cxJson.data[realId];
                            const mhStreamUrl = mhInfo.ManifestURI || "";
                            const mhIsHls = !!mhStreamUrl.includes('.m3u8');
                            const mhIsMpd = !!mhStreamUrl.includes('.mpd');
                            const mhKey = `mh-${realId}`;
                            const dataToSign = `${domain}|${timeBlock}|${mhKey}|unknown`;
                            const token = await generateHMAC(dataToSign, SECRET_KEY);
                            const linkMh = `https://${domain}/?id=${encodeURIComponent(mhKey)}&token=${token}`;
                            addChannelItem(mhKey, linkMh, mhIsHls, mhIsMpd, realId);
                        }
                    }
                }
            } catch (e) {
                console.error("Error fetching as-cxblbp channels for API", e);
            }

            try {
                const stDataList = await Promise.all(
                    BROBP_CHANNELS.map(async (id) => {
                        try {
                            const res = await fetch(`https://as-stflx.rabba.workers.dev/?id=${encodeURIComponent(id)}`, {
                                cf: { cacheTtl: 300, cacheEverything: true }
                            });
                            if (res.ok) {
                                const json = await res.json();
                                return Array.isArray(json) ? json[0] : json;
                            }
                        } catch (e) { }
                        return null;
                    })
                );

                for (const stData of stDataList.filter(Boolean)) {
                    if (stData && stData.name) {
                        const rawInitials = getInitials(stData.name);
                        const stStreamUrl = stData.mpd || stData.url || stData.streamUrl || "";
                        const stIsHls = !!stStreamUrl.includes('.m3u8');
                        const stIsMpd = !!(stData.mpd || stStreamUrl.includes('.mpd'));
                        const stKey = `st-${rawInitials}`;
                        const dataToSign = `${domain}|${timeBlock}|${stKey}|unknown`;
                        const token = await generateHMAC(dataToSign, SECRET_KEY);
                        const linkSt = `https://${domain}/?id=${encodeURIComponent(stKey)}&token=${token}`;
                        addChannelItem(stKey, linkSt, stIsHls, stIsMpd, stData.name);
                    }
                }
            } catch (e) {
                console.error("Error fetching as-stflx channels", e);
            }

            try {
                responseData["as-cjbp"] = {};
                const cjDataList = await Promise.all(
                    BROBP_CHANNELS.map(async (id) => {
                        try {
                            const res = await fetch(`https://as-cjbp.yinave4095.workers.dev/?id=${encodeURIComponent(id)}`, {
                                cf: { cacheTtl: 300, cacheEverything: true }
                            });
                            if (res.ok) {
                                const json = await res.json();
                                return Array.isArray(json) ? json[0] : json;
                            }
                        } catch (e) { }
                        return null;
                    })
                );

                for (const cjData of cjDataList.filter(Boolean)) {
                    if (cjData && cjData.name) {
                        const rawInitials = getInitials(cjData.name);
                        const cjStreamUrl = cjData.url || cjData.mpd || cjData.streamUrl || "";
                        const cjIsHls = !!cjStreamUrl.includes('.m3u8');
                        const cjIsMpd = !!(cjData.mpd || cjStreamUrl.includes('.mpd'));
                        const cjKey = `cj-${rawInitials}`;
                        const dataToSign = `${domain}|${timeBlock}|${cjKey}|unknown`;
                        const token = await generateHMAC(dataToSign, SECRET_KEY);
                        const linkCj = `https://${domain}/?id=${encodeURIComponent(cjKey)}&token=${token}`;
                        const itemObj = addChannelItem(cjKey, linkCj, cjIsHls, cjIsMpd, cjData.name);
                        responseData["as-cjbp"][cjKey] = itemObj;
                    }
                }
            } catch (e) {
                console.error("Error fetching as-cjbp channels", e);
            }

            try {
                for (const realId of CRICKESTER_CHANNELS) {
                    const szKey = `sz-${realId}`;
                    const dataToSign = `${domain}|${timeBlock}|${szKey}|unknown`;
                    const token = await generateHMAC(dataToSign, SECRET_KEY);
                    const linkSz = `https://${domain}/?id=${encodeURIComponent(szKey)}&token=${token}`;
                    addChannelItem(szKey, linkSz, true, false, "Willow Cricket");
                }
            } catch (e) {
                console.error("Error generating sz- channels for API", e);
            }

            try {
                const iosRes = await fetch("https://as-cxfiosbp.rabba.workers.dev/api/channels/all", { cf: { cacheTtl: 300, cacheEverything: true } }).catch(() => null);
                if (iosRes && iosRes.ok) {
                    const iosJson = await iosRes.json();
                    if (iosJson && iosJson.data) {
                        for (const realId of Object.keys(iosJson.data)) {
                            const iosInfo = iosJson.data[realId];
                            const iosStreamUrl = iosInfo.mpd || iosInfo.ManifestURI || iosInfo.url || iosInfo.streamUrl || "";
                            const iosIsHls = !!iosStreamUrl.includes('.m3u8');
                            const iosIsMpd = !!(iosInfo.mpd || iosStreamUrl.includes('.mpd'));
                            const iosKey = `ios-${realId}`;
                            const dataToSign = `${domain}|${timeBlock}|${iosKey}|unknown`;
                            const token = await generateHMAC(dataToSign, SECRET_KEY);
                            const linkIos = `https://${domain}/?id=${encodeURIComponent(iosKey)}&token=${token}`;
                            addChannelItem(iosKey, linkIos, iosIsHls, iosIsMpd);
                        }
                    }
                }
            } catch (e) {
                console.error("Error fetching as-cxfiosbp channels for API", e);
            }
            const jsonString = JSON.stringify(responseData);
            const encoder = new TextEncoder();
            const rawKey = encoder.encode(ENCRYPTION_KEY);
            const iv = crypto.getRandomValues(new Uint8Array(12));

            const cryptoKey = await crypto.subtle.importKey(
                "raw", rawKey,
                { name: "AES-GCM" },
                false, ["encrypt"]
            );

            const encryptedBuffer = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv },
                cryptoKey,
                encoder.encode(jsonString)
            );

            const encryptedBytes = new Uint8Array(encryptedBuffer);
            const combinedBuffer = new Uint8Array(iv.length + encryptedBytes.length);
            combinedBuffer.set(iv, 0);
            combinedBuffer.set(encryptedBytes, iv.length);
            let binaryStr = "";
            const chunkSize = 0x8000;
            for (let i = 0; i < combinedBuffer.length; i += chunkSize) {
                binaryStr += String.fromCharCode.apply(null, combinedBuffer.subarray(i, i + chunkSize));
            }
            const base64Output = btoa(binaryStr);

            return new Response(base64Output, {
                headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' }
            });
        }

        if (url.pathname.startsWith('/api/proxy/')) {
            const userAgent = request.headers.get("User-Agent") || "";
            const isBot = BOT_TOOL_USER_AGENTS.some(bot => userAgent.toLowerCase().includes(bot));

            if (isBot) {
                return new Response("403 Forbidden", {
                    status: 403,
                    headers: { "Access-Control-Allow-Origin": "*" }
                });
            }

            const origin = request.headers.get("Origin") || "";
            const referer = request.headers.get("Referer") || "";

            if (origin && !isAllowedDomain(origin)) {
                return new Response("403 Forbidden", {
                    status: 403,
                    headers: { "X-Proxy-Error": "403 Forbidden - Origin Not Allowed", "Access-Control-Allow-Origin": "*" }
                });
            }

            if (referer && !isAllowedDomain(referer)) {
                return new Response("403 Forbidden", {
                    status: 403,
                    headers: { "X-Proxy-Error": "403 Forbidden - Referer Not Allowed", "Access-Control-Allow-Origin": "*" }
                });
            }

            const fullProxyPath = url.pathname.substring('/api/proxy/'.length);
            const firstSlashIdx = fullProxyPath.indexOf('/');
            let hashToken = fullProxyPath;
            let extraPath = "";

            if (firstSlashIdx !== -1) {
                hashToken = fullProxyPath.substring(0, firstSlashIdx);
                extraPath = fullProxyPath.substring(firstSlashIdx);
            }

            const proxyPayload = await decryptProxyToken(hashToken);

            if (!proxyPayload || !proxyPayload.s) {
                return new Response("403 Forbidden", {
                    status: 403,
                    headers: { "X-Proxy-Error": "403 Forbidden", "Access-Control-Allow-Origin": "*" }
                });
            }

            const session = await decryptStreamSessionToken(proxyPayload.s, clientIp);
            if (!session) {
                return new Response("403 Forbidden", {
                    status: 403,
                    headers: { "X-Proxy-Error": "403 Forbidden", "Access-Control-Allow-Origin": "*" }
                });
            }

            if (proxyPayload.t === 3) {
                if (!session.ki || !session.k) {
                    return new Response(JSON.stringify({ error: "No DRM key available" }), {
                        status: 404,
                        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
                    });
                }

                const toBase64Url = (str) => {
                    let hex = str.replace(/[^0-9a-fA-F]/g, '');
                    if (hex.length % 2 !== 0) hex = '0' + hex;
                    let bytes;
                    if (hex.length > 0 && hex.length === str.replace(/[^0-9a-fA-F]/g, '').length) {
                        bytes = new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                    } else {
                        bytes = new TextEncoder().encode(str);
                    }
                    let bin = "";
                    for (let i = 0; i < bytes.length; i++) {
                        bin += String.fromCharCode(bytes[i]);
                    }
                    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
                };

                const kidB64 = toBase64Url(session.ki);
                const keyB64 = toBase64Url(session.k);

                const responsePayload = {
                    keys: [
                        {
                            kty: "oct",
                            kid: kidB64,
                            k: keyB64
                        }
                    ],
                    type: "temporary",
                    clearKeys: {
                        [session.ki]: session.k
                    }
                };

                const rawJson = JSON.stringify(responsePayload);
                const jsonBytes = new TextEncoder().encode(rawJson);
                const seed = Math.floor(Math.random() * 200) + 20;
                const salt = Math.floor(Math.random() * 50) + 7;
                const encBytes = new Uint8Array(jsonBytes.length);

                for (let i = 0; i < jsonBytes.length; i++) {
                    encBytes[i] = jsonBytes[i] ^ ((seed + (i * salt)) & 0xFF);
                }

                let binary = "";
                for (let i = 0; i < encBytes.length; i++) {
                    binary += String.fromCharCode(encBytes[i]);
                }
                const b64Drm = btoa(binary);

                const drmPayload = JSON.stringify({
                    d: b64Drm,
                    s: seed,
                    l: salt
                });

                return new Response(drmPayload, {
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "*",
                        "Cache-Control": "no-cache, no-store, must-revalidate"
                    }
                });
            }

            async function fetchUpstreamSmart(targetUrl, token, ftToken, isSegment = false, rangeHeader = null) {
                targetUrl = (targetUrl || "").trim().replace(/[\r\n\t\s]/g, '');
                let targetHost = "";
                try {
                    targetHost = new URL(targetUrl).hostname;
                } catch (e) { }

                const baseCf = isSegment
                    ? { cacheTtl: 86400, cacheEverything: true }
                    : { cacheTtl: 5, cacheEverything: false };

                const makeHeaders = (ua, ref, orig, tok, includeIp = false) => {
                    let h = {
                        "User-Agent": ua || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                        "Accept": "*/*",
                        "Accept-Language": "en-US,en;q=0.9"
                    };
                    if (ref) h["Referer"] = ref;
                    if (orig) h["Origin"] = orig;
                    if (rangeHeader) h["Range"] = rangeHeader;
                    if (includeIp) {
                        h["X-Forwarded-For"] = "49.36.180.50";
                        h["X-Real-IP"] = "49.36.180.50";
                    }
                    if (tok) {
                        if (tok.startsWith("Bearer ") || tok.startsWith("eyJ")) {
                            h["Authorization"] = tok.startsWith("Bearer ") ? tok : `Bearer ${tok}`;
                        } else if (tok.includes("=") || tok.startsWith("hdnea=") || tok.startsWith("__hdnea__")) {
                            h["Cookie"] = tok.startsWith("hdnea=") || tok.includes("=") ? tok : `hdnea=${tok}`;
                        } else {
                            h["Authorization"] = `Bearer ${tok}`;
                            h["Cookie"] = `hdnea=${tok}`;
                        }
                    }
                    return h;
                };

                const attempts = [];
                attempts.push(makeHeaders("plaYtv/7.1.5 (Linux;Android 13) ExoPlayerLib/2.11.6", null, null, token));
                if (ftToken) {
                    attempts.push(makeHeaders("plaYtv/7.1.5 (Linux;Android 13) ExoPlayerLib/2.11.6", null, null, ftToken));
                }

                if (targetUrl.includes("amagi.tv") || targetUrl.includes("willow") || targetUrl.includes("sportstribal")) {
                    attempts.push(makeHeaders(null, "https://now.amagi.tv/", "https://now.amagi.tv", token));
                    attempts.push(makeHeaders(null, "https://www.willow.tv/", "https://www.willow.tv", token));
                    attempts.push(makeHeaders(null, "https://www.sportstribal.tv/", "https://www.sportstribal.tv", token));
                    attempts.push(makeHeaders(null, "https://now.amagi.tv/", "https://now.amagi.tv", null, true));
                }

                attempts.push(makeHeaders(null, `https://${targetHost}/`, `https://${targetHost}`, token, true));
                attempts.push(makeHeaders(null, null, null, null, false));

                for (const h of attempts) {
                    try {
                        const res = await fetch(targetUrl, { method: "GET", headers: h, cf: baseCf });
                        if (res.ok) {
                            return res;
                        }
                    } catch (e) { }
                }

                return await fetch(targetUrl, { method: "GET", headers: attempts[0], cf: baseCf });
            }

            if (proxyPayload.t === 1) {
                const targetUrl = (proxyPayload.u || session.u || "").trim().replace(/[\r\n\t\s]/g, '');
                let upstreamRes = await fetchUpstreamSmart(targetUrl, session.t, session.ft, false);

                if (!upstreamRes.ok) {
                    let errText = "No upstream error body";
                    try { errText = await upstreamRes.text(); } catch (e) { }
                    const colo = request.cf ? request.cf.colo : "unknown";
                    const debugInfo = `\n\nDebug Info:\n- Upstream URL: ${targetUrl}\n- CF PoP: ${colo}\n- Client IP: ${clientIp}`;
                    return new Response(`502 Bad Gateway - Proxy Step: Manifest Upstream Error HTTP ${upstreamRes.status}\n\nUpstream Error Body:\n${errText}${debugInfo}`, {
                        status: 502,
                        headers: {
                            "Access-Control-Allow-Origin": "*",
                            "X-Proxy-Error": `Forbidden HTTP ${upstreamRes.status}`,
                            "X-Upstream-Url": targetUrl.substring(0, 200),
                            "X-CF-Colo": colo,
                            "X-Upstream-Error-Body": errText.replace(/\n/g, ' ').substring(0, 200)
                        }
                    });
                }

                const isAdminCustom = !!(session.ac || isJioUrl(targetUrl));
                const isMpd = targetUrl.includes('.mpd');
                if (isMpd) {
                    const rawMpdXml = await upstreamRes.text();
                    let baseDir;
                    try {
                        const parsedMpd = new URL(targetUrl);
                        const mpdPath = parsedMpd.pathname;
                        baseDir = parsedMpd.origin + mpdPath.substring(0, mpdPath.lastIndexOf('/') + 1);
                    } catch (e) {
                        baseDir = targetUrl.substring(0, targetUrl.lastIndexOf('/') + 1);
                    }
                    const mpdXml = await rewriteDashManifestUniversal(rawMpdXml, baseDir, proxyPayload.s, domain, isAdminCustom);

                    return new Response(request.method === "HEAD" ? null : mpdXml, {
                        headers: {
                            "Content-Type": "application/dash+xml",
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
                            "Cache-Control": "public, max-age=2, s-maxage=2, stale-while-revalidate=4"
                        }
                    });
                } else {
                    const manifestText = await upstreamRes.text();
                    let baseUrl;
                    let parentQuery = '';
                    try {
                        const parsedUrl = new URL(targetUrl);
                        parentQuery = parsedUrl.search ? parsedUrl.search.substring(1) : '';
                        const pathOnly = parsedUrl.pathname;
                        const basePath = pathOnly.substring(0, pathOnly.lastIndexOf('/') + 1);
                        baseUrl = parsedUrl.origin + basePath;
                    } catch (e) {
                        baseUrl = targetUrl.substring(0, targetUrl.lastIndexOf('/') + 1);
                    }
                    const rewrittenManifest = await rewriteHlsManifestUniversal(manifestText, baseUrl, proxyPayload.s, domain, parentQuery, isAdminCustom);

                    return new Response(request.method === "HEAD" ? null : rewrittenManifest, {
                        headers: {
                            "Content-Type": "application/vnd.apple.mpegurl",
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
                            "Cache-Control": "public, max-age=2, s-maxage=2, stale-while-revalidate=4"
                        }
                    });
                }
            }

            if (proxyPayload.t === 2) {
                let targetUrl = (proxyPayload.u || "").trim().replace(/[\r\n\t\s]/g, '');
                if (!targetUrl) {
                    return new Response("400 Bad Request - Proxy Step: Missing Target URL", { status: 400 });
                }

                if (extraPath) {
                    try {
                        const relPathWithQuery = extraPath.substring(1) + url.search;
                        targetUrl = new URL(relPathWithQuery, targetUrl).href;
                    } catch (e) { }
                }

                const rangeHeader = request.headers.has("Range") ? request.headers.get("Range") : null;
                let upstreamRes = await fetchUpstreamSmart(targetUrl, session.t, session.ft, true, rangeHeader);

                const responseHeaders = new Headers();
                responseHeaders.set("Access-Control-Allow-Origin", "*");
                responseHeaders.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
                responseHeaders.set("Access-Control-Allow-Headers", "*");

                const copyHeader = (name) => {
                    if (upstreamRes.headers.has(name)) {
                        responseHeaders.set(name, upstreamRes.headers.get(name));
                    }
                };

                copyHeader("Content-Type");
                copyHeader("Content-Length");
                copyHeader("Content-Range");
                copyHeader("Accept-Ranges");
                copyHeader("Etag");
                copyHeader("Last-Modified");
                responseHeaders.set("Cache-Control", "public, max-age=86400, s-maxage=86400, immutable");

                if (!upstreamRes.ok) {
                    let errText = "No upstream error body";
                    try { errText = await upstreamRes.text(); } catch (e) { }
                    return new Response(`502 Bad Gateway - Proxy Step: Segment Upstream Error HTTP ${upstreamRes.status}\n\nUpstream Error Body:\n${errText}`, {
                        status: 502,
                        headers: {
                            "Access-Control-Allow-Origin": "*",
                            "X-Proxy-Error": `403 Forbidden HTTP ${upstreamRes.status}`,
                            "X-Upstream-Error-Body": errText.replace(/\n/g, ' ').substring(0, 200)
                        }
                    });
                }

                return new Response(request.method === "HEAD" ? null : upstreamRes.body, {
                    status: upstreamRes.status,
                    statusText: upstreamRes.statusText,
                    headers: responseHeaders
                });
            }

            return new Response("400 Bad Request - Invalid Proxy Type", { status: 400 });
        }

        let channelId = url.searchParams.get("id");
        let providedToken = url.searchParams.get("token");
        const encryptedParam = url.searchParams.get("e");

        if (encryptedParam) {
            try {
                let base64 = encryptedParam.replace(/-/g, '+').replace(/_/g, '/');
                while (base64.length % 4) { base64 += '='; }
                const binaryString = atob(base64);
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    bytes[i] = binaryString.charCodeAt(i);
                }
                const iv = bytes.slice(0, 12);
                const encryptedData = bytes.slice(12);

                const encEncoder = new TextEncoder();
                const cryptoKey = await crypto.subtle.importKey(
                    "raw", encEncoder.encode(ENCRYPTION_KEY),
                    { name: "AES-GCM" },
                    false, ["decrypt"]
                );

                const decryptedBuffer = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv },
                    cryptoKey,
                    encryptedData
                );

                const jsonText = new TextDecoder().decode(decryptedBuffer);
                const payload = JSON.parse(jsonText);
                channelId = payload.i || payload.id || payload.ssid || payload.channelId;
                providedToken = payload.t || payload.token || payload.auth;
            } catch (err) {
                return new Response("403 Forbidden - Encrypted Payload Error", { status: 403 });
            }
        }

        const navFetchDest = request.headers.get("Sec-Fetch-Dest");
        const navFetchSite = request.headers.get("Sec-Fetch-Site");
        const navReferer = request.headers.get("Referer") || "";
        const navOrigin = request.headers.get("Origin") || "";
        const isAllowedRef = isAllowedDomain(navReferer) || isAllowedDomain(navOrigin);

        if (!isAllowedRef && navFetchDest !== "iframe" && navFetchSite === "none") {
            return new Response("403 Forbidden - Direct Access Not Allowed. Stream can only be embedded via iframe on authorized domains.", {
                status: 403,
                headers: { "Content-Type": "text/plain", "Access-Control-Allow-Origin": "*" }
            });
        }

        if (!channelId || !providedToken) {
            return new Response("403 Forbidden", { status: 403 });
        }

        const domainsToCheck = Array.from(new Set([domain, ...ALLOWED_DOMAINS]));
        let isTokenValid = false;

        const prevTimeBlock = timeBlock - 1;

        for (const dom of domainsToCheck) {
            const dataToVerify = `${dom}|${timeBlock}|${channelId}|${clientIp}`;
            const expectedToken = await generateHMAC(dataToVerify, SECRET_KEY);

            const prevDataToVerify = `${dom}|${prevTimeBlock}|${channelId}|${clientIp}`;
            const prevExpectedToken = await generateHMAC(prevDataToVerify, SECRET_KEY);

            const ipFreeData = `${dom}|${timeBlock}|${channelId}|unknown`;
            const expectedIpFreeToken = await generateHMAC(ipFreeData, SECRET_KEY);

            const prevIpFreeData = `${dom}|${prevTimeBlock}|${channelId}|unknown`;
            const prevExpectedIpFreeToken = await generateHMAC(prevIpFreeData, SECRET_KEY);

            if (providedToken === expectedToken || providedToken === prevExpectedToken || providedToken === expectedIpFreeToken || providedToken === prevExpectedIpFreeToken) {
                isTokenValid = true;
                break;
            }
        }

        if (!isTokenValid) {
            return new Response("403 Forbidden", {
                status: 403,
                headers: { "Access-Control-Allow-Origin": "*", "X-Proxy-Error": "403 Forbidden - Token Signature Mismatch" }
            });
        }

        let channelData = null;

        if (channelId.startsWith("ios-")) {
            try {
                const realId = channelId.substring(4);
                const iosRes = await fetch("https://as-cxfiosbp.rabba.workers.dev/api/channels/all", { cf: { cacheTtl: 300, cacheEverything: true } });
                if (iosRes.ok) {
                    const iosJson = await iosRes.json();
                    if (iosJson && iosJson.data) {
                        const matchKey = Object.keys(iosJson.data).find(k => k.toLowerCase() === realId.toLowerCase()) || realId;
                        const info = iosJson.data[matchKey] || iosJson.data[realId];
                        if (info) {
                            const rawStreamUrl = info.mpd || info.ManifestURI || info.url || info.streamUrl || "";
                            const streamUrl = rawStreamUrl.trim().replace(/[\r\n\t\s]/g, '');
                            const drmKeys = info.DRMKeys || info.clearKey || {};
                            const keyId = Object.keys(drmKeys)[0] || (info.clearKey && info.clearKey.keyId) || info.keyId || "";
                            const keyVal = Object.values(drmKeys)[0] || (info.clearKey && info.clearKey.key) || info.key || "";

                            channelData = {
                                name: info.name || realId,
                                streamUrl: streamUrl,
                                isMpd: !!(streamUrl.includes('.mpd') || info.isMpd),
                                isHls: !!(streamUrl.includes('.m3u8') || info.isHls),
                                keyId: keyId,
                                key: keyVal,
                                token: info.token || info.cookie || ""
                            };
                        }
                    }
                }
            } catch (e) {
                console.error("Error fetching ios- channel from as-cxfiosbp worker", e);
            }
        } else if (channelId.startsWith("sz-")) {
            try {
                const realId = channelId.substring(3);
                const ckUrl = `https://as-cksbp.rabba.workers.dev/?id=${encodeURIComponent(realId)}`;
                const ckRes = await fetch(ckUrl, { cf: { cacheTtl: 0, cacheEverything: false } });
                if (ckRes.ok) {
                    const data = await ckRes.json();
                    if (data) {
                        const rawUrl = data.mpd || data.streamUrl || data.url || "";
                        const streamUrl = rawUrl.trim().replace(/[\r\n\t\s]/g, '');
                        const keyId = (data.clearKey && data.clearKey.keyId) || data.k1 || "";
                        const keyVal = (data.clearKey && data.clearKey.key) || data.k2 || "";
                        const token = (data.Bearer || "").trim();

                        channelData = {
                            name: data.name || realId,
                            streamUrl: streamUrl,
                            isMpd: !!streamUrl.includes('.mpd'),
                            isHls: !!streamUrl.includes('.m3u8'),
                            keyId: keyId,
                            key: keyVal,
                            token: token
                        };
                    }
                }
            } catch (e) {
                console.error("Error fetching sz- channel from as-cksbp worker", e);
            }
        } else if (channelId.startsWith("mh-")) {
            try {
                const realId = channelId.substring(3);
                const cxRes = await fetch("https://as-cxblbp.rabba.workers.dev/api/channels/all", { cf: { cacheTtl: 300, cacheEverything: true } });
                if (cxRes.ok) {
                    const cxJson = await cxRes.json();
                    if (cxJson && cxJson.data && cxJson.data[realId]) {
                        const info = cxJson.data[realId];
                        const streamUrl = (info.ManifestURI || "").trim().replace(/[\r\n\t\s]/g, '');
                        const drmKeys = info.DRMKeys || {};
                        const keyId = Object.keys(drmKeys)[0] || "";
                        const keyVal = Object.values(drmKeys)[0] || "";

                        channelData = {
                            name: realId,
                            streamUrl: streamUrl,
                            isMpd: !!streamUrl.includes('.mpd'),
                            isHls: !!streamUrl.includes('.m3u8'),
                            keyId: keyId,
                            key: keyVal,
                            token: ""
                        };
                    }
                }
            } catch (e) {
                console.error("Error fetching mh- channel from as-cxblbp worker", e);
            }
        } else if (channelId.startsWith("st-")) {
            try {
                const rawInitials = channelId.substring(3);

                const allowedData = await Promise.all(
                    BROBP_CHANNELS.map(async (id) => {
                        try {
                            const res = await fetch(`https://as-stflx.rabba.workers.dev/api/cache?id=${encodeURIComponent(id)}`, {
                                cf: { cacheTtl: 300, cacheEverything: true }
                            });
                            if (res.ok) {
                                const json = await res.json();
                                return Array.isArray(json) ? json[0] : json;
                            }
                        } catch (e) { }
                        return null;
                    })
                );

                const validAllowed = allowedData.filter(Boolean);
                const getInitials = (name) => {
                    if (!name) return "";
                    return name.split(' ').filter(Boolean).map(w => {
                        const lowerW = w.toLowerCase();
                        if (lowerW === 'hindi') return 'hin';
                        if (lowerW === 'tamil') return 'tam';
                        if (lowerW === 'telugu') return 'tel';
                        if (lowerW === 'kannada') return 'kan';
                        if (lowerW === 'select') return 'sel';
                        if (lowerW === 'liv') return 'l';
                        return lowerW[0];
                    }).join('').toLowerCase();
                };

                const matched = validAllowed.find(ch => getInitials(ch.name) === rawInitials);

                if (matched && matched.name) {
                    const rawStreamUrl = matched.mpd || matched.url || matched.streamUrl || "";
                    const streamUrl = rawStreamUrl.trim().replace(/[\r\n\t\s]/g, '');
                    const isMpd = !!(matched.mpd || streamUrl.includes('.mpd'));
                    const isHls = !!streamUrl.includes('.m3u8');

                    channelData = {
                        name: matched.name || "",
                        streamUrl: streamUrl,
                        isMpd: isMpd,
                        isHls: isHls,
                        keyId: matched.keyId || "",
                        key: matched.key || "",
                        token: matched.cookie || matched.token || "",
                        fallback_token: matched.fallback_cookie || "",
                        logo: matched.logo || ""
                    };
                }
            } catch (e) {
                console.error("Error fetching st- channel from as-stflx worker", e);
            }
        } else if (channelId.startsWith("cj-")) {
            try {
                const rawId = channelId.substring(3);
                let matched = null;

                if (rawId) {
                    try {
                        const directRes = await fetch(`https://as-cjbp.yinave4095.workers.dev/?id=${encodeURIComponent(rawId)}`, {
                            cf: { cacheTtl: 60, cacheEverything: true }
                        });
                        if (directRes.ok) {
                            const data = await directRes.json();
                            matched = Array.isArray(data) ? data[0] : data;
                        }
                    } catch (e) { }
                }

                if (!matched || (!matched.mpd && !matched.url && !matched.streamUrl)) {
                    const allowedData = await Promise.all(
                        BROBP_CHANNELS.map(async (id) => {
                            try {
                                const res = await fetch(`https://as-cjbp.yinave4095.workers.dev/?id=${encodeURIComponent(id)}`, {
                                    cf: { cacheTtl: 300, cacheEverything: true }
                                });
                                if (res.ok) {
                                    const json = await res.json();
                                    return Array.isArray(json) ? json[0] : json;
                                }
                            } catch (e) { }
                            return null;
                        })
                    );

                    const validAllowed = allowedData.filter(Boolean);
                    const getInitials = (name) => {
                        if (!name) return "";
                        return name.split(' ').filter(Boolean).map(w => {
                            const lowerW = w.toLowerCase();
                            if (lowerW === 'hindi') return 'hin';
                            if (lowerW === 'tamil') return 'tam';
                            if (lowerW === 'telugu') return 'tel';
                            if (lowerW === 'kannada') return 'kan';
                            if (lowerW === 'select') return 'sel';
                            if (lowerW === 'liv') return 'l';
                            return lowerW[0];
                        }).join('').toLowerCase();
                    };

                    matched = validAllowed.find(ch =>
                        getInitials(ch.name) === rawId ||
                        String(ch.id) === rawId ||
                        (ch.name && ch.name.toLowerCase().includes(rawId.toLowerCase()))
                    );
                }

                if (matched && (matched.name || matched.url || matched.mpd || matched.streamUrl)) {
                    const rawStreamUrl = matched.url || matched.mpd || matched.streamUrl || "";
                    const streamUrl = rawStreamUrl.trim().replace(/[\r\n\t\s]/g, '');
                    const isMpd = !!(matched.mpd || streamUrl.includes('.mpd'));
                    const isHls = !!streamUrl.includes('.m3u8');

                    channelData = {
                        name: matched.name || rawId,
                        streamUrl: streamUrl,
                        isMpd: isMpd,
                        isHls: isHls,
                        keyId: matched.keyId || matched.key_id || matched.kid || "",
                        key: matched.key || matched.key_hex || "",
                        token: matched.cookie || matched.token || "",
                        fallback_token: matched.fallback_cookie || "",
                        logo: matched.logo || ""
                    };
                }
            } catch (e) {
                console.error("Error fetching cj- channel from as-cjbp worker", e);
            }
        } else if (channelId.startsWith("jp") || channelId.startsWith("j")) {
            try {
                const targetEndpoint = channelId.startsWith("jp") ? "api/jtvplus/cache" : "api/jtv/cache";
                const rawId = channelId.replace(/^(jtvplus|jtv|jp|j)[_-]?/i, '');

                let matched = null;

                if (rawId && /^\d+$/.test(rawId)) {
                    const directRes = await fetch(`${getBrobpWorker(rawId)}/${targetEndpoint}?id=${encodeURIComponent(rawId)}`, {
                        cf: { cacheTtl: 120, cacheEverything: true }
                    }).catch(() => null);
                    if (directRes && directRes.ok) {
                        const data = await directRes.json();
                        matched = Array.isArray(data) ? data[0] : data;
                    }
                }

                if (!matched || (!matched.mpd && !matched.url && !matched.streamUrl)) {
                    const fallbackRes = await fetch(`https://as-cjbp.yinave4095.workers.dev/?id=${encodeURIComponent(rawId)}`, {
                        cf: { cacheTtl: 120, cacheEverything: true }
                    }).catch(() => null);
                    if (fallbackRes && fallbackRes.ok) {
                        const data = await fallbackRes.json();
                        matched = Array.isArray(data) ? data[0] : data;
                    }
                }

                if (!matched || !matched.name) {
                    const allowedData = await Promise.all(
                        BROBP_CHANNELS.map(async (id) => {
                            try {
                                const res = await fetch(`${getBrobpWorker(id)}/${targetEndpoint}?id=${encodeURIComponent(id)}`, {
                                    cf: { cacheTtl: 300, cacheEverything: true }
                                });
                                if (res.ok) {
                                    const json = await res.json();
                                    return Array.isArray(json) ? json[0] : json;
                                }
                            } catch (e) { }
                            return null;
                        })
                    );

                    const validAllowed = allowedData.filter(Boolean);
                    const getInitials = (name) => {
                        if (!name) return "";
                        return name.split(' ').filter(Boolean).map(w => {
                            const lowerW = w.toLowerCase();
                            if (lowerW === 'hindi') return 'hin';
                            if (lowerW === 'tamil') return 'tam';
                            if (lowerW === 'telugu') return 'tel';
                            if (lowerW === 'kannada') return 'kan';
                            if (lowerW === 'select') return 'sel';
                            if (lowerW === 'liv') return 'l';
                            return lowerW[0];
                        }).join('').toLowerCase();
                    };
                    const prefix = channelId.startsWith("jp") ? "jp" : "j";

                    matched = validAllowed.find(ch =>
                        (prefix + getInitials(ch.name)) === channelId ||
                        String(ch.id) === rawId ||
                        String(ch.id) === channelId ||
                        (ch.name && ch.name.toLowerCase().trim() === channelId.toLowerCase().trim())
                    );
                }

                if (matched && (matched.name || matched.url || matched.mpd || matched.streamUrl)) {
                    const rawStreamUrl = matched.mpd || matched.url || matched.streamUrl || "";
                    const streamUrl = rawStreamUrl.trim().replace(/[\r\n\t\s]/g, '');
                    const isMpd = !!(matched.mpd || streamUrl.includes('.mpd'));
                    const isHls = !!streamUrl.includes('.m3u8');

                    channelData = {
                        name: matched.name || rawId,
                        streamUrl: streamUrl,
                        isMpd: isMpd,
                        isHls: isHls,
                        keyId: matched.keyId || matched.key_id || "",
                        key: matched.key || matched.key_hex || "",
                        token: matched.cookie || matched.token || "",
                        fallback_token: matched.jtvplusfallbackcookie || matched.jtvfallbackcookie || matched.fallback_cookie || "",
                        logo: matched.logo || ""
                    };
                }
            } catch (e) {
                console.error("Error fetching channel from as-brobp worker", e);
            }
        }

        if (!channelData && !ALLOWED_CHANNELS.includes(channelId) && !BROBP_CHANNELS.includes(channelId)) {
            const FIREBASE_API_KEY = "AIzaSyD-nUtWeFqHLCWPOQaFDCgmHfCGjf7L6Mo";
            const FIREBASE_URL = `https://firestore.googleapis.com/v1/projects/sports-zone-ed3a9/databases/(default)/documents/matches?key=${FIREBASE_API_KEY}`;

            try {
                const fbRes = await fetch(FIREBASE_URL, { cf: { cacheTtl: 60, cacheEverything: true } });
                if (fbRes.ok) {
                    const fbData = await fbRes.json();
                    if (fbData.documents) {
                        for (const doc of fbData.documents) {
                            const match = doc.fields;
                            const matchName = match.matchName ? match.matchName.stringValue : "";
                            const matchInitials = matchName.split(' ').filter(Boolean).map(w => w[0]).join('').toLowerCase();

                            if (match.servers && match.servers.arrayValue && match.servers.arrayValue.values) {
                                const docId = doc.name ? doc.name.split('/').pop() : "";
                                for (const srv of match.servers.arrayValue.values) {
                                    const server = srv.mapValue.fields;
                                    const channelName = server.channelName ? server.channelName.stringValue : "";
                                    const channelInitials = channelName.split(' ').filter(Boolean).map(w => w[0]).join('').toLowerCase();
                                    const cleanChName = channelName.toLowerCase().replace(/[^a-z0-9]/g, '');
                                    const cleanChId = channelId.toLowerCase().replace(/[^a-z0-9]/g, '');

                                    const isMatch = (matchInitials + channelInitials) === cleanChId ||
                                        channelInitials === cleanChId ||
                                        cleanChName === cleanChId ||
                                        docId === channelId ||
                                        (matchName + " " + channelName).toLowerCase().replace(/[^a-z0-9]/g, '').includes(cleanChId);

                                    if (isMatch) {
                                        const mpd = server.mpd ? server.mpd.stringValue : "";
                                        const url = server.url ? server.url.stringValue : "";
                                        const key = server.key ? server.key.stringValue : "";
                                        const cookie = server.cookie ? server.cookie.stringValue : "";
                                        const typeStr = server.type ? server.type.stringValue.toLowerCase() : "";
                                        const rawStreamUrl = (mpd || url).trim().replace(/[\r\n\t\s]/g, '');
                                        let isMpd = false;
                                        let isHls = false;
                                        let isIframe = false;

                                        if (typeStr === "iframe" || rawStreamUrl.includes("embed") || rawStreamUrl.includes("wapka.site") || (!rawStreamUrl.includes(".m3u8") && !rawStreamUrl.includes(".mpd") && rawStreamUrl.includes("http"))) {
                                            isIframe = true;
                                        } else if (typeStr === "hls" || rawStreamUrl.includes(".m3u8")) {
                                            isHls = true;
                                        } else if (typeStr === "mpd" || typeStr === "dash" || rawStreamUrl.includes(".mpd")) {
                                            isMpd = true;
                                        } else if (mpd && !url) {
                                            isMpd = true;
                                        } else {
                                            isHls = true;
                                        }

                                        let keyId = "";
                                        let keyVal = "";
                                        if (key && key.includes(':')) {
                                            const parts = key.split(':');
                                            keyId = parts[0];
                                            keyVal = parts[1];
                                        }

                                        channelData = {
                                            name: channelName || matchName || "",
                                            streamUrl: rawStreamUrl,
                                            isMpd: isMpd,
                                            isHls: isHls,
                                            isIframe: isIframe,
                                            keyId: keyId,
                                            key: keyVal,
                                            token: cookie,
                                            isAdminCustom: true
                                        };
                                        break;
                                    }
                                }
                            }
                            if (channelData) break;
                        }
                    }
                }
            } catch (e) {
                console.error("Firebase fetch error", e);
            }

            if (!channelData) {
                try {
                    const FIREBASE_API_KEY = "AIzaSyD-nUtWeFqHLCWPOQaFDCgmHfCGjf7L6Mo";
                    const FIREBASE_CUSTOM_URL = `https://firestore.googleapis.com/v1/projects/sports-zone-ed3a9/databases/(default)/documents/fanxzone_custom?key=${FIREBASE_API_KEY}`;
                    const customFbRes = await fetch(FIREBASE_CUSTOM_URL, { cf: { cacheTtl: 10, cacheEverything: false } });
                    if (customFbRes.ok) {
                        const customFbData = await customFbRes.json();
                        if (customFbData.documents) {
                            for (const doc of customFbData.documents) {
                                const match = doc.fields || {};
                                const ssid = match.ssid ? match.ssid.stringValue.trim() : "";
                                const docId = doc.name ? doc.name.split('/').pop() : "";
                                const cleanChId = (channelId || "").trim().toLowerCase();

                                if (ssid === channelId || docId === channelId || (ssid && cleanChId === ssid.toLowerCase())) {
                                    const title = match.title ? match.title.stringValue : "";
                                    const rawStreamUrl = (match.streamUrl ? match.streamUrl.stringValue : "").trim().replace(/[\r\n\t\s]/g, '');
                                    const keys = match.keys ? match.keys.stringValue : "";
                                    const cookie = match.cookie ? match.cookie.stringValue : "";
                                    const isHls = match.isHls ? (typeof match.isHls.booleanValue === 'boolean' ? match.isHls.booleanValue : match.isHls.stringValue === "true") : rawStreamUrl.includes(".m3u8");
                                    const isMpd = match.isMpd ? (typeof match.isMpd.booleanValue === 'boolean' ? match.isMpd.booleanValue : match.isMpd.stringValue === "true") : (!isHls || rawStreamUrl.includes(".mpd"));

                                    let keyId = "";
                                    let keyVal = "";
                                    if (keys && keys.includes(':')) {
                                        const parts = keys.split(':');
                                        keyId = parts[0].trim();
                                        keyVal = parts[1].trim();
                                    } else if (keys) {
                                        keyVal = keys.trim();
                                    }

                                    channelData = {
                                        name: title || ssid,
                                        streamUrl: rawStreamUrl,
                                        isMpd: isMpd,
                                        isHls: isHls,
                                        isIframe: false,
                                        keyId: keyId,
                                        key: keyVal,
                                        token: cookie,
                                        isAdminCustom: true
                                    };
                                    break;
                                }
                            }
                        }
                    }
                } catch (e) {
                    console.error("Firebase custom channel fetch error", e);
                }
            }

            if (!channelData) {
                // SECURITY FIX: Removed unrestricted fallback to as-cjbp for unknown IDs to prevent open proxying.
                if (!channelData) {
                    try {
                        const allowedData = await Promise.all(
                            ALLOWED_CHANNELS.map(async (id) => {
                                try {
                                    const res = await fetch(`https://as-test.rabba.workers.dev/?id=${id}`, { cf: { cacheTtl: 300, cacheEverything: true } });
                                    if (res.ok) {
                                        const json = await res.json();
                                        return Array.isArray(json) ? json[0] : json;
                                    }
                                } catch (e) { }
                                return null;
                            })
                        );

                        const validAllowed = allowedData.filter(Boolean);
                        const getInitials = (name) => {
                            if (!name) return "";
                            return name.split(' ').filter(Boolean).map(w => {
                                const lowerW = w.toLowerCase();
                                if (lowerW === 'hindi') return 'hin';
                                if (lowerW === 'tamil') return 'tam';
                                if (lowerW === 'telugu') return 'tel';
                                if (lowerW === 'kannada') return 'kan';
                                if (lowerW === 'select') return 'sel';
                                if (lowerW === 'liv') return 'l';
                                return lowerW[0];
                            }).join('').toLowerCase();
                        };

                        const matched = validAllowed.find(ch => getInitials(ch.name) === channelId);
                        if (matched && matched.name) {
                            const rawStreamUrl = matched.mpd || matched.url || matched.streamUrl || "";
                            const streamUrl = rawStreamUrl.trim().replace(/[\r\n\t\s]/g, '');
                            channelData = {
                                name: matched.name || "",
                                streamUrl: streamUrl,
                                isMpd: !!(matched.mpd || streamUrl.includes('.mpd')),
                                isHls: !!streamUrl.includes('.m3u8'),
                                keyId: matched.keyId || "",
                                key: matched.key || "",
                                token: matched.cookie || matched.token || "",
                                fallback_token: matched.jtvplusfallbackcookie || matched.jtvfallbackcookie || matched.fallback_cookie || "",
                                logo: matched.logo || ""
                            };
                        }
                    } catch (e) {
                        console.error("Error fetching as-test initials fallback", e);
                    }
                }
            }
        } else {
            let apiUrl = "";
            if (ALLOWED_CHANNELS.includes(channelId)) {
                apiUrl = `https://as-test.rabba.workers.dev/?id=${encodeURIComponent(channelId)}`;
            } else {
                apiUrl = `${getBrobpWorker(channelId)}/api/jtv/cache?id=${encodeURIComponent(channelId)}`;
            }

            try {
                const apiResponse = await fetch(apiUrl, {
                    headers: {
                        "User-Agent": "Cloudflare-Worker"
                    },
                    cf: { cacheTtl: 300, cacheEverything: true }
                });

                if (apiResponse.ok) {
                    const data = await apiResponse.json();
                    const matched = Array.isArray(data) ? data[0] : data;
                    if (matched) {
                        const streamUrl = matched.mpd || matched.url || matched.streamUrl || "";
                        const isMpd = !!(matched.mpd || streamUrl.includes('.mpd'));
                        const isHls = !!streamUrl.includes('.m3u8');

                        channelData = {
                            name: matched.name || "",
                            streamUrl: streamUrl,
                            isMpd: isMpd,
                            isHls: isHls,
                            keyId: matched.keyId || "",
                            key: matched.key || "",
                            token: matched.cookie || matched.token || "",
                            fallback_token: matched.jtvplusfallbackcookie || matched.jtvfallbackcookie || matched.fallback_cookie || "",
                            logo: matched.logo || ""
                        };
                    }
                }
            } catch (error) {
                console.error("Worker Fetch Error:", error);
            }
        }

        if (
            !channelData ||
            Object.keys(channelData).length === 0
        ) {

            return new Response(
                "404 Not Found",
                {
                    status: 404
                }
            );
        }

        const sessionToken = await createStreamSessionToken(channelData, clientIp);
        const manifestProxyToken = await createProxyToken(1, sessionToken, channelData.streamUrl);
        const drmProxyToken = await createProxyToken(3, sessionToken, "");

        let finalStreamUrl = channelData.streamUrl;
        const isJioStream = isJioUrl(finalStreamUrl);

        if (isJioStream) {
            const rawToken = channelData.token || channelData.fallback_token || "";
            finalStreamUrl = attachJioTokenToUrl(finalStreamUrl, rawToken);
        }

        const proxiedChannel = {
            name: channelData.name || "",
            streamUrl: (channelData.isAdminCustom || isJioStream || channelData.isIframe) ? finalStreamUrl : `https://${domain}/api/proxy/${manifestProxyToken}`,
            isMpd: !!channelData.isMpd,
            isHls: !!channelData.isHls,
            isIframe: !!channelData.isIframe,
            hasDrm: !!(channelData.keyId && channelData.key && !channelData.keyId.includes("Error")),
            drmLicenseUrl: `https://${domain}/api/proxy/${drmProxyToken}`
        };

        const safeChannelJson =
            JSON.stringify(proxiedChannel)
                .replace(/</g, "\\u003c");


        const hasCookie = !!((channelData.token && channelData.token.trim()) || (channelData.fallback_token && channelData.fallback_token.trim()) || finalStreamUrl.includes("hdnea=") || finalStreamUrl.includes("__hdnea__="));

        if (proxiedChannel.isMpd && !hasCookie) {
            const mpdStreamUrl = proxiedChannel.streamUrl || "";
            const mpdKeyParam = (channelData.keyId && channelData.key && !channelData.keyId.includes("Error")) ? `${channelData.keyId}:${channelData.key}` : "";
            const mpdPlayerHtml = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <title>SPORTS ZONE - MEDIA PLAYER</title>

  <!-- Shaka Player -->
  <script
    src="https://cdnjs.cloudflare.com/ajax/libs/shaka-player/4.7.11/shaka-player.ui.min.js"
    crossorigin="anonymous">
  </script>

  <link
    rel="stylesheet"
    href="https://cdnjs.cloudflare.com/ajax/libs/shaka-player/4.7.11/controls.min.css"
    crossorigin="anonymous">

  <!-- Ad Script -->
  <script
    id="aclib"
    type="text/javascript"
    src="//acscdn.com/script/aclib.js">
  </script>

  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    html,
    body {
      background: #000;
      width: 100vw;
      height: 100vh;
      overflow: hidden;
      font-family: system-ui, -apple-system, sans-serif;
    }

    .shaka-video-container {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      background: #000;
    }

    video {
      width: 100%;
      height: 100%;
      background: #000;
      object-fit: contain;
    }

    .shaka-spinner-container,
    .shaka-spinner,
    .shaka-spinner-svg {
      display: none !important;
      visibility: hidden !important;
      opacity: 0 !important;
    }
  </style>
</head>

<body>

  <div
    class="shaka-video-container"
    data-shaka-player>

    <video
      autoplay
      playsinline
      preload="metadata"
      poster="">
    </video>

  </div>


  <script>

    /*
     * ============================================
     * 1. JOIN CHANNEL PROMPT
     * ============================================
     */

    window.addEventListener('DOMContentLoaded', () => {

      const join = confirm("Join Our Channel");

      if (join) {
        location.href =
          "https://t.me/+rtK_sfY8t_A2NDU1";
      }

    });


    /*
     * ============================================
     * 2. SHAKA PLAYER
     * ============================================
     */

    document.addEventListener('DOMContentLoaded', async () => {

      shaka.polyfill.installAll();

      if (!shaka.Player.isBrowserSupported()) {

        console.error(
          'Browser not supported by Shaka Player'
        );

        return;
      }


      /*
       * GET URL PARAMETERS
       *
       * ?url=MPD_URL&key=KID:KEY
       */

      const params =
        new URLSearchParams(
          window.location.search
        );

      const streamUrl =
        params.get('url') || "${mpdStreamUrl}";

      const keyParam =
        params.get('key') || "${mpdKeyParam}";


      /*
       * VALIDATE MPD
       */

      if (!streamUrl) {

        console.error(
          'Missing ?url=MPD_URL parameter'
        );

        return;
      }


      /*
       * VALIDATE KEY
       */

      if (!keyParam) {

        console.error(
          'Missing ?key=KID:KEY parameter'
        );

        return;
      }


      /*
       * PARSE KID:KEY
       */

      const separatorIndex =
        keyParam.indexOf(':');


      if (separatorIndex === -1) {

        console.error(
          'Invalid key format. Expected KID:KEY'
        );

        return;
      }


      const kid =
        keyParam
          .substring(0, separatorIndex)
          .trim();


      const key =
        keyParam
          .substring(separatorIndex + 1)
          .trim();


      if (!kid || !key) {

        console.error(
          'Invalid KID or KEY'
        );

        return;
      }


      console.log(
        'MPD URL:',
        streamUrl
      );

      console.log(
        'KID:',
        kid
      );


      /*
       * PLAYER
       */

      const video =
        document.querySelector('video');


      const player =
        new shaka.Player();


      await player.attach(video);\n
        const shakaContainer = document.querySelector(".shaka-video-container");
        if (shakaContainer) {
            const ui = new shaka.ui.Overlay(player, shakaContainer, video);
            ui.configure({
                controlPanelElements: [
                    'play_pause', 'time_and_duration', 'mute', 'volume',
                    'spacer', 'language', 'captions', 'picture_in_picture',
                    'quality', 'fullscreen'
                ],
                volumeBarColors: {
                    base: 'rgba(0, 136, 255, 0.3)',
                    level: 'rgb(0, 136, 255)'
                },
                seekBarColors: {
                    base: 'rgba(0, 136, 255, 0.3)',
                    buffered: 'rgba(0, 136, 255, 0.6)',
                    played: 'rgb(0, 136, 255)'
                }
            });
        }



      /*
       * SHAKA UI
       */

      const container =
        document.querySelector(
          '.shaka-video-container'
        );


      const ui =
        new shaka.ui.Overlay(
          player,
          container,
          video
        );


      ui.configure({

        controlPanelElements: [

          'play_pause',
          'time_and_duration',
          'mute',
          'volume',
          'spacer',
          'language',
          'captions',
          'picture_in_picture',
          'quality',
          'fullscreen'

        ],

        volumeBarColors: {

          base:
            'rgba(0, 136, 255, 0.3)',

          level:
            'rgb(0, 136, 255)'

        },

        seekBarColors: {

          base:
            'rgba(0, 136, 255, 0.3)',

          buffered:
            'rgba(0, 136, 255, 0.6)',

          played:
            'rgb(0, 136, 255)'

        }

      });


      /*
       * CLEARKEY DRM
       */

      const drmConfig = {

        clearKeys: {

          [kid]: key

        }

      };


      /*
       * PLAYER CONFIG
       */

      player.configure({

        drm: drmConfig,

        streaming: {

          lowLatencyMode: true,

          bufferingGoal: 15,

          rebufferingGoal: 2,

          bufferBehind: 15,

          retryParameters: {

            timeout: 10000,

            maxAttempts: 5,

            baseDelay: 300,

            backoffFactor: 1.2

          },

          segmentRequestTimeout: 8000,

          segmentPrefetchLimit: 2,

          useNativeHlsOnSafari: true

        },

        manifest: {

          retryParameters: {

            timeout: 8000,

            maxAttempts: 3

          }

        }

      });


      /*
       * ERROR HANDLER
       */

      player.addEventListener(
        'error',
        (event) => {

          console.error(
            'Shaka Player Error:',
            event.detail
          );

        }
      );


      /*
       * JIO / HDNEA TOKEN FILTER FOR SEGMENTS
       */

      let jioTokenParam = "";

      if (streamUrl.includes("__hdnea__=")) {
        try {
          jioTokenParam = "__hdnea__=" + streamUrl.split("__hdnea__=")[1].split("&")[0];
        } catch (e) {}
      } else if (streamUrl.includes("hdnea=")) {
        try {
          jioTokenParam = "hdnea=" + streamUrl.split("hdnea=")[1].split("&")[0];
        } catch (e) {}
      } else if (params.get('token')) {
        let t = params.get('token').trim();
        if (t.startsWith("__hdnea__=") || t.startsWith("hdnea=")) {
          jioTokenParam = t;
        } else if (t) {
          jioTokenParam = "__hdnea__=" + t;
        }
      } else if (params.get('cookie')) {
        let t = params.get('cookie').trim();
        if (t.startsWith("__hdnea__=") || t.startsWith("hdnea=")) {
          jioTokenParam = t;
        } else if (t) {
          jioTokenParam = "__hdnea__=" + t;
        }
      }

      if (jioTokenParam) {
        player.getNetworkingEngine().registerRequestFilter((type, request) => {
          if (request.uris && request.uris.length > 0) {
            for (let i = 0; i < request.uris.length; i++) {
              let uri = request.uris[i];
              if (!uri.includes("__hdnea__=") && !uri.includes("hdnea=")) {
                const separator = uri.includes("?") ? "&" : "?";
                request.uris[i] = uri + separator + jioTokenParam;
              }
            }
          }
        });
      }


      /*
       * LOAD STREAM
       */

      try {

        await player.load(streamUrl);

        console.log(
          'Stream loaded successfully'
        );


        /*
         * AUTOPLAY
         */

        try {

          await video.play();

          console.log(
            'Autoplay started'
          );

        } catch (autoplayError) {

          console.warn(
            'Autoplay blocked:',
            autoplayError
          );

        }

      } catch (error) {

        console.error(
          'MPD Load Error:',
          error
        );

      }

    });


    /*
     * ============================================
     * 3. FIRST CLICK AD
     * ============================================
     */

    let firstClickHandled = false;


    document.addEventListener(
      'click',
      function () {

        if (firstClickHandled) {
          return;
        }

        firstClickHandled = true;


        if (
          typeof aclib !== 'undefined' &&
          typeof aclib.runPop === 'function'
        ) {

          try {

            aclib.runPop({
              zoneId: '11800802'
            });

          } catch (error) {

            console.error(
              'Ad error:',
              error
            );

          }

        }

      },
      {
        once: true,
        passive: true
      }
    );

  </script>

</body>
</html>
`;

            return new Response(mpdPlayerHtml, {
                headers: {
                    "Content-Type": "text/html;charset=UTF-8",
                    "Access-Control-Allow-Origin": "*"
                }
            });
        }

        let html = `<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width,
        initial-scale=1.0,
        maximum-scale=1.0,
        user-scalable=no"
    >

    <title>Live TV Player</title>

    <!-- ==========================================
         HLS.JS & SHAKA PLAYER
         ========================================== -->

    <script src="https://cdnjs.cloudflare.com/ajax/libs/hls.js/1.5.17/hls.min.js"></script>

    <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/shaka-player/4.7.11/controls.min.css"
    >

    <script
        src="https://cdnjs.cloudflare.com/ajax/libs/shaka-player/4.7.11/shaka-player.ui.min.js">
    </script>

    <!-- ==========================================
         MUX
         ========================================== -->

    <script
        src="https://cdn.jsdelivr.net/npm/mux.js@6.2.0/dist/mux.min.js">
    </script>

    <!-- ==========================================
         ADS
         ========================================== -->

    <script
        id="aclib"
        type="text/javascript"
        src="https://acscdn.com/script/aclib.js">
    </script>

    <style>

        /* ==========================================
           BASIC
           ========================================== */

        html,
        body {

            margin: 0;
            padding: 0;

            width: 100%;
            height: 100%;

            background: #000;

            overflow: hidden;

            font-family:
                "Segoe UI",
                Tahoma,
                Geneva,
                Verdana,
                sans-serif;

            touch-action: manipulation;
        }

        /* ==========================================
           PLAYER
           ========================================== */

        .shaka-video-container {

            width: 100vw;
            height: 100vh;

            background: #000;

            position: relative;
        }

        video {

            width: 100%;
            height: 100%;

            object-fit: contain;

            background: #000;

            display: block;
        }

        /* ==========================================
           LOADING
           ========================================== */

        #loading-text {
            display: none;
            position: absolute;

            top: 50%;
            left: 50%;

            transform:
                translate(-50%, -50%);

            color: #fff;

            font-size: 18px;

            z-index: 100;

            text-align: center;

            white-space: nowrap;
        }

        /* ==========================================
           ERROR
           ========================================== */

        #error-text {

            display: none;

            position: absolute;

            top: 50%;
            left: 50%;

            transform:
                translate(-50%, -50%);

            color: #fff;

            font-size: 17px;

            z-index: 100;

            text-align: center;
        }

        /* ==========================================
           BUFFERING
           ========================================== */

        #buffering-indicator {

            display: none;

            position: absolute;

            left: 50%;
            top: 50%;

            transform:
                translate(-50%, -50%);

            z-index: 90;

            width: 42px;
            height: 42px;

            border:
                4px solid
                rgba(255, 255, 255, 0.25);

            border-top-color:
                #00c6ff;

            border-radius: 50%;

            animation:
                spin 0.8s linear infinite;

            pointer-events: none;
        }

        @keyframes spin {

            to {

                transform:
                    translate(-50%, -50%)
                    rotate(360deg);
            }
        }

        /* ==========================================
           ADBLOCK WARNING
           ========================================== */

        #adblock-warning {

            display: none;

            position: fixed;

            inset: 0;

            background: #000;

            color: #fff;

            z-index: 9999999;

            flex-direction: column;

            justify-content: center;

            align-items: center;

            text-align: center;

            padding: 20px;

            box-sizing: border-box;
        }

        #adblock-warning h2 {

            color: #ff4500;

            font-size: 28px;

            margin-bottom: 15px;
        }

        #adblock-warning p {

            font-size: 18px;

            max-width: 600px;

            line-height: 1.5;
        }

        /* ==========================================
           CUSTOM CONTROL STATE
           ========================================== */

        .custom-controls-hidden {
            opacity: 0 !important;
            visibility: hidden !important;
            pointer-events: none !important;
        }

        /* ==========================================
           HEADER BAR WITH PURE WHITE LOGO
           ========================================== */
        #player-header {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 64px;
            background: transparent !important; /* NO BACKGROUND BEHIND LOGOS */
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 24px;
            z-index: 1000;
            pointer-events: none;
            transition: opacity 0.3s ease;
        }

        .header-left {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        #channel-logo {
            max-height: 38px;
            max-width: 140px;
            object-fit: contain;
            filter: brightness(0) invert(1) !important; /* PURE WHITE LOGO */
        }

        #channel-name {
            color: #ffffff;
            font-size: 17px;
            font-weight: 700;
            letter-spacing: 0.5px;
            text-shadow: 0 2px 6px rgba(0,0,0,0.9);
        }

        .live-tag {
            background: #ff1e1e;
            color: #ffffff;
            font-size: 12px;
            font-weight: 800;
            padding: 4px 12px;
            border-radius: 4px;
            display: flex;
            align-items: center;
            gap: 6px;
            letter-spacing: 1px;
            box-shadow: 0 2px 8px rgba(255, 30, 30, 0.4);
        }

        .live-dot {
            width: 7px;
            height: 7px;
            background: #ffffff;
            border-radius: 50%;
            animation: pulse-live 1.2s ease-in-out infinite;
        }

        @keyframes pulse-live {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(0.8); }
        }

        /* ==========================================
           SOLID PROFESSIONAL CONTROL BAR (NO GLASS EFFECT)
           ========================================== */
        #custom-player-controls {
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 60px;
            background: transparent !important; /* NO BACKGROUND COLOR */
            border-top: none !important;
            box-shadow: none !important;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 20px;
            z-index: 1000;
            transition: opacity 0.3s ease, visibility 0.3s ease;
        }

        .controls-left, .controls-right {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        #custom-player-controls button {
            background: transparent;
            border: none;
            color: #ffffff;
            cursor: pointer;
            padding: 6px;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: background 0.2s ease, transform 0.1s ease;
        }

        #custom-player-controls button:hover {
            background: #1e202c;
        }

        #custom-player-controls button:active {
            transform: scale(0.94);
        }

        /* NORMAL SKY COLOR VOLUME BAR WITH NO GLOW */
        .volume-container {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        input[type=range].colorful-volume-slider {
            -webkit-appearance: none;
            width: 90px;
            height: 4px;
            background: rgba(255, 255, 255, 0.3);
            border-radius: 2px;
            outline: none;
            cursor: pointer;
        }

        input[type=range].colorful-volume-slider::-webkit-slider-runnable-track {
            height: 4px;
            border-radius: 2px;
            background: transparent;
        }

        input[type=range].colorful-volume-slider::-webkit-slider-thumb {
            -webkit-appearance: none;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #ffffff !important;
            box-shadow: none !important; /* NO GLOW */
            cursor: pointer;
            margin-top: -4px;
        }

        /* QUALITY SELECTOR WITH GEAR LOGO */
        .quality-wrapper {
            display: flex;
            align-items: center;
            gap: 4px;
            background: transparent;
            padding: 2px 6px;
            border-radius: 6px;
        }

        #quality-selector {
            background: transparent;
            color: #ffffff;
            border: none;
            padding: 4px 2px;
            font-size: 13px;
            font-weight: 600;
            outline: none;
            cursor: pointer;
        }

        #quality-selector option {
            background: #14151f;
            color: #ffffff;
        }

        /* ==========================================
           FULL RESPONSIVE MEDIA QUERIES (MOBILE, TABLET, DESKTOP)
           ========================================== */
        #custom-player-controls {
            z-index: 2147483647 !important;
        }

        #player-header {
            z-index: 2147483647 !important;
        }

        @media (max-width: 600px) {
            #player-header {
                height: 48px;
                padding: 0 12px;
            }

            #channel-logo {
                max-height: 28px;
                max-width: 100px;
            }

            #channel-name {
                font-size: 14px;
            }

            .live-tag {
                font-size: 10px;
                padding: 3px 8px;
            }

            #custom-player-controls {
                height: 48px;
                padding: 0 10px;
            }

            .controls-left, .controls-right {
                gap: 8px;
            }

            input[type=range].colorful-volume-slider {
                width: 60px;
            }

            #quality-selector {
                font-size: 11px;
                padding: 2px 0;
            }

            #custom-player-controls button {
                padding: 4px;
            }

            #custom-player-controls svg {
                width: 18px;
                height: 18px;
            }
        }

        @media (max-width: 380px) {
            input[type=range].colorful-volume-slider {
                width: 45px;
            }

            .header-left {
                gap: 6px;
            }

            #channel-name {
                max-width: 90px;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }
        }

    </style>

</head>

<body>

    <!-- HEADER BAR WITH PURE WHITE LOGO (NO TV ICON) -->
    <div id="player-header">
        <div class="header-left">
            <img id="channel-logo" src="${safeChannelJson}" alt="Logo" style="filter: brightness(0) invert(1);" onError="this.style.display='none';" />
            <span id="channel-name">Live Channel</span>
        </div>
        <div class="header-right">
            <div class="live-tag"><span class="live-dot"></span> LIVE</div>
        </div>
    </div>

    <!-- ==========================================
         ADBLOCK WARNING
         ========================================== -->

    <div id="adblock-warning">

        <h2>
            Adblocker Detected!
        </h2>

        <p>
            Please disable your Adblocker,
            Brave Shields, or uBlock Origin
            to watch this stream.
            Refresh the page after disabling.
        </p>

    </div>

    <!-- ==========================================
         LOADING
         ========================================== -->

    <div id="loading-text">
        Starting Stream...
    </div>

    <!-- ==========================================
         ERROR
         ========================================== -->

    <div id="error-text">
        Reconnecting...
    </div>

    <!-- ==========================================
         BUFFERING
         ========================================== -->

    <div id="buffering-indicator"></div>

    <!-- ==========================================
         PLAYER
         ========================================== -->

    <div class="shaka-video-container">

        <video
            id="video"
            autoplay
            muted
            playsinline
            webkit-playsinline
            x5-playsinline="true"
            x5-video-player-type="h5"
            x5-video-player-fullscreen="true"
            preload="auto">
        </video>

    </div>

    <!-- CUSTOM BROADCAST CONTROL BAR (NO GLASS EFFECT - SOLID PREMIUM DARK) -->
    <div id="custom-player-controls" class="controls-overlay">
        <div class="controls-left">
            <button id="btn-play-pause" title="Play/Pause">
                <svg id="icon-play" viewBox="0 0 24 24" width="22" height="22" fill="#fff"><path d="M8 5v14l11-7z"/></svg>
                <svg id="icon-pause" viewBox="0 0 24 24" width="22" height="22" fill="#fff" style="display:none;"><path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/></svg>
            </button>

            <!-- COLORFUL VOLUME BAR -->
            <div class="volume-container">
                <button id="btn-mute" title="Mute/Unmute">
                    <svg id="icon-vol-high" viewBox="0 0 24 24" width="20" height="20" fill="#fff"><path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02zM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77z"/></svg>
                    <svg id="icon-vol-mute" viewBox="0 0 24 24" width="20" height="20" fill="#ff4444" style="display:none;"><path d="M16.5 12c0-1.77-1.02-3.29-2.5-4.03v2.21l2.45 2.45c.03-.2.05-.41.05-.63zm2.5 0c0 .94-.2 1.82-.54 2.64l1.51 1.51C20.63 14.91 21 13.5 21 12c0-4.28-2.99-7.86-7-8.77v2.06c2.89.86 5 3.54 5 6.71zM4.27 3L3 4.27 7.73 9H3v6h4l5 5v-6.73l4.25 4.25c-.67.52-1.42.93-2.25 1.18v2.06c1.38-.31 2.63-.95 3.69-1.81L19.73 21 21 19.73 4.27 3zM12 4L9.91 6.09 12 8.18V4z"/></svg>
                </button>
                <input type="range" id="volume-slider" min="0" max="1" step="0.05" value="1" class="colorful-volume-slider" title="Volume" />
            </div>
        </div>

        <div class="controls-right">
            <!-- QUALITY SELECTOR WITH GEAR LOGO -->
            <div class="quality-wrapper" title="Stream Quality">
                <svg viewBox="0 0 24 24" width="20" height="20" fill="#ffffff" style="margin-right:2px;"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/></svg>
                <select id="quality-selector">
                    <option value="auto">Auto</option>
                </select>
            </div>

            <!-- ASPECT RATIO TOGGLE -->
            <button id="btn-aspect" title="Aspect Ratio">
                <svg viewBox="0 0 24 24" width="20" height="20" fill="#fff"><path d="M19 12h-2v3h-3v2h5v-5zM7 9h3V7H5v5h2V9zm14-6H3c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h18c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H3V5h18v14z"/></svg>
                <span id="aspect-label" style="font-size:12px; margin-left:4px; font-weight:bold;">Fit</span>
            </button>

            <!-- PICTURE IN PICTURE -->
            <button id="btn-pip" title="Picture in Picture">
                <svg viewBox="0 0 24 24" width="20" height="20" fill="#fff"><path d="M19 7h-8v6h8V7zm2-4H3c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h18c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H3V5h18v14z"/></svg>
            </button>

            <!-- FULLSCREEN TOGGLE -->
            <button id="btn-fullscreen" title="Fullscreen">
                <svg id="icon-fs-enter" viewBox="0 0 24 24" width="20" height="20" fill="#fff"><path d="M7 14H5v5h5v-2H7v-3zm-2-4h2V7h3V5H5v5zm12 7h-3v2h5v-5h-2v3zM14 5v2h3v3h2V5h-5z"/></svg>
                <svg id="icon-fs-exit" viewBox="0 0 24 24" width="20" height="20" fill="#fff" style="display:none;"><path d="M5 16h3v3h2v-5H5v2zm3-8H5v2h5V5H8v3zm6 11h2v-3h3v-2h-5v5zm2-11V5h-2v5h5V8h-3z"/></svg>
            </button>
        </div>
    </div>

<script>
(function() {
    'use strict';

    try {
        const _n = function() {};
        console.log = _n; console.dir = _n; console.warn = _n; console.table = _n;
    } catch (e) { }

    const channel = Object.freeze(${safeChannelJson});

    let activePlayer = null;

    let isCurrentStreamHls = false;

    let isRecovering = false;

    let recoveryTimer = null;

    let stallTimer = null;

    let lastRecoveryTime = 0;

    const RECOVERY_COOLDOWN = 4000;

    let adCooldownUntil = 0;

    const AD_COOLDOWN = 12000;

    let suppressCurrentInteraction = false;

    let controlsVisible = false;

    let controlsHideTimer = null;

    function checkAdblock() {

        setTimeout(() => {

            let isBlocked = false;

            if (
                typeof aclib === "undefined"
            ) {

                isBlocked = true;
            }

            const bait =
                document.createElement("div");

            bait.innerHTML =
                "&nbsp;";

            bait.className =
                "pub_300x250 " +
                "pub_300x250m " +
                "pub_728x90 " +
                "text-ad " +
                "textAd " +
                "text_ad " +
                "text_ads " +
                "text-ads " +
                "text-ad-links";

            bait.style.position =
                "absolute";

            bait.style.top =
                "-9999px";

            bait.style.left =
                "-9999px";

            document.body.appendChild(
                bait
            );

            setTimeout(() => {

                const style =
                    window.getComputedStyle(
                        bait
                    );

                if (

                    bait.offsetHeight === 0 ||

                    bait.clientHeight === 0 ||

                    style.display === "none" ||

                    style.visibility === "hidden"

                ) {

                    isBlocked = true;
                }

                if (isBlocked) {

                    const container =
                        document.querySelector(
                            ".shaka-video-container"
                        );

                    const loading =
                        document.getElementById(
                            "loading-text"
                        );

                    if (container) {

                        container.style.display =
                            "none";
                    }

                    if (loading) {

                        loading.style.display =
                            "none";
                    }

                    const warning =
                        document.getElementById(
                            "adblock-warning"
                        );

                    if (warning) {

                        warning.style.display =
                            "flex";
                    }

                }

                bait.remove();

            }, 150);

        }, 800);
    }

    checkAdblock();

    function triggerAd() {

        const now =
            Date.now();

        if (
            now < adCooldownUntil
        ) {

            return false;
        }

        try {

            if (

                typeof aclib !== "undefined" &&

                typeof aclib.runPop ===
                    "function"

            ) {

                aclib.runPop({

                    zoneId:
                        "11800802"

                });

            }

        } catch (error) {

            console.warn(
                "Ad trigger error:",
                error
            );

        }

        adCooldownUntil =
            now + AD_COOLDOWN;

        return true;
    }

    function getControlsContainer() {

        const playerContainer =
            document.querySelector(
                ".shaka-video-container"
            );

        if (!playerContainer) {

            return null;
        }

        return playerContainer.querySelector(
            ".shaka-controls-container"
        );
    }

    function isShakaControl(target) {

        if (!target) {

            return false;
        }

        return !!target.closest(

            ".shaka-controls-container, " +

            ".shaka-control, " +

            ".shaka-play-button, " +

            ".shaka-volume-bar-container, " +

            ".shaka-overflow-menu, " +

            ".shaka-settings-menu, " +

            ".shaka-resolution-button, " +

            ".shaka-language-button, " +

            ".shaka-fullscreen-button"

        );
    }

    function showPlayerControls(autoHide = true) {
        const controls = getControlsContainer();
        const customControls = document.getElementById("custom-player-controls");
        const playerHeader = document.getElementById("player-header");

        if (controls) {
            controls.classList.remove("shaka-controls-hidden");
            controls.classList.remove("custom-controls-hidden");
            controls.style.opacity = "1";
            controls.style.visibility = "visible";
            controls.style.pointerEvents = "auto";
        }

        if (isCurrentStreamHls) {
            if (customControls) {
                customControls.style.display = "flex";
                customControls.classList.remove("custom-controls-hidden");
                customControls.style.opacity = "1";
                customControls.style.visibility = "visible";
                customControls.style.pointerEvents = "auto";
            }

            if (playerHeader) {
                playerHeader.style.display = "flex";
                playerHeader.classList.remove("custom-controls-hidden");
                playerHeader.style.opacity = "1";
                playerHeader.style.visibility = "visible";
            }
        } else {
            if (customControls) customControls.style.display = "none";
            if (playerHeader) playerHeader.style.display = "none";
        }

        controlsVisible = true;
        clearTimeout(controlsHideTimer);

        if (autoHide) {
            controlsHideTimer = setTimeout(() => {
                hidePlayerControls();
            }, 4000);
        }
    }

    function hidePlayerControls() {
        const controls = getControlsContainer();
        const customControls = document.getElementById("custom-player-controls");
        const playerHeader = document.getElementById("player-header");

        if (controls) {
            controls.classList.add("custom-controls-hidden");
        }

        if (isCurrentStreamHls) {
            if (customControls) {
                customControls.classList.add("custom-controls-hidden");
                customControls.style.opacity = "0";
                customControls.style.visibility = "hidden";
                customControls.style.pointerEvents = "none";
            }

            if (playerHeader) {
                playerHeader.classList.add("custom-controls-hidden");
                playerHeader.style.opacity = "0";
                playerHeader.style.visibility = "hidden";
            }
        } else {
            if (customControls) customControls.style.display = "none";
            if (playerHeader) playerHeader.style.display = "none";
        }

        controlsVisible = false;
        clearTimeout(controlsHideTimer);
    }

    function togglePlayerControls() {

        if (controlsVisible) {

            hidePlayerControls();

        } else {

            showPlayerControls(true);

        }
    }

    function showBuffering() {

        const indicator =
            document.getElementById(
                "buffering-indicator"
            );

        if (indicator) {

            indicator.style.display =
                "block";
        }
    }

    function hideBuffering() {
        const indicator =
            document.getElementById(
                "buffering-indicator"
            );

        if (indicator) {
            indicator.style.display =
                "none";
        }
    }

    function showCustomErrorNotice(msg) {
        let errNotice = document.getElementById("custom-error-notice");
        if (!errNotice) {
            errNotice = document.createElement("div");
            errNotice.id = "custom-error-notice";
            errNotice.style.position = "absolute";
            errNotice.style.top = "50%";
            errNotice.style.left = "50%";
            errNotice.style.transform = "translate(-50%, -50%)";
            errNotice.style.background = "rgba(18, 18, 22, 0.95)";
            errNotice.style.border = "2px solid #ff4444";
            errNotice.style.borderRadius = "12px";
            errNotice.style.color = "#ffffff";
            errNotice.style.padding = "24px 32px";
            errNotice.style.textAlign = "center";
            errNotice.style.zIndex = "999999";
            errNotice.style.boxShadow = "0 8px 32px rgba(0, 0, 0, 0.85)";
            errNotice.style.fontFamily = "sans-serif";
            errNotice.style.maxWidth = "85%";
            document.body.appendChild(errNotice);
        }
        errNotice.innerHTML = '<div style="font-size: 34px; margin-bottom: 8px;">⚠️</div>' +
            '<div style="font-size: 20px; font-weight: bold; color: #ff5555; margin-bottom: 8px;">Stream Error</div>' +
            '<div style="font-size: 16px; color: #e0e0e0; line-height: 1.4;">' + msg + '</div>';
        errNotice.style.display = "block";
        hideBuffering();
        const loadingText = document.getElementById("loading-text");
        if (loadingText) loadingText.style.display = "none";
        const errorText = document.getElementById("error-text");
        if (errorText) errorText.style.display = "none";
    }

    function hideCustomErrorNotice() {
        const errNotice = document.getElementById("custom-error-notice");
        if (errNotice) errNotice.style.display = "none";
    }

    async function recoverPlayer(
        reason = "unknown"
    ) {

        if (!activePlayer) {

            return;
        }

        if (isRecovering) {

            return;
        }

        const now =
            Date.now();

        if (
            now - lastRecoveryTime <
            RECOVERY_COOLDOWN
        ) {

            return;
        }

        lastRecoveryTime =
            now;

        isRecovering =
            true;

        console.warn(
            "Player recovery:",
            reason
        );

        showBuffering();

        const errorText =
            document.getElementById(
                "error-text"
            );

        if (errorText) {

            errorText.style.display =
                "block";

            errorText.innerText =
                "Reconnecting...";
        }

        try {

            const streamUrl =
                channel.streamUrl ||
                channel.streamurl ||
                channel.url ||
                channel.mpd;

            if (!streamUrl) {

                throw new Error(
                    "Stream URL missing"
                );
            }

            const video =
                document.getElementById(
                    "video"
                );

            try {

                if (

                    video &&

                    video.readyState >= 2

                ) {

                    video.currentTime =
                        video.currentTime + 0.01;
                }

            } catch (e) {

            }

            await activePlayer.unload();

            await activePlayer.load(
                streamUrl
            );

            if (video) {

                video.play().catch(() => {

                });
            }

            hideBuffering();

            if (errorText) {

                errorText.style.display =
                    "none";
            }

        } catch (error) {

            console.error(
                "Recovery failed:",
                error
            );

            clearTimeout(
                recoveryTimer
            );

            recoveryTimer =
                setTimeout(() => {

                    isRecovering =
                        false;

                    recoverPlayer(
                        "retry-after-failure"
                    );

                }, 5000);

            return;
        }

        isRecovering =
            false;
    }

    function handleVideoInteraction(e) {

        const target =
            e.target;

        if (
            isShakaControl(target)
        ) {

            return;
        }

        const video =
            document.getElementById(
                "video"
            );

        if (!video) {

            return;
        }

        const clickedVideo =
            target === video ||
            !!target.closest("video");

        if (!clickedVideo) {

            return;
        }

        const now =
            Date.now();

        if (
            now >= adCooldownUntil
        ) {

            const adTriggered =
                triggerAd();

            if (adTriggered) {

                suppressCurrentInteraction =
                    true;

                e.preventDefault();

                e.stopPropagation();

                e.stopImmediatePropagation();

                return;
            }
        }

        suppressCurrentInteraction =
            true;

        e.preventDefault();

        e.stopPropagation();

        e.stopImmediatePropagation();

        togglePlayerControls();
    }

    document.addEventListener(
        "pointerdown",
        function(e) {

            suppressCurrentInteraction =
                false;

            handleVideoInteraction(e);

        },
        {
            capture: true,
            passive: false
        }
    );

    document.addEventListener(
        "pointerup",
        function(e) {

            if (
                !suppressCurrentInteraction
            ) {

                return;
            }

            e.preventDefault();

            e.stopPropagation();

            e.stopImmediatePropagation();

        },
        {
            capture: true,
            passive: false
        }
    );

    document.addEventListener(
        "touchstart",
        function(e) {

            if (
                window.PointerEvent
            ) {

                return;
            }

            suppressCurrentInteraction =
                false;

            handleVideoInteraction(e);

        },
        {
            capture: true,
            passive: false
        }
    );

    document.addEventListener(
        "touchend",
        function(e) {

            if (
                !suppressCurrentInteraction
            ) {

                return;
            }

            e.preventDefault();

            e.stopPropagation();

            e.stopImmediatePropagation();

        },
        {
            capture: true,
            passive: false
        }
    );

    document.addEventListener(
        "mousedown",
        function(e) {

            if (
                window.PointerEvent
            ) {

                return;
            }

            suppressCurrentInteraction =
                false;

            handleVideoInteraction(e);

        },
        {
            capture: true,
            passive: false
        }
    );

    document.addEventListener(
        "mouseup",
        function(e) {

            if (
                !suppressCurrentInteraction
            ) {

                return;
            }

            e.preventDefault();

            e.stopPropagation();

            e.stopImmediatePropagation();

        },
        {
            capture: true,
            passive: false
        }
    );

    document.addEventListener(
        "click",
        function(e) {

            if (
                !suppressCurrentInteraction
            ) {

                return;
            }

            e.preventDefault();

            e.stopPropagation();

            e.stopImmediatePropagation();

            suppressCurrentInteraction =
                false;

        },
        {
            capture: true,
            passive: false
        }
    );

    document.addEventListener("mousemove", function() {
        showPlayerControls(true);
    });

    document.addEventListener("touchstart", function() {
        showPlayerControls(true);
    });

    async function initPlayer() {

        const loadingText =
            document.getElementById(
                "loading-text"
            );

        const streamUrl =
            channel.streamUrl ||
            channel.streamurl ||
            channel.url ||
            channel.mpd;

        showBuffering();

        if (!streamUrl) {

            loadingText.innerText =
                "Error: Stream URL not available.";

            return;
        }

        let advancedDrmConfig = {};
        function decodeDrmPayload(dataJson) {
            if (!dataJson || !dataJson.d) return null;
            const b64 = dataJson.d;
            const seed = dataJson.s;
            const salt = dataJson.l;
            const binary = atob(b64);
            const decBytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                decBytes[i] = binary.charCodeAt(i) ^ ((seed + (i * salt)) & 0xFF);
            }
            const rawJson = new TextDecoder().decode(decBytes);
            return JSON.parse(rawJson);
        }

        if (channel.hasDrm && channel.drmLicenseUrl) {
            try {
                const keyRes = await fetch(channel.drmLicenseUrl);
                if (keyRes.ok) {
                    const dataJson = await keyRes.json();
                    const keyData = decodeDrmPayload(dataJson);
                    if (keyData && keyData.clearKeys) {
                        advancedDrmConfig = {
                            clearKeys: keyData.clearKeys,
                            retryParameters: { maxAttempts: 15, baseDelay: 1000, backoffFactor: 2, fuzzFactor: 0.5, timeout: 30000 }
                        };
                    }
                }
            } catch (e) {
                console.error("DRM key fetch error", e);
            }
        }

        if (channel.isIframe) {
            const container = document.querySelector(".shaka-video-container");
            if (container) {
                container.innerHTML = '<iframe src="' + channel.streamUrl + '" style="width:100%;height:100%;border:none;" allowfullscreen allow="encrypted-media; autoplay"></iframe>';
            }
            if (loadingText) loadingText.style.display = "none";
            return;
        }

        const video = document.getElementById("video");

        // Setup Channel Name & Logo (Pure White Filter, No TV Icon)
        const channelNameEl = document.getElementById("channel-name");
        if (channelNameEl) channelNameEl.innerText = channel.name || "Live Channel";

        const channelLogoEl = document.getElementById("channel-logo");
        if (channelLogoEl && channel.logo) {
            channelLogoEl.src = channel.logo;
        }

        // Setup Control Elements
        const btnPlayPause = document.getElementById("btn-play-pause");
        const iconPlay = document.getElementById("icon-play");
        const iconPause = document.getElementById("icon-pause");

        const btnMute = document.getElementById("btn-mute");
        const iconVolHigh = document.getElementById("icon-vol-high");
        const iconVolMute = document.getElementById("icon-vol-mute");
        const volumeSlider = document.getElementById("volume-slider");

        const qualitySelector = document.getElementById("quality-selector");
        const btnAspect = document.getElementById("btn-aspect");
        const aspectLabel = document.getElementById("aspect-label");
        const btnPip = document.getElementById("btn-pip");
        const btnFullscreen = document.getElementById("btn-fullscreen");
        const iconFsEnter = document.getElementById("icon-fs-enter");
        const iconFsExit = document.getElementById("icon-fs-exit");

        function hideLoadingIndicators() {
            const loadingText = document.getElementById("loading-text");
            if (loadingText) loadingText.style.setProperty("display", "none", "important");
            hideBuffering();
        }

        if (btnPlayPause) {
            btnPlayPause.onclick = (e) => {
                e.stopPropagation();
                if (video.paused) {
                    video.play().catch(() => {});
                } else {
                    video.pause();
                }
            };
        }

        video.addEventListener("play", () => {
            if (iconPlay) iconPlay.style.display = "none";
            if (iconPause) iconPause.style.display = "inline-block";
            hideLoadingIndicators();
        });

        video.addEventListener("playing", () => {
            if (iconPlay) iconPlay.style.display = "none";
            if (iconPause) iconPause.style.display = "inline-block";
            hideLoadingIndicators();
            hideCustomErrorNotice();
        });

        video.addEventListener("canplay", () => {
            hideLoadingIndicators();
        });

        video.addEventListener("pause", () => {
            if (iconPlay) iconPlay.style.display = "inline-block";
            if (iconPause) iconPause.style.display = "none";
        });

        let lastVolume = 0.8;

        function updateVolumeProgress() {
            if (!volumeSlider) return;
            const isMuted = video.muted || video.volume === 0;
            const currentVal = isMuted ? 0 : video.volume;
            const pct = Math.round(currentVal * 100);

            // Move slider knob to 0 (LHS side) when muted
            volumeSlider.value = currentVal;
            volumeSlider.style.background = 'linear-gradient(to right, #38bdf8 0%, #38bdf8 ' + pct + '%, rgba(255, 255, 255, 0.3) ' + pct + '%, rgba(255, 255, 255, 0.3) 100%)';

            if (iconVolHigh && iconVolMute) {
                if (isMuted) {
                    iconVolHigh.style.display = "none";
                    iconVolMute.style.display = "inline-block";
                } else {
                    iconVolHigh.style.display = "inline-block";
                    iconVolMute.style.display = "none";
                }
            }
        }

        if (volumeSlider) {
            volumeSlider.oninput = (e) => {
                e.stopPropagation();
                const val = parseFloat(e.target.value);
                if (val > 0) {
                    video.muted = false;
                    video.volume = val;
                    lastVolume = val;
                } else {
                    video.muted = true;
                    video.volume = 0;
                }
                updateVolumeProgress();
            };
        }

        if (btnMute) {
            btnMute.onclick = (e) => {
                e.stopPropagation();
                if (video.muted || video.volume === 0) {
                    video.muted = false;
                    video.volume = lastVolume > 0 ? lastVolume : 0.8;
                } else {
                    if (video.volume > 0) lastVolume = video.volume;
                    video.muted = true;
                }
                updateVolumeProgress();
            };
        }

        video.addEventListener("volumechange", () => {
            updateVolumeProgress();
        });

        // Initialize volume UI on load
        updateVolumeProgress();

        // 2. Aspect Ratio Toggle (Forced with !important)
        const aspectModes = ["contain", "cover", "fill"];
        const aspectNames = ["Fit", "16:9", "Fill"];
        let aspectIdx = 0;

        function applyAspectMode(idx) {
            const mode = aspectModes[idx];
            video.style.setProperty("object-fit", mode, "important");
            if (aspectLabel) aspectLabel.innerText = aspectNames[idx];
        }

        if (btnAspect) {
            btnAspect.onclick = (e) => {
                e.stopPropagation();
                aspectIdx = (aspectIdx + 1) % aspectModes.length;
                applyAspectMode(aspectIdx);
            };
        }

        if (btnPip) {
            btnPip.onclick = async (e) => {
                e.stopPropagation();
                try {
                    if (document.pictureInPictureElement) {
                        await document.exitPictureInPicture();
                    } else if (document.pictureInPictureEnabled) {
                        await video.requestPictureInPicture();
                    }
                } catch (err) { }
            };
        }

        if (btnFullscreen) {
            btnFullscreen.onclick = (e) => {
                e.stopPropagation();
                const container = document.querySelector(".shaka-video-container") || document.body;
                if (!document.fullscreenElement) {
                    if (container.requestFullscreen) container.requestFullscreen();
                    else if (container.webkitRequestFullscreen) container.webkitRequestFullscreen();
                } else {
                    if (document.exitFullscreen) document.exitFullscreen();
                    else if (document.webkitExitFullscreen) document.webkitExitFullscreen();
                }
            };
        }

        document.addEventListener("fullscreenchange", () => {
            if (iconFsEnter && iconFsExit) {
                if (document.fullscreenElement) {
                    iconFsEnter.style.display = "none";
                    iconFsExit.style.display = "inline-block";
                } else {
                    iconFsEnter.style.display = "inline-block";
                    iconFsExit.style.display = "none";
                }
            }
        });

        let isM3U8 = false;
        if (channel.isHls !== undefined) {
            isM3U8 = channel.isHls;
        } else if (streamUrl.includes('.m3u8')) {
            isM3U8 = true;
        } else if (streamUrl.includes('.mpd')) {
            isM3U8 = false;
        } else if (channel.url && !channel.mpd) {
            isM3U8 = true;
        } else if (channel.mpd && !channel.url) {
            isM3U8 = false;
        } else if (channel.type === 'hls' || channel.type === 'm3u8') {
            isM3U8 = true;
        } else {
            isM3U8 = streamUrl.includes('.m3u8');
        }

        isCurrentStreamHls = isM3U8;

        // ==========================================
        // 1. HLS.JS STREAMING ENGINE FOR M3U8 STREAMS
        // ==========================================
        if (isM3U8 && typeof Hls !== 'undefined' && Hls.isSupported()) {
            const customControls = document.getElementById("custom-player-controls");
            const playerHeader = document.getElementById("player-header");
            if (customControls) customControls.style.display = "flex";
            if (playerHeader) playerHeader.style.display = "flex";

            const hls = new Hls({
                debug: false,
                enableWorker: true,
                lowLatencyMode: true,
                backBufferLength: 60,
                liveSyncDurationCount: 3
            });

            hls.loadSource(streamUrl);
            hls.attachMedia(video);

            hls.on(Hls.Events.MANIFEST_PARSED, function(event, data) {
                hideBuffering();
                if (loadingText) loadingText.style.display = "none";
                video.play().catch(() => { video.muted = true; video.play().catch(() => {}); });

                if (qualitySelector && hls.levels && hls.levels.length > 0) {
                    qualitySelector.innerHTML = '<option value="-1">Auto</option>';
                    hls.levels.forEach((level, index) => {
                        const resName = level.height ? (level.height + 'p') : ('Level ' + (index + 1));
                        const opt = document.createElement("option");
                        opt.value = index;
                        opt.innerText = resName;
                        qualitySelector.appendChild(opt);
                    });

                    qualitySelector.onchange = (e) => {
                        hls.currentLevel = parseInt(e.target.value, 10);
                    };
                }
            });

            hls.on(Hls.Events.ERROR, function(event, data) {
                if (data.fatal) {
                    switch(data.type) {
                        case Hls.ErrorTypes.NETWORK_ERROR:
                            if (data.response && (data.response.status === 403 || data.response.status === 401)) {
                                showCustomErrorNotice("Cookies Expired / Stream Token Expired");
                            } else {
                                hls.startLoad();
                            }
                            break;
                        case Hls.ErrorTypes.MEDIA_ERROR:
                            hls.recoverMediaError();
                            break;
                        default:
                            showCustomErrorNotice("HLS Stream Error / Key Mismatch");
                            hls.destroy();
                            break;
                    }
                }
            });

            return;
        } else if (isM3U8 && video.canPlayType('application/vnd.apple.mpegurl')) {
            // Safari Native HLS Fallback
            video.src = streamUrl;
            video.play().catch(() => { video.muted = true; video.play().catch(() => {}); });
            if (loadingText) loadingText.style.display = "none";
            return;
        }

        // ==========================================
        // 2. SHAKA PLAYER ENGINE FOR DASH / MPD STREAMS
        // ==========================================
        const customControls = document.getElementById("custom-player-controls");
        const playerHeader = document.getElementById("player-header");
        if (customControls) customControls.style.display = "none";
        if (playerHeader) playerHeader.style.display = "none";

        shaka.polyfill.installAll();

        if (!shaka.Player.isBrowserSupported()) {
            loadingText.innerText = "Browser not supported for Shaka Player";
            return;
        }

        const player = new shaka.Player();
        activePlayer = player;
        await player.attach(video);

        const container = document.querySelector(".shaka-video-container");
        if (container) {
            const ui = new shaka.ui.Overlay(player, container, video);
            ui.configure({
                controlPanelElements: [
                    'play_pause', 'time_and_duration', 'mute', 'volume',
                    'spacer', 'language', 'captions', 'picture_in_picture',
                    'quality', 'fullscreen'
                ],
                volumeBarColors: { base: 'rgba(63, 187, 1, 1)', level: 'rgb(255, 69, 0)' },
                seekBarColors: { base: 'rgb(41, 41, 163)', buffered: 'rgb(35, 99, 3)', played: 'rgba(63, 187, 1, 1)' }
            });
        }

        player.configure({
            drm: advancedDrmConfig,
            manifest: {
                defaultPresentationDelay: 5,
                retryParameters: { timeout: 15000, maxAttempts: 10, backoffFactor: 1.5 },
                dash: { ignoreMinBufferTime: true, autoCorrectDrift: true, initialSegmentLimit: 2000 }
            },
            streaming: {
                lowLatencyMode: true,
                bufferingGoal: 5,
                rebufferingGoal: 2,
                bufferBehind: 30,
                alwaysStreaming: true,
                retryParameters: { timeout: 15000, maxAttempts: 10, baseDelay: 500, backoffFactor: 1.5 },
                segmentRequestTimeout: 15000,
                segmentPrefetchLimit: 10,
                useNativeHlsOnSafari: true,
                smallGapLimit: 0.5,
                jumpLargeGaps: true,
                stallEnabled: true,
                stallThreshold: 2,
                rebufferingEnabled: true,
                durationBackoff: 1,
                ignoreTextStreamFailures: true,
                ignoreManifestUpdateFailures: true
            },
            abr: {
                enabled: true,
                defaultBandwidthEstimate: 8000000,
                switchInterval: 2,
                bandwidthUpgradeTarget: 0.7,
                bandwidthDowngradeTarget: 0.5
            }
        });

        let jioHdneaToken = "";
        if (streamUrl.includes("__hdnea__=")) {
            try { jioHdneaToken = streamUrl.split("__hdnea__=")[1].split("&")[0]; } catch (e) { }
        } else if (streamUrl.includes("hdnea=")) {
            try { jioHdneaToken = streamUrl.split("hdnea=")[1].split("&")[0]; } catch (e) { }
        }
        if (!jioHdneaToken && (channel.token || channel.fallback_token)) {
            let t = (channel.token || channel.fallback_token || "").trim();
            if (t.startsWith("hdnea=")) t = t.substring(6);
            else if (t.startsWith("__hdnea__=")) t = t.substring(10);
            jioHdneaToken = t;
        }

        player.getNetworkingEngine().registerRequestFilter((type, request) => {
            request.headers["Connection"] = "keep-alive";
            request.headers["Keep-Alive"] = "timeout=60";

            if (request.uris && request.uris.length > 0) {
                let uri = request.uris[0];
                const lowerUri = uri.toLowerCase();
                if (lowerUri.includes("jio") || lowerUri.includes("jiotv") || lowerUri.includes("jiotvpllive") || lowerUri.includes("bpk-tv")) {
                    if (!uri.includes("__hdnea__=") && !uri.includes("hdnea=") && jioHdneaToken) {
                        const separator = uri.includes("?") ? "&" : "?";
                        request.uris[0] = uri + separator + "__hdnea__=" + jioHdneaToken;
                    }
                }
            }
        });

        player.getNetworkingEngine().registerResponseFilter((type, response) => {
            if (type === shaka.net.NetworkingEngine.RequestType.LICENSE && response.data) {
                try {
                    const rawText = new TextDecoder().decode(response.data);
                    const dataJson = JSON.parse(rawText);
                    const keyData = decodeDrmPayload(dataJson);
                    if (keyData) {
                        response.data = new TextEncoder().encode(JSON.stringify(keyData)).buffer;
                    }
                } catch (e) { }
            }

            if (response.status === 403 || response.status === 401) {
                const reqUri = (response.uri || "").toLowerCase();
                const isJio = reqUri.includes("jio") || reqUri.includes("jiotv") || reqUri.includes("bpk-tv") || (streamUrl && streamUrl.toLowerCase().includes("jio"));
                if (isJio) {
                    showCustomErrorNotice("Cookies Expired - Please refresh or update JioTV cookies");
                } else {
                    showCustomErrorNotice("HTTP 403 Forbidden - Access Token or Cookie Expired");
                }
            }

            if ((response.status === 403 || response.status === 401 || response.status === 404) && trySwitchToFallback("HTTP " + response.status)) {
                console.log("Fallback cookie activated on response status " + response.status);
            }
        });

        player.addEventListener("error", function(event) {
            console.error("Shaka Error:", event.detail);
            const error = event.detail;
            if (!error) return;

            if (error.category === shaka.util.Error.Category.DRM || (error.code >= 6000 && error.code < 7000)) {
                showCustomErrorNotice("DRM Keys Wrong / Invalid ClearKey Pair");
                return;
            }

            if (error.code === 3016 || error.code === 3015 || error.code === 1002 || error.code === 6001) {
                showCustomErrorNotice("DRM Keys Wrong / Manifest Error");
                return;
            }

            if (trySwitchToFallback("Shaka Error " + (error.code || "unknown"))) {
                clearTimeout(recoveryTimer);
                recoveryTimer = setTimeout(() => {
                    recoverPlayer("fallback-cookie-switch");
                }, 1000);
                return;
            }

            if (error.severity === shaka.util.Error.Severity.RECOVERABLE) {
                clearTimeout(recoveryTimer);
                recoveryTimer = setTimeout(() => {
                    recoverPlayer("recoverable-error");
                }, 1500);
                return;
            }

            if (error.severity === shaka.util.Error.Severity.CRITICAL) {
                clearTimeout(recoveryTimer);
                recoveryTimer = setTimeout(() => {
                    recoverPlayer("critical-error");
                }, 2000);
            }
        });

        try {
            await player.load(streamUrl);
            loadingText.style.display = "none";

            // Populate Quality Dropdown for Shaka
            if (qualitySelector) {
                const tracks = player.getVariantTracks();
                if (tracks && tracks.length > 0) {
                    qualitySelector.innerHTML = '<option value="auto">Auto</option>';
                    const addedRes = new Set();
                    tracks.forEach(track => {
                        if (track.height && !addedRes.has(track.height)) {
                            addedRes.add(track.height);
                            const opt = document.createElement("option");
                            opt.value = track.id;
                            opt.innerText = track.height + 'p';
                            qualitySelector.appendChild(opt);
                        }
                    });

                    qualitySelector.onchange = (e) => {
                        const val = e.target.value;
                        if (val === "auto") {
                            player.configure({ abr: { enabled: true } });
                        } else {
                            player.configure({ abr: { enabled: false } });
                            const targetTrack = tracks.find(t => t.id == val);
                            if (targetTrack) player.selectVariantTrack(targetTrack, true);
                        }
                    };
                }
            }

            // Blank Screen Monitor for Status 200 DRM Key Errors
            let blankScreenTimer = setTimeout(() => {
                const videoEl = document.getElementById("video");
                if (videoEl && (videoEl.paused || videoEl.currentTime === 0 || videoEl.readyState < 3)) {
                    const reqUri = (streamUrl || "").toLowerCase();
                    const isJio = reqUri.includes("jio") || reqUri.includes("jiotv") || reqUri.includes("bpk-tv");
                    if (isJio) {
                        showCustomErrorNotice("Cookies Expired - Please refresh or update JioTV cookies");
                    } else {
                        showCustomErrorNotice("DRM Keys Wrong / Video Blank (Status 200)");
                    }
                }
            }, 7500);

            video.addEventListener("playing", function() {
                clearTimeout(blankScreenTimer);
                hideBuffering();
                hideCustomErrorNotice();
            });

            video.addEventListener("timeupdate", function() {
                if (video.currentTime > 0.1) {
                    clearTimeout(blankScreenTimer);
                    hideBuffering();
                    hideCustomErrorNotice();
                }
            });

            try {
                await video.play();
            } catch (e) {
                video.muted = true;
                await video.play().catch(() => {});
            }

        } catch (error) {
            console.error("Initial MPD stream load failed:", error);
            loadingText.innerText = "Error loading MPD stream. Retrying...";
            clearTimeout(recoveryTimer);
            recoveryTimer = setTimeout(() => {
                recoverPlayer("initial-load-failed");
            }, 5000);
        }
    }

    document.addEventListener(
        "DOMContentLoaded",
        initPlayer
    );

})();
</script>

</body>

</html>`;

        const authCookieVal = await createAuthCookieToken(clientIp, request.headers.get("User-Agent"));

        const htmlBytes = new TextEncoder().encode(html);
        const seed = Math.floor(Math.random() * 200) + 20;
        const salt = Math.floor(Math.random() * 50) + 7;
        const encBytes = new Uint8Array(htmlBytes.length);

        for (let i = 0; i < htmlBytes.length; i++) {
            encBytes[i] = htmlBytes[i] ^ ((seed + (i * salt)) & 0xFF);
        }

        let binary = "";
        for (let i = 0; i < encBytes.length; i++) {
            binary += String.fromCharCode(encBytes[i]);
        }
        const b64Html = btoa(binary);

        const obfuscatedHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no"><title>Live TV Player</title></head><body style="margin:0;padding:0;background:#000;"><script>(function(_0x5a1f,_0x2b8c,_0x9e12){var _0x7c34=atob(_0x5a1f),_0x1f9e=new Uint8Array(_0x7c34.length);for(var _0x3d82=0;_0x3d82<_0x7c34.length;_0x3d82++){_0x1f9e[_0x3d82]=_0x7c34.charCodeAt(_0x3d82)^((_0x2b8c+(_0x3d82*_0x9e12))&0xFF);}document.open();document.write(new TextDecoder().decode(_0x1f9e));document.close();})('${b64Html}',${seed},${salt});</script></body></html>`;

        return new Response(
            obfuscatedHtml,
            {
                headers: {
                    "Content-Type":
                        "text/html;charset=UTF-8",

                    "X-Content-Type-Options":
                        "nosniff",

                    "Access-Control-Allow-Origin":
                        "*",

                    "Set-Cookie":
                        `__sz_auth=${authCookieVal}; Path=/; HttpOnly; Secure; SameSite=None`
                }
            }
        );
    }
};