const SECRET_KEY = "xQ#9vL2$pM8@kR4*jT6!nW7^yC3(hF1&";
const API_SECRET_KEY = "G5*bN#8zK2@vX9$mP1^qL4!cH7&yR3(t";
const ENCRYPTION_KEY = "wD@4jB9!vN2$xP7*kM5^qL8#cT3(hF1&";
const DRM_MASK_KEY = "zK9#vL2$pM8@kR4*jT6!nW7^yC3(hF1&";
const ALLOWED_CHANNELS = ['1106', '1108', '1109', '1114', '1122', '1123', '1124', '1141', '1142', '1389', '155', '162', '1650', '1651', '1774', '1775', '1984', '1985', '1998', '2852', '2853', '3273', '3274', '3277', '3278', '3372', '3373', '3374', '3397', '3398', '3399', '3528', '362', '460', '461', '514', '523', '524', '525', '891', '892'];
const CRICKESTER_CHANNELS = ['so1', 'so3', 'TNT4', 'wbyc'];
const BROBP_CHANNELS = ['1106', '1108', '1109', '1114', '1122', '1123', '1124', '1141', '1142', '1389', '155', '162', '1650', '1651', '1774', '1775', '1984', '1985', '1998', '2852', '2853', '3273', '3274', '3277', '3278', '3372', '3373', '3374', '3397', '3398', '3399', '3528', '362', '460', '461', '514', '523', '524', '525', '891', '892'];

// Supabase Configuration
const SUPABASE_URL = "https://tawgctxobadzwfokqagk.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRhd2djdHhvYmFkendmb2txYWdrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODkyMDE5NzMsImV4cCI6MjEwNDc3Nzk3M30.cdYkz85bwWUcQ_mslfpUisT7wefxWN1b6hARNgc57v8";
const SUPABASE_SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRhd2djdHhvYmFkendmb2txYWdrIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4OTIwMTk3MywiZXhwIjoyMTA0Nzc3OTczfQ.XHycdYspt231EZ7R7xYh7_wTo9kSCW4wXV7QttrHe-o";
const SUPABASE_KEY = SUPABASE_SERVICE_ROLE_KEY;

const SUPABASE_TABLE = "nibbu";

function getSupabaseHeaders() {
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": `Bearer ${SUPABASE_KEY}`,
        "Content-Type": "application/json",
        "Accept": "application/json"
    };
}

async function fetchSupabaseTable(table, query = "") {
    try {
        const url = `${SUPABASE_URL}/rest/v1/${table}${query ? (query.startsWith('?') ? query : '?' + query) : ''}`;
        const res = await fetch(url, {
            headers: getSupabaseHeaders(),
            cf: { cacheTtl: 0, cacheEverything: false }
        });
        if (!res.ok) {
            return null;
        }
        return await res.json();
    } catch (e) {
        console.error(`Supabase fetch error for ${table}:`, e);
        return null;
    }
}

const ALLOWED_DOMAINS = [
    "nibbu.arabba.workers.dev",
    "nibbu.pages.dev",
    "sony.rabba.workers.dev",
    "nibbu.workers.dev"
];

function isAllowedDomain(originOrReferer) {
    if (!originOrReferer) return false;
    try {
        const urlObj = new URL(originOrReferer);
        return ALLOWED_DOMAINS.some(domain => urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain) || urlObj.hostname.includes('nibbu') || urlObj.hostname.includes('nibba') || urlObj.hostname.includes('fanxzone') || urlObj.hostname.includes('rabba'));
    } catch (e) {
        return ALLOWED_DOMAINS.some(domain => originOrReferer.includes(domain)) || originOrReferer.includes('nibbu') || originOrReferer.includes('nibba') || originOrReferer.includes('fanxzone') || originOrReferer.includes('rabba');
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
    if (url.pathname === '/api/get/channels' || url.pathname === '/api/channels' || url.pathname === '/api/get/admin' || url.pathname === '/admin' || url.pathname.startsWith('/api/admin') || url.searchParams.get("id") === "test_preview_temp") {
        return false; // Unconditionally allow access to channels, admin portal, and stream preview test
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

function isFancodeUrl(urlStr) {
    if (!urlStr) return false;
    const lower = String(urlStr).toLowerCase();
    return lower.includes("fancode.com") || lower.includes("dai-fancode") || lower.includes("fancode");
}

function getFancodePlayerHtml(initialUrl = "") {
    const escapedUrl = initialUrl ? JSON.stringify(initialUrl) : '""';
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>FANCODE LIVE · HLS Player</title>
  <meta name="referrer" content="no-referrer">
  <meta name="viewport" content="width=device-width,initial-scale=1, maximum-scale=1, user-scalable=no">
  <!-- Poppins font -->
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
  <!-- Shaka Player UI (latest stable) -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/shaka-player/4.6.0/shaka-player.ui.min.js"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/shaka-player/4.6.0/controls.min.css">
  <style>
    * {
      box-sizing: border-box;
    }
    html, body {
      margin: 0;
      padding: 0;
      background: #000;
      height: 100%;
      width: 100%;
      overflow: hidden;
      font-family: 'Poppins', sans-serif;
    }
    .video-container {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: #000;
    }
    .shaka-video-container {
      width: 100%;
      height: 100%;
      position: relative;
    }
    video {
      width: 100%;
      height: 100%;
      object-fit: contain;
      background: #000;
      outline: none;
    }
    /* custom loading overlay */
    .loading-overlay {
      position: absolute;
      inset: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-direction: column;
      background: #000;
      color: #fff;
      z-index: 2000;
      font-size: 1rem;
      font-weight: 500;
      letter-spacing: 0.5px;
      transition: opacity 0.3s ease;
      pointer-events: none;
    }
    .loading-overlay.hidden {
      opacity: 0;
      display: none;
    }
    .spinner {
      border: 4px solid rgba(255, 255, 255, 0.15);
      border-top: 4px solid #3b82f6;
      border-radius: 50%;
      width: 44px;
      height: 44px;
      animation: spin 0.9s linear infinite;
      margin-bottom: 16px;
      box-shadow: 0 0 12px rgba(59, 130, 246, 0.3);
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    /* error state (optional, but nice) */
    .error-message {
      color: #ff7b7b;
      font-size: 0.9rem;
      text-align: center;
      padding: 0 20px;
      max-width: 90%;
    }
    /* shaka ui overrides – ensure fullscreen fills */
    .shaka-controls-container {
      font-family: 'Poppins', sans-serif;
    }
  </style>
</head>
<body>

  <div class="video-container">
    <div class="shaka-video-container" data-shaka-player>
      <video id="video" autoplay playsinline muted></video>
      <div id="loading" class="loading-overlay">
        <div class="spinner"></div>
        <div id="loadingText">Analyzing the stream…</div>
      </div>
    </div>
  </div>

  <script>
    (function() {
      // ----- 1. Parse query parameters: support both ?data= (base64) and ?url= (plain) -----
      const params = new URLSearchParams(window.location.search);
      const dataParam = params.get('data');     // base64 encoded
      const urlParam = params.get('url');       // direct url

      let streamUrl = ${escapedUrl} || '';
      if (!streamUrl) {
        if (dataParam) {
          try {
            streamUrl = atob(dataParam);
          } catch (e) {
            console.warn('Invalid base64 data parameter, falling back to url if present');
            streamUrl = urlParam || '';
          }
        } else if (urlParam) {
          streamUrl = urlParam;
        }

        // If still no url, try hash (fallback)
        if (!streamUrl && window.location.hash) {
          streamUrl = window.location.hash.substring(1);
        }
      }

      // DOM elements
      const video = document.getElementById('video');
      const loadingOverlay = document.getElementById('loading');
      const loadingText = document.getElementById('loadingText');

      // Utility: show error and hide spinner
      function showError(message) {
        loadingOverlay.classList.remove('hidden');
        loadingText.innerHTML = \`<span class="error-message">⚠️ \${message}</span>\`;
        const spinner = loadingOverlay.querySelector('.spinner');
        if (spinner) spinner.style.display = 'none';
      }

      // If no stream URL found
      if (!streamUrl || streamUrl.trim() === '') {
        showError('Missing stream URL. Use ?url= or ?data=');
        // Try to play nothing, but we stop.
        return;
      }

      // ----- 2. Initialize Shaka Player with UI -----
      let player = null;
      let ui = null;

      async function initPlayer() {
        try {
          // Create Shaka Player instance
          player = new shaka.Player(video);

          // Get the container that already has class .shaka-video-container
          const container = document.querySelector('.shaka-video-container');
          // Create UI overlay (Shaka UI)
          ui = new shaka.ui.Overlay(player, container, video);

          // UI configuration – clean modern controls
          ui.configure({
            controlPanelElements: [
              'play_pause',
              'mute',
              'time_and_duration',
              'spacer',
              'quality',
              'language',
              'picture_in_picture',
              'fullscreen',
              'overflow_menu'
            ],
            addSeekBar: true,
            // hide overflow menu options that are not needed
            overflowMenuButtons: ['captions', 'quality', 'language', 'picture_in_picture'],
            // enable keyboard controls (nice)
            enableKeyboardPlaybackControls: true,
            // seek bar colors (optional)
            seekBarColors: {
              base: 'rgba(255,255,255,0.2)',
              buffered: 'rgba(255,255,255,0.4)',
              played: '#3b82f6'
            }
          });

          // Shaka player configuration (optimized for live / hls)
          player.configure({
            streaming: {
              bufferingGoal: 8,          // seconds
              rebufferingGoal: 1.5,
              bufferBehind: 20,
              lowLatencyMode: true,      // better for live streams (if supported)
              retryParameters: {
                maxAttempts: 3,
                baseDelay: 1000,
                backoffFactor: 2,
                fuzzFactor: 0.5,
                timeout: 30000
              }
            },
            manifest: {
              retryParameters: {
                maxAttempts: 3,
                baseDelay: 1000,
                backoffFactor: 2
              }
            }
          });

          // Optional: handle player events for better UX
          player.addEventListener('error', (event) => {
            const error = event.detail;
            console.error('Shaka Player error:', error);
            // If Shaka fails, fallback to native HLS (for Safari / native support)
            // but only if we haven't already tried fallback
            if (!player._fallbackAttempted) {
              player._fallbackAttempted = true;
              console.warn('Shaka failed, attempting native HLS playback…');
              video.src = streamUrl;
              video.play().catch(e => {
                showError('Playback error: ' + (e.message || 'unknown'));
              });
            } else {
              showError('Playback error: ' + (error.message || 'unknown'));
            }
          });

          // When playback starts, hide loading overlay
          video.addEventListener('playing', () => {
            loadingOverlay.classList.add('hidden');
          }, { once: false });

          // Also listen for 'canplay' in case playing doesn't fire early enough
          video.addEventListener('canplay', () => {
            loadingOverlay.classList.add('hidden');
          }, { once: false });

          // Load the stream
          await player.load(streamUrl);
          console.log('Shaka Player loaded stream:', streamUrl);

          // Autoplay handling – try unmuted first (some browsers block)
          try {
            await video.play();
          } catch (playError) {
            console.warn('Autoplay with sound blocked, muting and retrying…', playError);
            video.muted = true;
            await video.play();
            // Optionally show unmute hint, but we keep it simple
          }

          // If after 10 seconds the stream hasn't started, show a hint
          setTimeout(() => {
            if (video.paused || video.readyState < 2) {
              // still not playing? show a gentle message
              loadingText.textContent = 'Still loading… please check your connection.';
            }
          }, 10000);

        } catch (e) {
          console.error('Initialization error:', e);
          // If Shaka fails to load the manifest (e.g., CORS, bad url), fallback to native HLS
          if (!player || !player._fallbackAttempted) {
            player._fallbackAttempted = true;
            console.warn('Shaka initialization failed, trying native video element fallback…');
            video.src = streamUrl;
            video.play().catch(err => {
              showError('Native playback failed: ' + (err.message || 'unknown error'));
            });
            // hide loading when/if it plays
            video.addEventListener('playing', () => {
              loadingOverlay.classList.add('hidden');
            });
            // also handle error on native fallback
            video.addEventListener('error', () => {
              showError('Native playback error');
            });
          } else {
            showError('Failed to load stream: ' + (e.message || 'unknown error'));
          }
        }
      }

      // ----- 3. Start when DOM ready -----
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initPlayer);
      } else {
        // DOM already ready
        initPlayer();
      }

      // ----- 4. Also handle window resize for UI (optional) -----
      window.addEventListener('resize', () => {
        // Shaka UI handles resize automatically
      });

      // ----- 5. Expose player for debugging (optional) -----
      window.__player = () => player;
    })();
  </script>

</body>
</html>`;
}

async function handleAdminRoute(request, domain) {
    const url = new URL(request.url);

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

    const authenticated = (reqPassword === "@hariom@00" || cookiePass === "@hariom@00");

    if (!authenticated) {
        let errorNotice = (reqPassword && reqPassword !== "@hariom@00") ? `<div class="error-msg">Incorrect Password! Please try again.</div>` : "";
        const loginHtml = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nibba Admin Login</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif; }
body { background: #f8fafc; color: #0f172a; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
.login-card { background: #ffffff; padding: 36px; border-radius: 12px; width: 100%; max-width: 400px; box-shadow: 0 10px 25px -5px rgba(15,23,42,0.08); border: 1px solid #e2e8f0; }
.title { font-size: 22px; font-weight: 800; color: #0f172a; margin-bottom: 6px; text-align: center; display: flex; align-items: center; justify-content: center; gap: 8px; letter-spacing: -0.3px; }
.subtitle { font-size: 13px; color: #64748b; margin-bottom: 24px; text-align: center; }
.input-group { margin-bottom: 20px; }
label { display: block; font-size: 12px; color: #475569; margin-bottom: 6px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
input[type="password"] { width: 100%; padding: 10px 14px; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; color: #0f172a; font-size: 14px; outline: none; transition: border-color 0.2s; }
input[type="password"]:focus { border-color: #2563eb; }
button { width: 100%; padding: 11px; background: #2563eb; border: none; border-radius: 8px; color: #fff; font-size: 14px; font-weight: 600; cursor: pointer; transition: background 0.2s; display: flex; align-items: center; justify-content: center; gap: 6px; }
button:hover { background: #1d4ed8; }
.error-msg { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; padding: 10px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; text-align: center; font-weight: 500; }
</style>
</head>
<body>
<div class="login-card">
  <div class="title">
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
    Nibba Admin
  </div>
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
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Set-Cookie": "__sz_admin_pass=@hariom@00; Path=/; HttpOnly; Secure; SameSite=Lax" }
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
                headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Set-Cookie": "__sz_admin_pass=@hariom@00; Path=/; HttpOnly; Secure; SameSite=Lax" }
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
                headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Set-Cookie": "__sz_admin_pass=@hariom@00; Path=/; HttpOnly; Secure; SameSite=Lax" }
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
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Set-Cookie": "__sz_admin_pass=@hariom@00; Path=/; HttpOnly; Secure; SameSite=Lax" }
        });
    }

    if (action === "create" || (request.method === "POST" && bodyData.title && bodyData.ssid)) {
        const title = (bodyData.title || url.searchParams.get("title") || "").trim();
        const ssid = (bodyData.ssid || url.searchParams.get("ssid") || "").trim();
        const streamUrl = (bodyData.streamUrl || url.searchParams.get("streamUrl") || "").trim();
        const keys = (bodyData.keys || bodyData.key || url.searchParams.get("keys") || url.searchParams.get("key") || "").trim();
        const cookie = (bodyData.cookie || bodyData.token || url.searchParams.get("cookie") || url.searchParams.get("token") || "").trim();
        const streamType = (bodyData.streamType || url.searchParams.get("streamType") || "").toLowerCase();
        let isHls = false;
        let isMpd = false;
        if (streamType === "hls") {
            isHls = true;
            isMpd = false;
        } else if (streamType === "mpd" || streamType === "mpd_cookie") {
            isHls = false;
            isMpd = true;
        } else if (streamType === "fancode") {
            isHls = false;
            isMpd = false;
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
                // If temporary preview test, remove any existing test row first to avoid duplicate key constraints
                if (ssid === "test_preview_temp") {
                    try {
                        await fetch(`${SUPABASE_URL}/rest/v1/${SUPABASE_TABLE}?ssid=eq.test_preview_temp`, {
                            method: "DELETE",
                            headers: getSupabaseHeaders()
                        });
                    } catch (e) { }
                }

                // Insert into Supabase nibbu table
                let insertPayload = {
                    title: title,
                    ssid: ssid,
                    stream_url: streamUrl,
                    keys: keys,
                    cookie: cookie,
                    is_hls: !!isHls,
                    is_mpd: !!isMpd,
                    stream_type: streamType || (isHls ? "hls" : isMpd ? "mpd" : "custom"),
                    status: "Live"
                };

                let sbPostRes = await fetch(`${SUPABASE_URL}/rest/v1/${SUPABASE_TABLE}`, {
                    method: "POST",
                    headers: {
                        ...getSupabaseHeaders(),
                        "Prefer": "return=representation"
                    },
                    body: JSON.stringify(insertPayload)
                });

                // If column naming error (e.g. table created with camelCase), retry with camelCase
                if (!sbPostRes.ok && sbPostRes.status === 400) {
                    const camelPayload = {
                        title: title,
                        ssid: ssid,
                        streamUrl: streamUrl,
                        keys: keys,
                        cookie: cookie,
                        isHls: !!isHls,
                        isMpd: !!isMpd,
                        streamType: streamType || (isHls ? "hls" : isMpd ? "mpd" : "custom"),
                        status: "Live"
                    };
                    sbPostRes = await fetch(`${SUPABASE_URL}/rest/v1/${SUPABASE_TABLE}`, {
                        method: "POST",
                        headers: {
                            ...getSupabaseHeaders(),
                            "Prefer": "return=representation"
                        },
                        body: JSON.stringify(camelPayload)
                    });
                }

                // If schema doesn't yet have stream_type/status columns, fallback to basic schema
                if (!sbPostRes.ok && sbPostRes.status === 400) {
                    const basicPayload = {
                        title: title,
                        ssid: ssid,
                        stream_url: streamUrl,
                        keys: keys,
                        cookie: cookie,
                        is_hls: !!isHls,
                        is_mpd: !!isMpd
                    };
                    sbPostRes = await fetch(`${SUPABASE_URL}/rest/v1/${SUPABASE_TABLE}`, {
                        method: "POST",
                        headers: {
                            ...getSupabaseHeaders(),
                            "Prefer": "return=representation"
                        },
                        body: JSON.stringify(basicPayload)
                    });
                }

                const isCreated = sbPostRes.ok;
                const targetDom = bodyData.domain || url.searchParams.get("domain") || domain || "nibbu.arabba.workers.dev";
                const timeBlock = Math.floor(Date.now() / (1000 * 60 * 60 * 24));
                const dataToSign = `${targetDom}|${timeBlock}|${ssid}|unknown`;
                const token = await generateHMAC(dataToSign, SECRET_KEY);
                const playUrl = `https://${targetDom}/?id=${encodeURIComponent(ssid)}&token=${token}`;

                if (request.headers.get("Accept")?.includes("application/json") || request.headers.get("X-Requested-With") || bodyData.ajax) {
                    return new Response(JSON.stringify({
                        success: isCreated,
                        ssid: ssid,
                        token: token,
                        playUrl: playUrl,
                        streamType: streamType,
                        status: sbPostRes.status
                    }), {
                        headers: {
                            "Content-Type": "application/json",
                            "Access-Control-Allow-Origin": "*",
                            "Set-Cookie": "__sz_admin_pass=@hariom@00; Path=/; HttpOnly; Secure; SameSite=Lax"
                        }
                    });
                }
            } catch (e) {
                console.error("Error creating match in Supabase", e);
            }
        }
    } else if (action === "delete") {
        const docId = bodyData.docId || url.searchParams.get("docId");
        if (docId) {
            try {
                // Delete from Supabase
                const deleteUrl = `${SUPABASE_URL}/rest/v1/${SUPABASE_TABLE}?or=(id.eq.${encodeURIComponent(docId)},ssid.eq.${encodeURIComponent(docId)})`;
                const sbDelRes = await fetch(deleteUrl, {
                    method: "DELETE",
                    headers: getSupabaseHeaders()
                });

                if (request.headers.get("Accept")?.includes("application/json")) {
                    return new Response(JSON.stringify({ success: sbDelRes.ok }), {
                        headers: { "Content-Type": "application/json", "Set-Cookie": "__sz_admin_pass=@hariom@00; Path=/; HttpOnly; Secure; SameSite=Lax" }
                    });
                }
            } catch (e) {
                console.error("Error deleting match in Supabase", e);
            }
        }
    }

    let matchesList = [];
    try {
        let sbData = await fetchSupabaseTable(SUPABASE_TABLE, '?select=*&order=created_at.desc');
        if (!sbData || !Array.isArray(sbData)) {
            sbData = await fetchSupabaseTable(SUPABASE_TABLE, '?select=*');
        }

        if (Array.isArray(sbData) && sbData.length > 0) {
            const timeBlock = Math.floor(Date.now() / (1000 * 60 * 60 * 24));
            for (const row of sbData) {
                const docId = String(row.id || row.ssid || "");
                const title = row.title || "";
                const ssid = row.ssid || "";
                const streamUrl = row.stream_url || row.streamUrl || "";
                const keys = row.keys || row.key || "";
                const cookie = row.cookie || row.token || "";
                const isHls = (row.is_hls !== undefined) ? !!row.is_hls : ((row.isHls !== undefined) ? !!row.isHls : streamUrl.includes(".m3u8"));
                const createdAt = row.created_at || row.createdAt || "";

                let playUrl = "";
                if (ssid) {
                    const dataToSign = `${domain}|${timeBlock}|${ssid}|unknown`;
                    const token = await generateHMAC(dataToSign, SECRET_KEY);
                    playUrl = `https://${domain}/?id=${encodeURIComponent(ssid)}&token=${token}`;
                }

                const rawType = (row.stream_type || row.streamType || "").toLowerCase();
                const streamType = rawType || (isHls ? "hls" : (cookie ? "mpd_cookie" : "mpd"));

                matchesList.push({
                    docId, title, ssid, streamUrl, keys, cookie, isHls, streamType, createdAt, playUrl
                });
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
        rowsHtml = `<tr><td colspan="7" style="text-align:center; padding: 32px; color: #64748b; font-size: 14px;">No matches created yet in Supabase table. Use the form above or the Sports Extractor to add streams.</td></tr>`;
    } else {
        for (const m of paginatedMatches) {
            let typeBadge = "";
            const lowerUrl = (m.streamUrl || "").toLowerCase();
            if (m.streamType === "fancode" || lowerUrl.includes("fancode")) {
                typeBadge = `<span style="background: #f3e8ff; color: #7e22ce; border: 1px solid #e9d5ff; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; white-space: nowrap;">⚡ FanCode</span>`;
            } else if (m.streamType === "hls" || m.isHls || lowerUrl.includes(".m3u8")) {
                typeBadge = `<span style="background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; white-space: nowrap;">▶ HLS</span>`;
            } else if (m.streamType === "mpd_cookie" || (m.cookie && m.cookie.trim().length > 0)) {
                typeBadge = `<span style="background: #fffbeb; color: #b45309; border: 1px solid #fde68a; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; white-space: nowrap;">🍪 MPD + Cookie</span>`;
            } else {
                typeBadge = `<span style="background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; white-space: nowrap;">🎬 MPD</span>`;
            }

            rowsHtml += `
            <tr style="border-bottom: 1px solid #e2e8f0; transition: background 0.15s ease;">
              <td style="padding: 12px 14px; font-weight: 600; color: #0f172a; font-size: 13px;">${escapeHtml(m.title)}</td>
              <td style="padding: 12px 14px; color: #2563eb; font-family: monospace; font-weight: 600; white-space: nowrap; font-size: 13px;">${escapeHtml(m.ssid)}</td>
              <td style="padding: 12px 14px; color: #475569; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px;" title="${escapeHtml(m.streamUrl)}">${escapeHtml(m.streamUrl)}</td>
              <td style="padding: 12px 14px; color: #64748b; font-family: monospace; max-width: 160px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px;">${escapeHtml(m.keys || '-')}</td>
              <td style="padding: 12px 14px; color: #64748b; max-width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px;">${escapeHtml(m.cookie || '-')}</td>
              <td style="padding: 12px 14px; white-space: nowrap;">${typeBadge}</td>
              <td style="padding: 12px 14px; white-space: nowrap;">
                <div style="display: flex; gap: 8px; align-items: center; flex-wrap: nowrap;">
                  <button onclick="openIframeModal('${escapeHtml(m.ssid)}', '${m.playUrl}')" style="background: #2563eb; color: #fff; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; transition: background 0.2s; white-space: nowrap; display: inline-flex; align-items: center; gap: 4px;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
                    iFrame
                  </button>
                  <button onclick="deleteMatch('${m.docId}', '${escapeHtml(m.title)}')" style="background: #dc2626; color: #fff; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; transition: background 0.2s; white-space: nowrap; display: inline-flex; align-items: center; gap: 4px;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                    Delete
                  </button>
                </div>
              </td>
            </tr>`;
        }
    }

    let paginationHtml = "";
    if (totalPages > 1) {
        paginationHtml = `<div style="display: flex; justify-content: space-between; align-items: center; margin-top: 18px; padding-top: 14px; border-top: 1px solid #e2e8f0; flex-wrap: wrap; gap: 10px;">
            <div style="font-size: 13px; color: #64748b;">Showing ${startIndex + 1} - ${Math.min(startIndex + pageSize, totalMatches)} of ${totalMatches} matches</div>
            <div style="display: flex; gap: 6px;">`;

        if (currentPage > 1) {
            paginationHtml += `<a href="/api/get/admin?page=${currentPage - 1}" style="background: #ffffff; color: #475569; border: 1px solid #cbd5e1; padding: 6px 12px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 600;">← Previous</a>`;
        }

        for (let p = 1; p <= totalPages; p++) {
            const activeStyle = p === currentPage ? "background: #2563eb; color: #ffffff; border: 1px solid #2563eb;" : "background: #ffffff; color: #475569; border: 1px solid #cbd5e1;";
            paginationHtml += `<a href="/api/get/admin?page=${p}" style="${activeStyle} padding: 6px 12px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 600;">${p}</a>`;
        }

        if (currentPage < totalPages) {
            paginationHtml += `<a href="/api/get/admin?page=${currentPage + 1}" style="background: #ffffff; color: #475569; border: 1px solid #cbd5e1; padding: 6px 12px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 600;">Next →</a>`;
        }

        paginationHtml += `</div></div>`;
    }

    const dashboardHtml = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nibba Match Stream Admin</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif; }
body { background: #f8fafc; color: #1e293b; padding: clamp(12px, 3vw, 32px); min-height: 100vh; font-size: clamp(13px, 2.5vw, 15px); word-break: break-word; }
.container { max-width: 1100px; width: 100%; margin: 0 auto; }
.header { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; margin-bottom: clamp(16px, 3vw, 24px); padding-bottom: 12px; border-bottom: 1px solid #e2e8f0; gap: 10px; }
.title { font-size: clamp(18px, 4vw, 26px); font-weight: 800; color: #0f172a; display: flex; flex-wrap: wrap; align-items: center; gap: 8px; letter-spacing: -0.5px; }
.badge { background: #e0f2fe; color: #0369a1; border: 1px solid #bae6fd; font-size: clamp(10px, 2vw, 12px); padding: 4px 10px; border-radius: 12px; font-weight: 700; white-space: nowrap; }
.sub-tabs { display: flex; flex-wrap: wrap; gap: clamp(8px, 2vw, 12px); margin-bottom: clamp(16px, 3vw, 24px); border-bottom: 1px solid #e2e8f0; padding-bottom: 16px; }
.tab-btn { background: #ffffff; color: #64748b; border: 1px solid #cbd5e1; padding: clamp(8px, 2vw, 10px) clamp(12px, 2.5vw, 20px); border-radius: clamp(6px, 1.5vw, 8px); font-size: clamp(12px, 2.5vw, 14px); font-weight: 600; cursor: pointer; transition: all 0.2s ease; white-space: nowrap; display: inline-flex; align-items: center; justify-content: center; gap: 8px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
.tab-btn:hover { background: #f1f5f9; color: #0f172a; border-color: #94a3b8; }
.tab-btn.active { background: #0f172a; color: #ffffff; border-color: #0f172a; box-shadow: none; }
.card { background: #ffffff; border-radius: clamp(8px, 2vw, 14px); padding: clamp(16px, 3vw, 24px); margin-bottom: clamp(16px, 3vw, 28px); border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
.card-title { font-size: clamp(15px, 3vw, 18px); font-weight: 700; color: #0f172a; margin-bottom: clamp(16px, 2.5vw, 20px); border-bottom: 1px solid #e2e8f0; padding-bottom: 12px; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 8px; }
.form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(clamp(140px, 45vw, 300px), 1fr)); gap: clamp(12px, 2.5vw, 20px); margin-bottom: 20px; }
.input-group { display: flex; flex-direction: column; gap: 6px; }
.full-width-input { grid-column: span 2; }
label { font-size: clamp(11px, 2.2vw, 13px); color: #475569; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
input[type="text"], input[type="number"], select, textarea { background: #ffffff; border: 1px solid #cbd5e1; border-radius: clamp(6px, 1.5vw, 8px); padding: clamp(8px, 2vw, 10px) clamp(10px, 2vw, 14px); color: #0f172a; font-size: clamp(13px, 2.5vw, 14px); outline: none; transition: border-color 0.2s; width: 100%; }
input[type="text"]:focus, input[type="number"]:focus, select:focus, textarea:focus { border-color: #2563eb; }
.btn-submit { background: #2563eb; color: #fff; border: none; padding: clamp(9px, 2vw, 11px) clamp(16px, 2.5vw, 22px); border-radius: clamp(6px, 1.5vw, 8px); font-size: clamp(13px, 2.5vw, 14px); font-weight: 600; cursor: pointer; transition: background 0.2s; white-space: nowrap; display: inline-flex; align-items: center; justify-content: center; gap: 8px; box-shadow: none; }
.btn-submit:hover { background: #1d4ed8; }
.btn-submit:active { background: #1e40af; }
.btn-danger { background: #dc2626; color: #fff; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; transition: background 0.2s; white-space: nowrap; display: inline-flex; align-items: center; gap: 4px; }
.btn-danger:hover { background: #b91c1c; }
.table-responsive { width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; border-radius: 8px; border: 1px solid #e2e8f0; }
table { width: 100%; border-collapse: collapse; text-align: left; min-width: 400px; background: #ffffff; }
th { padding: clamp(10px, 2vw, 12px) clamp(10px, 2vw, 14px); color: #475569; font-size: clamp(11px, 2vw, 12px); font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #e2e8f0; background: #f8fafc; white-space: nowrap; }
td { padding: clamp(10px, 2vw, 12px) clamp(10px, 2vw, 14px); font-size: clamp(13px, 2.2vw, 14px); border-bottom: 1px solid #e2e8f0; color: #1e293b; }
tr:hover td { background: #f8fafc; }
.modal-overlay { display: none; position: fixed; inset: 0; background: rgba(15,23,42,0.6); z-index: 99999; align-items: center; justify-content: center; padding: clamp(8px, 3vw, 20px); backdrop-filter: blur(4px); }
.modal-card { background: #ffffff; border: 1px solid #e2e8f0; border-radius: clamp(12px, 2vw, 16px); width: 100%; max-width: 650px; max-height: 90vh; overflow-y: auto; padding: clamp(20px, 3vw, 32px); box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1); }
.api-endpoint-box { background: #ffffff; border: 1px solid #e2e8f0; padding: 12px 16px; border-radius: 8px; display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 20px; box-shadow: 0 1px 2px rgba(0,0,0,0.03); }
.api-endpoint-box code { font-family: monospace; color: #0f172a; font-size: 13px; font-weight: 600; word-break: break-all; }
.badge-hls { background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; }
.badge-mpd { background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }
.badge-mpd-cookie { background: #fffbeb; color: #b45309; border: 1px solid #fde68a; }
.badge-fancode { background: #f3e8ff; color: #7e22ce; border: 1px solid #e9d5ff; }
.stream-pill { padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; display: inline-flex; align-items: center; gap: 4px; white-space: nowrap; }
@media (max-width: 600px) {
  .full-width-input { grid-column: span 1 !important; }
  .form-actions-row { flex-direction: column; align-items: stretch !important; gap: 12px; }
  .btn-submit { width: 100%; }
  .sub-tabs { flex-direction: column; }
  .tab-btn { width: 100%; text-align: center; }
}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="title">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
      Nibba Admin <span class="badge">Supabase: nibbu</span>
    </div>
  </div>

  <div class="api-endpoint-box">
    <div>
      <div style="font-size:11px; font-weight:700; color:#475569; text-transform:uppercase; margin-bottom:4px; letter-spacing:0.5px;">Channels JSON API Endpoint</div>
      <code>https://${domain}/api/channels</code>
    </div>
    <button class="btn-submit" onclick="navigator.clipboard.writeText('https://${domain}/api/channels'); alert('Copied endpoint URL!')" style="padding: 6px 14px; font-size: 12px; background: #f1f5f9; color: #0f172a; border: 1px solid #cbd5e1;">Copy</button>
  </div>

  <div class="sub-tabs">
    <button id="tab-btn-matches" onclick="switchTab('matches')" class="tab-btn active">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="15" rx="2" ry="2"></rect><polyline points="17 2 12 7 7 2"></polyline></svg>
      Matches Management
    </button>
    <button id="tab-btn-cron" onclick="switchTab('cron')" class="tab-btn">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
      Cron & Cookies
    </button>
    <button id="tab-btn-extractor" onclick="switchTab('extractor')" class="tab-btn">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path></svg>
      Sports Extractor
    </button>
  </div>

  <div id="tab-content-matches">
    <div class="card">
      <div class="card-title">
        <div style="display:flex; align-items:center; gap:8px;">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
          Create New Stream Match
        </div>
      </div>
      <form id="create-match-form" onsubmit="event.preventDefault(); showConfirmationModal(this);">
        <input type="hidden" name="action" value="create">
        <input type="hidden" name="password" value="@hariom@00">
        <input type="hidden" name="ajax" value="true">
        <div class="form-grid">
          <div class="input-group">
            <label>Match Title</label>
            <input type="text" name="title" placeholder="e.g. IND vs PAK T20 Live" required>
          </div>
          <div class="input-group">
            <label>Fixed SSID (Channel ID)</label>
            <input type="text" name="ssid" placeholder="e.g. fz1 or star1" required>
          </div>
          <div class="input-group">
            <label>Bind Domain</label>
            <select name="domain" id="manual-domain-select" required></select>
          </div>
          <div class="input-group">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <label>Stream Type</label>
              <span id="manual-type-pill" class="stream-pill" style="display:none;"></span>
            </div>
            <select name="streamType" id="manual-stream-type" onchange="onManualStreamTypeChange()">
              <option value="auto">⚡ Auto Detect (from URL & Cookie)</option>
              <option value="hls">▶ HLS (.m3u8)</option>
              <option value="mpd_cookie">🍪 MPD + Cookie</option>
              <option value="mpd">🎬 MPD (DASH)</option>
              <option value="fancode">⚡ FanCode</option>
            </select>
          </div>
          <div class="input-group full-width-input">
            <label>Stream URL</label>
            <input type="text" name="streamUrl" id="manual-stream-url" placeholder="e.g. https://domain.com/live/index.m3u8" oninput="autoDetectManualStreamType()" required>
            <div id="manual-type-banner" style="display:none; margin-top:6px; font-size:12px; font-weight:600; padding:6px 10px; border-radius:6px;"></div>
          </div>
          <div class="input-group">
            <label>Keys (DRM keyId:key)</label>
            <input type="text" name="keys" id="manual-keys" placeholder="e.g. 1234567890abcdef:fedcba0987654321" oninput="autoDetectManualStreamType()">
          </div>
          <div class="input-group">
            <label style="display: flex; align-items: center; justify-content: space-between;">
              <span>Cookie / Authorization Token</span>
              <span onclick="showCookieFormatModal()" style="cursor: pointer; display: inline-flex; align-items: center; justify-content: center; width: 18px; height: 18px; border-radius: 50%; background: #2563eb; color: #fff; font-size: 11px; font-weight: bold;" title="Click to view supported cookie formats">ℹ</span>
            </label>
            <input type="text" name="cookie" id="manual-cookie" placeholder="e.g. hdnea=st=... or Bearer token" oninput="autoDetectManualStreamType()">
          </div>
        </div>
        <div class="form-actions-row" style="display: flex; justify-content: flex-end; align-items: center; margin-top: 10px;">
          <button type="submit" class="btn-submit">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
            Create Match
          </button>
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
          <button id="btn-update-st" onclick="runStWorkerUpdate()" class="btn-submit" style="padding: 8px 16px; font-size: 13px; background: #2563eb;">⚡ Update ST Worker</button>
          <button id="btn-run-dryrun" onclick="runDryRunTest()" class="btn-submit" style="padding: 8px 16px; font-size: 13px; background: #059669;">🧪 Run Live Stream Dry Run</button>
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
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid #e2e8f0; padding-bottom: 12px;">
      <h3 id="modal-title" style="color: #0f172a; font-size: 18px; font-weight: 700;">Channel Cookie Details</h3>
      <button onclick="closeCookieModal()" style="background: transparent; border: none; color: #64748b; font-size: 20px; cursor: pointer;">&times;</button>
    </div>
    <div style="margin-bottom: 16px;">
      <label style="display: block; margin-bottom: 6px;">Updated Cookie Token</label>
      <div style="position: relative;">
        <pre id="modal-cookie" style="background: #f8fafc; border: 1px solid #e2e8f0; padding: 12px; border-radius: 8px; color: #047857; font-size: 12px; font-family: monospace; white-space: pre-wrap; word-break: break-all; max-height: 140px; overflow-y: auto;"></pre>
        <button onclick="copyModalCookie()" style="position: absolute; top: 8px; right: 8px; background: #2563eb; color: #fff; border: none; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; cursor: pointer;">Copy</button>
      </div>
    </div>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 16px;">
      <div>
        <label>Expires At</label>
        <div id="modal-expiry" style="color: #0f172a; font-size: 14px; margin-top: 4px; font-weight: 600;"></div>
      </div>
      <div>
        <label>Cookie Generated At</label>
        <div id="modal-gen" style="color: #0f172a; font-size: 14px; margin-top: 4px; font-weight: 600;"></div>
      </div>
    </div>
    <div style="margin-bottom: 20px;">
      <label>Stream URL</label>
      <div id="modal-url" style="color: #475569; font-size: 12px; font-family: monospace; word-break: break-all; margin-top: 4px;"></div>
    </div>
    <div style="text-align: right;">
      <button onclick="closeCookieModal()" style="background: #f1f5f9; color: #0f172a; border: 1px solid #cbd5e1; padding: 8px 18px; border-radius: 6px; cursor: pointer; font-weight: 600;">Close</button>
    </div>
  </div>
</div>

<div id="iframe-modal" class="modal-overlay">
  <div class="modal-card">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid #e2e8f0; padding-bottom: 12px;">
      <h3 id="iframe-modal-title" style="color: #0f172a; font-size: 18px; font-weight: 700;">Embed iFrame Code</h3>
      <button onclick="closeIframeModal()" style="background: transparent; border: none; color: #64748b; font-size: 20px; cursor: pointer;">&times;</button>
    </div>
    <div style="margin-bottom: 16px;">
      <label style="display: block; margin-bottom: 6px; color: #475569; font-weight: 700; text-transform: uppercase; font-size: 12px;">Select Authorized Domain for iFrame</label>
      <select id="iframe-domain-select" onchange="updateIframeCodeForSelectedDomain()" style="width: 100%; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 10px 14px; color: #0f172a; font-size: 14px; font-weight: 600; outline: none; cursor: pointer;">
      </select>
    </div>
    <div style="margin-bottom: 16px;">
      <label style="display: block; margin-bottom: 6px; color: #475569; font-weight: 700; text-transform: uppercase; font-size: 12px;">HTML iFrame Embed Code</label>
      <div style="position: relative;">
        <pre id="iframe-code-text" style="background: #f8fafc; border: 1px solid #e2e8f0; padding: 14px; border-radius: 8px; color: #0f172a; font-size: 13px; font-family: monospace; white-space: pre-wrap; word-break: break-all; max-height: 140px; overflow-y: auto;"></pre>
        <button onclick="copyIframeCodeText()" style="position: absolute; top: 8px; right: 8px; background: #2563eb; color: #fff; border: none; padding: 6px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; cursor: pointer;">Copy Code</button>
      </div>
    </div>
    <div style="background: #eff6ff; border-left: 4px solid #2563eb; padding: 12px; border-radius: 6px; font-size: 13px; color: #1e40af; margin-bottom: 20px;">
      <strong>Authorized Domain Protection Active:</strong><br>
      This stream iframe will only play when embedded inside the selected authorized domain. Direct address bar navigation to the raw iframe URL is automatically blocked with 403 Forbidden.
    </div>
    <div style="text-align: right;">
      <button onclick="closeIframeModal()" style="background: #f1f5f9; color: #0f172a; border: 1px solid #cbd5e1; padding: 8px 18px; border-radius: 6px; cursor: pointer; font-weight: 600;">Close</button>
    </div>
  </div>
</div>

<div id="cookie-format-info-modal" class="modal-overlay">
  <div class="modal-card" style="max-width: 580px;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid #e2e8f0; padding-bottom: 12px;">
      <h3 style="color: #0f172a; font-size: 18px; font-weight: 700; display: flex; align-items: center; gap: 8px;">Supported Cookie & Token Formats</h3>
      <button onclick="closeCookieFormatModal()" style="background: transparent; border: none; color: #64748b; font-size: 20px; cursor: pointer;">&times;</button>
    </div>
    <div style="font-size: 13px; color: #334155; line-height: 1.6; max-height: 380px; overflow-y: auto; padding-right: 6px;">
      
      <div style="margin-bottom: 14px; background: #f8fafc; padding: 12px; border-radius: 8px; border: 1px solid #e2e8f0;">
        <strong style="color: #0f172a; display: block; margin-bottom: 4px;">1. JioTV / Akamai 'hdnea' Token</strong>
        <span style="color: #64748b;">Used for JioTV, JioTV+, and Akamai CDN streams. Automatically injected into all segment requests.</span>
        <code style="display: block; background: #ffffff; border: 1px solid #e2e8f0; padding: 6px 10px; border-radius: 6px; color: #047857; font-family: monospace; font-size: 11px; margin-top: 6px; word-break: break-all;">hdnea=st=1700000000~exp=1700086400~acl=/*~hmac=abcdef...</code>
        <code style="display: block; background: #ffffff; border: 1px solid #e2e8f0; padding: 6px 10px; border-radius: 6px; color: #047857; font-family: monospace; font-size: 11px; margin-top: 4px; word-break: break-all;">__hdnea__=st=1700000000~exp=1700086400~acl=/*~hmac=abcdef...</code>
      </div>

      <div style="margin-bottom: 14px; background: #f8fafc; padding: 12px; border-radius: 8px; border: 1px solid #e2e8f0;">
        <strong style="color: #0f172a; display: block; margin-bottom: 4px;">2. Standard HTTP Cookie Header</strong>
        <span style="color: #64748b;">Multiple key-value pairs separated by semicolons for CloudFront or custom auth nodes.</span>
        <code style="display: block; background: #ffffff; border: 1px solid #e2e8f0; padding: 6px 10px; border-radius: 6px; color: #047857; font-family: monospace; font-size: 11px; margin-top: 6px; word-break: break-all;">CloudFront-Key-Pair-Id=K12345; CloudFront-Signature=...; CloudFront-Policy=...</code>
      </div>

      <div style="margin-bottom: 14px; background: #f8fafc; padding: 12px; border-radius: 8px; border: 1px solid #e2e8f0;">
        <strong style="color: #0f172a; display: block; margin-bottom: 4px;">3. Bearer Authorization Token</strong>
        <span style="color: #64748b;">Standard OAuth / JWT tokens for API authorized streams.</span>
        <code style="display: block; background: #ffffff; border: 1px solid #e2e8f0; padding: 6px 10px; border-radius: 6px; color: #047857; font-family: monospace; font-size: 11px; margin-top: 6px; word-break: break-all;">Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6...</code>
      </div>

      <div style="background: #f8fafc; padding: 12px; border-radius: 8px; border: 1px solid #e2e8f0;">
        <strong style="color: #0f172a; display: block; margin-bottom: 4px;">4. Raw Token Parameter</strong>
        <span style="color: #64748b;">Plain token string appended directly to manifest and media segment URLs.</span>
        <code style="display: block; background: #ffffff; border: 1px solid #e2e8f0; padding: 6px 10px; border-radius: 6px; color: #047857; font-family: monospace; font-size: 11px; margin-top: 6px; word-break: break-all;">st=1700000000~exp=1700086400~acl=/*~hmac=abcdef...</code>
      </div>

    </div>
    <div style="text-align: right; margin-top: 16px;">
      <button onclick="closeCookieFormatModal()" style="background: #2563eb; color: #fff; border: none; padding: 8px 20px; border-radius: 6px; cursor: pointer; font-weight: 600;">Got It</button>
    </div>
  </div>
</div>

  <div id="tab-content-extractor" style="display: none;">
    <div class="sub-tabs" style="margin-bottom: 12px;">
      <button id="ext-tab-fancode" onclick="switchExtTab('fancode')" class="tab-btn active">Fancode</button>
      <button id="ext-tab-sonyliv" onclick="switchExtTab('sonyliv')" class="tab-btn">SonyLIV</button>
      <button id="ext-tab-tapmad" onclick="switchExtTab('tapmad')" class="tab-btn">Tapmad</button>
      <button id="ext-tab-willow" onclick="switchExtTab('willow')" class="tab-btn">Willow</button>
      <button id="ext-tab-primevideo" onclick="switchExtTab('primevideo')" class="tab-btn">PrimeVideo</button>
      <button id="ext-tab-jiostb" onclick="switchExtTab('jiostb')" class="tab-btn">JioSTB</button>
    </div>
    
    <div class="card" style="margin-bottom: 12px; position: relative; min-height: 400px; padding-bottom: 80px;">
      <div class="card-title">
        <span id="ext-source-title">Fancode Live Matches</span>
        <div style="display: flex; gap: 8px;">
          <button onclick="fetchExtData()" class="tab-btn" style="padding: 6px 12px; font-size: 12px;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6"></path><path d="M1 20v-6h6"></path><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>
            Refresh
          </button>
        </div>
      </div>
      
      <div id="ext-loading" style="display:none; text-align:center; padding: 40px; color: #2563eb; font-weight: 600;">⏳ Loading live sports data...</div>
      
      <div id="ext-grid" class="form-grid" style="grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));">
        <!-- Matches will be rendered here -->
      </div>
      
      <div id="ext-pagination" style="display: flex; justify-content: center; gap: 12px; margin-top: 16px;">
        <button onclick="prevExtPage()" class="tab-btn" id="ext-prev-btn" style="padding: 6px 14px;">&laquo; Prev</button>
        <span id="ext-page-info" style="color: #64748b; align-self: center; font-size: 13px; font-weight: 600;">Page 1</span>
        <button onclick="nextExtPage()" class="tab-btn" id="ext-next-btn" style="padding: 6px 14px;">Next &raquo;</button>
      </div>
    </div>
  </div>

  <!-- Match Details Modal -->
  <div id="ext-details-modal" class="modal-overlay">
    <div class="modal-card" style="position: relative;">
      <button onclick="closeExtDetailsModal()" style="position: absolute; top: 16px; right: 16px; background: none; border: none; color: #94a3b8; font-size: 24px; cursor: pointer; line-height: 1;">&times;</button>
      <div style="display: flex; gap: 16px; align-items: flex-start; margin-bottom: 20px;">
        <img id="ext-modal-logo" src="" style="width: 80px; height: 80px; object-fit: cover; border-radius: 8px; background: #e2e8f0; border: 1px solid #cbd5e1;">
        <div>
          <h2 id="ext-modal-title" style="margin: 0 0 8px 0; color: #0f172a; font-size: 18px; font-weight: 700;"></h2>
          <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
            <span id="ext-modal-status" class="badge"></span>
            <span id="ext-modal-source-badge" class="stream-pill badge-fancode" style="display:none;"></span>
          </div>
        </div>
      </div>
      
      <div class="form-grid" style="grid-template-columns: 1fr;">
        <div class="input-group">
          <label>Match Title</label>
          <input type="text" id="ext-modal-edit-title">
        </div>
        
        <div class="input-group">
          <label>Select Stream URL</label>
          <select id="ext-modal-url-select" style="font-family: monospace; font-size: 13px;" onchange="autoDetectExtStreamType()"></select>
        </div>
        
        <div class="input-group">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <label>Stream Type</label>
            <span id="ext-stream-type-pill" class="stream-pill" style="display:none;"></span>
          </div>
          <select id="ext-modal-stream-type" onchange="onExtStreamTypeChange()">
            <option value="auto">⚡ Auto Detect (Live Stream Analysis)</option>
            <option value="hls">▶ HLS (.m3u8)</option>
            <option value="mpd_cookie">🍪 MPD + Cookie</option>
            <option value="mpd">🎬 MPD (DASH)</option>
            <option value="fancode">⚡ FanCode</option>
          </select>
          <div id="ext-stream-type-banner" style="margin-top:6px; font-size:12px; font-weight:600; padding:8px 12px; border-radius:6px; background:#f8fafc; border:1px solid #e2e8f0; color:#334155;"></div>
        </div>
        
        <div class="input-group">
          <label>Bind Domain</label>
          <select id="ext-modal-domain" required></select>
        </div>
        
        <div class="input-group">
          <label>DRM Keys (kid:key)</label>
          <input type="text" id="ext-modal-keys" placeholder="Leave empty if not DRM" oninput="autoDetectExtStreamType()">
        </div>
        
        <div class="input-group">
          <label>Headers (JSON or Raw Cookie)</label>
          <input type="text" id="ext-modal-headers" placeholder="Leave empty if no headers needed" oninput="autoDetectExtStreamType()">
        </div>
      </div>
      
      <div style="margin-top: 20px; display: flex; gap: 12px;">
        <button onclick="testExtStream()" id="btn-test-stream" class="btn-submit" style="flex: 1; background: #475569;">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
          Test Stream
        </button>
        <button onclick="publishExtMatch()" id="btn-publish-stream" class="btn-submit" style="flex: 1; background: #059669;">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
          Publish Match
        </button>
      </div>
      
      <div id="ext-tester-container" style="display: none; margin-top: 20px; border-top: 1px solid #e2e8f0; padding-top: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <span style="font-size: 13px; font-weight: 700; color: #0f172a;">Live Stream Preview:</span>
          <span id="preview-status-pill" class="stream-pill badge-hls">Connecting...</span>
        </div>
        <div style="background: #000; border-radius: 8px; overflow: hidden; position: relative; aspect-ratio: 16/9; box-shadow: 0 4px 12px rgba(0,0,0,0.15);">
          <iframe id="ext-tester-iframe" src="" style="width: 100%; height: 100%; border: none;" allowfullscreen></iframe>
        </div>
      </div>
    </div>
  </div>

  <!-- Confirmation Modal -->
  <div id="confirmation-modal" class="modal-overlay">
    <div class="modal-card" style="max-width: 450px; text-align: center;">
      <h3 style="margin-bottom: 16px; color: #0f172a;">Confirm Match Creation</h3>
      <p style="color: #475569; margin-bottom: 24px; font-size: 14px;">Are you sure you want to publish this match?</p>
      <div style="background: #f1f5f9; padding: 12px; border-radius: 8px; text-align: left; margin-bottom: 24px; font-size: 13px;">
        <div style="margin-bottom: 8px;"><strong>Title:</strong> <span id="confirm-title" style="color:#0ea5e9;"></span></div>
        <div><strong>Domain:</strong> <span id="confirm-domain" style="color:#0ea5e9;"></span></div>
      </div>
      <div style="display: flex; gap: 12px; justify-content: center;">
        <button onclick="document.getElementById('confirmation-modal').style.display='none'" class="tab-btn" style="flex: 1;">Cancel</button>
        <button id="confirm-submit-btn" class="btn-submit" style="flex: 1;">Yes, Publish!</button>
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

function switchTab(tabName, skipCache = false) {
  if (!skipCache) localStorage.setItem('nibba_admin_tab', tabName);
  document.getElementById('tab-content-matches').style.display = tabName === 'matches' ? 'block' : 'none';
  document.getElementById('tab-content-cron').style.display = tabName === 'cron' ? 'block' : 'none';
  document.getElementById('tab-content-extractor').style.display = tabName === 'extractor' ? 'block' : 'none';
  
  const matchesBtn = document.getElementById('tab-btn-matches');
  const cronBtn = document.getElementById('tab-btn-cron');
  const extBtn = document.getElementById('tab-btn-extractor');
  
  matchesBtn.classList.remove('active');
  cronBtn.classList.remove('active');
  extBtn.classList.remove('active');
  
  if (tabName === 'matches') {
    matchesBtn.classList.add('active');
  } else if (tabName === 'cron') {
    cronBtn.classList.add('active');
    if (cronChannelsData.length === 0) {
      loadCronChannels();
    }
  } else if (tabName === 'extractor') {
    extBtn.classList.add('active');
    if (extAllMatches.length === 0) {
      switchExtTab('fancode');
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
  box.innerHTML = '<div style="color: #2563eb; padding: 14px; background: #f8fafc; border-radius: 8px; border: 1px solid #e2e8f0; font-weight: 600;">⚡ Executing live dry run simulation across all worker pools (as-cjbp, as-brobp, as-cksbp, as-cxfiosbp, as-test)...</div>';

  try {
    const res = await fetch('/api/get/admin?action=dry_run', { headers: { 'Accept': 'application/json' } });
    const data = await res.json();
    
    let html = '<div style="background: #ffffff; padding: 16px; border-radius: 12px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">' +
      '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:8px;">' +
        '<span style="font-weight:700; color:#0f172a; font-size:15px;">📊 Live Worker & Stream Dry Run Summary</span>' +
        '<span style="font-size:12px; color:#64748b;">Tested At: ' + new Date(data.timestamp).toLocaleTimeString() + '</span>' +
      '</div>' +
      '<div style="display:flex; gap:12px; margin-bottom:14px; flex-wrap:wrap;">' +
        '<span style="background:#ecfdf5; color:#047857; border: 1px solid #a7f3d0; padding:4px 12px; border-radius:20px; font-weight:700; font-size:12px;">✅ Passing: ' + data.summary.pass + '</span>' +
        '<span style="background:#fef2f2; color:#dc2626; border: 1px solid #fecaca; padding:4px 12px; border-radius:20px; font-weight:700; font-size:12px;">❌ Failing: ' + data.summary.fail + '</span>' +
        '<span style="background:#f1f5f9; color:#475569; border: 1px solid #cbd5e1; padding:4px 12px; border-radius:20px; font-weight:700; font-size:12px;">Total Pool: ' + data.summary.total + '</span>' +
      '</div>' +
      '<div style="overflow-x:auto;">' +
        '<table style="width:100%; border-collapse:collapse; font-size:12px;">' +
          '<thead><tr style="border-bottom:2px solid #e2e8f0; background:#f8fafc; color:#475569; text-align:left;">' +
            '<th style="padding:10px 8px; font-weight:700;">Worker Source</th>' +
            '<th style="padding:10px 8px; font-weight:700;">Test Stream Name</th>' +
            '<th style="padding:10px 8px; font-weight:700;">Latency</th>' +
            '<th style="padding:10px 8px; font-weight:700;">Cookie Token</th>' +
            '<th style="padding:10px 8px; font-weight:700;">Stream Health</th>' +
          '</tr></thead><tbody>';

    data.results.forEach(r => {
      const badgeStyle = r.ok ? 'background:#ecfdf5; color:#047857; border: 1px solid #a7f3d0;' : 'background:#fef2f2; color:#dc2626; border: 1px solid #fecaca;';
      const badgeText = r.ok ? '✅ ONLINE (HTTP ' + r.status + ')' : '❌ FAIL (HTTP ' + r.status + ')';
      const cookieBadge = r.hasCookie ? '<span style="color:#047857; font-weight:600;">🔑 Active</span>' : '<span style="color:#94a3b8;">⚪ None</span>';
      
      html += '<tr style="border-bottom:1px solid #e2e8f0;">' +
        '<td style="padding:10px 8px; font-weight:700; color:#2563eb; white-space:nowrap;">' + r.source + '</td>' +
        '<td style="padding:10px 8px; color:#0f172a; font-weight:600;">' + r.name + '</td>' +
        '<td style="padding:10px 8px; color:#475569; white-space:nowrap;">⚡ ' + r.latencyMs + 'ms</td>' +
        '<td style="padding:10px 8px; white-space:nowrap;">' + cookieBadge + '</td>' +
        '<td style="padding:10px 8px; white-space:nowrap;"><span style="padding:3px 8px; border-radius:4px; font-weight:600; ' + badgeStyle + '">' + badgeText + '</span></td>' +
      '</tr>';
    });

    html += '</tbody></table></div></div>';
    box.innerHTML = html;
  } catch (e) {
    box.innerHTML = '<div style="background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; padding: 12px; border-radius: 8px;">❌ Dry run failed: ' + e.message + '</div>';
  } finally {
    btn.disabled = false;
    btn.innerText = '🧪 Run Live Stream Dry Run';
  }
}

async function loadCronChannels() {
  const tbody = document.getElementById('cron-table-body');
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 20px; color: #64748b;">⏳ Aggregating channel cookies across all workers...</td></tr>';
  try {
    const res = await fetch('/api/get/admin?action=cron_list', {
      headers: { 'Accept': 'application/json' }
    });
    cronChannelsData = await res.json();
    renderCronChannels(cronChannelsData);
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 20px; color: #dc2626;">Failed to load aggregated cron channel list.</td></tr>';
  }
}

let activeCronCategory = 'all';

function setCronCategory(cat) {
  activeCronCategory = cat;
  ['all', 'jp', 'j', 'cj', 'st', 'normal'].forEach(c => {
    const btn = document.getElementById('cron-subtab-' + c);
    if (btn) {
      if (c === cat) {
        btn.style.background = '#2563eb';
        btn.style.color = '#ffffff';
        btn.style.borderColor = '#2563eb';
      } else {
        btn.style.background = '#ffffff';
        btn.style.color = '#64748b';
        btn.style.borderColor = '#cbd5e1';
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

    html += '<tr style="border-bottom: 1px solid #e2e8f0;">' +
      '<td style="padding: 12px; color: #2563eb; font-weight: 700; font-size: 11px; white-space: nowrap;">' + workerSource + '</td>' +
      '<td style="padding: 12px; color: #0f172a; font-family: monospace; font-weight: 600; white-space: nowrap;">' + ssid + ' (' + (ch.id || '') + ')</td>' +
      '<td style="padding: 12px; color: #1e293b; font-weight: 600;">' + (ch.name || 'Channel') + '</td>' +
      '<td style="padding: 12px; color: #047857; font-size: 13px; font-weight:600; white-space: nowrap;">' + expTime + '</td>' +
      '<td style="padding: 12px; color: #64748b; font-size: 13px; white-space: nowrap;">' + genTime + '</td>' +
      '<td style="padding: 12px; white-space: nowrap;">' +
        '<div style="display: flex; gap: 8px; align-items: center;">' +
          '<button onclick="openCookieModal(' + idx + ')" style="background: #ffffff; color: #1e293b; border: 1px solid #cbd5e1; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 4px;">👁️ View Cookie</button>' +
          '<button onclick="runCronUpdate()" style="background: #2563eb; color: #fff; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 4px;">🔄 Update</button>' +
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

// --- STREAM TYPE AUTO-DETECTION HELPER ---
function detectStreamTypeInfo(url, headers = '', keys = '') {
  const u = (url || '').trim().toLowerCase();
  const h = (typeof headers === 'string' ? headers : JSON.stringify(headers || '')).toLowerCase();
  const k = (keys || '').trim().toLowerCase();

  // FanCode
  if (u.includes('fancode') || u.includes('dai.fancode.com') || h.includes('fancode')) {
    return { type: 'fancode', label: 'FanCode', badgeClass: 'badge-fancode', icon: '⚡' };
  }
  // HLS (.m3u8)
  if (u.includes('.m3u8') || u.includes('hls') || u.includes('master.m3u8')) {
    return { type: 'hls', label: 'HLS (.m3u8)', badgeClass: 'badge-hls', icon: '▶' };
  }
  // MPD with Cookie / Token
  if (u.includes('.mpd') || u.includes('dash') || u.includes('manifest.mpd')) {
    const hasCookie = (h.length > 5 || h.includes('hdnea') || h.includes('cookie') || h.includes('bearer') || h.includes('token') || k.length > 5);
    if (hasCookie) {
      return { type: 'mpd_cookie', label: 'MPD + Cookie', badgeClass: 'badge-mpd-cookie', icon: '🍪' };
    }
    return { type: 'mpd', label: 'MPD (DASH)', badgeClass: 'badge-mpd', icon: '🎬' };
  }
  // Generic MPD if keys provided
  if (k.length > 0) {
    return { type: 'mpd', label: 'MPD (DASH)', badgeClass: 'badge-mpd', icon: '🎬' };
  }
  // Default to HLS
  return { type: 'hls', label: 'HLS (.m3u8)', badgeClass: 'badge-hls', icon: '▶' };
}

function autoDetectManualStreamType() {
  const url = (document.getElementById('manual-stream-url')?.value || '').trim();
  const cookie = (document.getElementById('manual-cookie')?.value || '').trim();
  const keys = (document.getElementById('manual-keys')?.value || '').trim();
  const typeSelect = document.getElementById('manual-stream-type');
  const pill = document.getElementById('manual-type-pill');
  const banner = document.getElementById('manual-type-banner');

  if (!url) {
    if (pill) pill.style.display = 'none';
    if (banner) banner.style.display = 'none';
    return;
  }

  const detected = detectStreamTypeInfo(url, cookie, keys);

  if (pill) {
    pill.style.display = 'inline-flex';
    pill.className = 'stream-pill ' + detected.badgeClass;
    pill.innerHTML = detected.icon + ' ' + detected.label;
  }

  if (banner) {
    banner.style.display = 'block';
    if (detected.type === 'fancode') {
      banner.style.background = '#f3e8ff';
      banner.style.color = '#7e22ce';
      banner.style.border = '1px solid #e9d5ff';
      banner.innerHTML = '⚡ Auto-Detected <strong>FanCode Stream</strong>. Direct FanCode playback pipeline active.';
    } else if (detected.type === 'hls') {
      banner.style.background = '#ecfdf5';
      banner.style.color = '#047857';
      banner.style.border = '1px solid #a7f3d0';
      banner.innerHTML = '▶ Auto-Detected <strong>HLS Stream (.m3u8)</strong>. Native HLS pipeline active.';
    } else if (detected.type === 'mpd_cookie') {
      banner.style.background = '#fffbeb';
      banner.style.color = '#b45309';
      banner.style.border = '1px solid #fde68a';
      banner.innerHTML = '🍪 Auto-Detected <strong>MPD + Cookie Stream</strong>. Session tokens will be forwarded.';
    } else {
      banner.style.background = '#eff6ff';
      banner.style.color = '#1d4ed8';
      banner.style.border = '1px solid #bfdbfe';
      banner.innerHTML = '🎬 Auto-Detected <strong>MPD (DASH) Stream</strong>. DASH playback pipeline active.';
    }
  }
}

function onManualStreamTypeChange() {
  const typeSelect = document.getElementById('manual-stream-type');
  if (typeSelect && typeSelect.value !== 'auto') {
    const pill = document.getElementById('manual-type-pill');
    const banner = document.getElementById('manual-type-banner');
    const selVal = typeSelect.value;
    const labels = {
      hls: { label: 'HLS (.m3u8)', cls: 'badge-hls', icon: '▶' },
      mpd_cookie: { label: 'MPD + Cookie', cls: 'badge-mpd-cookie', icon: '🍪' },
      mpd: { label: 'MPD (DASH)', cls: 'badge-mpd', icon: '🎬' },
      fancode: { label: 'FanCode', cls: 'badge-fancode', icon: '⚡' }
    };
    const chosen = labels[selVal];
    if (chosen) {
      if (pill) {
        pill.style.display = 'inline-flex';
        pill.className = 'stream-pill ' + chosen.cls;
        pill.innerHTML = chosen.icon + ' ' + chosen.label;
      }
      if (banner) {
        banner.style.display = 'block';
        banner.style.background = '#f8fafc';
        banner.style.color = '#334155';
        banner.style.border = '1px solid #e2e8f0';
        banner.innerHTML = 'Manual Stream Type Override: <strong>' + chosen.label + '</strong>';
      }
    }
  } else {
    autoDetectManualStreamType();
  }
}

function copyModalCookie() {
  const text = document.getElementById('modal-cookie').innerText;
  navigator.clipboard.writeText(text).then(() => {
    alert('Cookie copied to clipboard!');
  });
}

const ALLOWED_DOMAINS_LIST = [
  "nibbu.arabba.workers.dev",
  "nibbu.pages.dev",
  "sony.rabba.workers.dev",
  "nibbu.workers.dev"
];

let currentIframeSsid = '';

function openIframeModal(ssid, playUrl) {
  currentIframeSsid = ssid;
  
  const selectEl = document.getElementById('iframe-domain-select');
  if (selectEl) {
    selectEl.innerHTML = '';
    const currentHost = window.location.hostname;
    const domainOptions = Array.from(new Set([currentHost, ...ALLOWED_DOMAINS_LIST])).filter(Boolean);
    domainOptions.forEach(dom => {
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
  
  fetch('/api/get/admin?action=get_token&ssid=' + encodeURIComponent(currentIframeSsid) + '&target_domain=' + encodeURIComponent(selectedDomain) + '&password=' + encodeURIComponent('@hariom@00'), {
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
      body: JSON.stringify({ action: 'delete', docId: docId, password: '@hariom@00' })
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

// --- AUTO EXTRACTOR LOGIC ---
const extSources = {
  fancode: 'https://raw.githubusercontent.com/drmlive/fancode-live-events/main/fancode.json',
  sonyliv: 'https://raw.githubusercontent.com/drmlive/sliv-live-events/main/sonyliv.json',
  tapmad: 'https://gist.githubusercontent.com/albatr0ssss/3cff7a26be49b1d352c15f615067e7cd/raw/tapmad_bd.json',
  willow: 'https://raw.githubusercontent.com/srhady/willow-event/refs/heads/main/live_sports.json',
  primevideo: 'https://raw.githubusercontent.com/srhady/willow-event/refs/heads/main/primevideo_sports.json',
  jiostb: 'https://raw.githubusercontent.com/sportlive18/jio-tv-auto-update-playlist/refs/heads/main/star2.json'
};

let currentExtSource = '';
let extAllMatches = [];
let extCurrentPage = 1;
const extItemsPerPage = 12;

function switchExtTab(source, skipCache = false) {
  currentExtSource = source;
  if (!skipCache) localStorage.setItem('nibba_admin_ext_source', source);
  document.querySelectorAll('#tab-content-extractor .sub-tabs .tab-btn').forEach(btn => btn.classList.remove('active'));
  const targetBtn = document.getElementById('ext-tab-' + source);
  if (targetBtn) targetBtn.classList.add('active');
  
  const titles = { fancode: 'Fancode', sonyliv: 'SonyLIV', tapmad: 'Tapmad', willow: 'Willow', primevideo: 'PrimeVideo', jiostb: 'JioSTB' };
  document.getElementById('ext-source-title').innerText = (titles[source] || source) + ' Live Matches';
  
  fetchExtData();
}

async function fetchExtData() {
  const grid = document.getElementById('ext-grid');
  const loading = document.getElementById('ext-loading');
  grid.innerHTML = '';
  loading.style.display = 'block';
  extAllMatches = [];
  
  try {
    const url = extSources[currentExtSource] + '?t=' + Date.now();
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch ' + currentExtSource);
    let data = await res.json();
    
    let matches = [];
    if (currentExtSource === 'fancode') matches = data.matches || [];
    else if (currentExtSource === 'sonyliv') matches = data.matches || [];
    else if (currentExtSource === 'tapmad') matches = data.Matches || [];
    else if (currentExtSource === 'willow') matches = data.Matches || [];
    else if (currentExtSource === 'primevideo') matches = data.Matches || [];
    else if (currentExtSource === 'jiostb') matches = Array.isArray(data) ? data : [];
    
    extAllMatches = matches.map((m, index) => {
      let item = { id: index, original: m, title: '', logo: '', streamUrl: '', allUrls: [], keyHex: '', headers: '', status: '' };
      if (currentExtSource === 'fancode') {
        item.title = m.match_name || m.title || 'Unknown';
        item.logo = m.src || '';
        item.status = (m.status || '').toUpperCase();
        if (m.adfree_url) item.allUrls.push({name: 'Ad-Free', url: m.adfree_url});
        if (m.dai_url) item.allUrls.push({name: 'DAI', url: m.dai_url});
        item.streamUrl = item.allUrls.length > 0 ? item.allUrls[0].url : '';
        if (m['user-agent']) {
          item.headers = '{"User-Agent": "' + m['user-agent'] + '"}';
        }
      } else if (currentExtSource === 'sonyliv') {
        item.title = m.match_name || m.event_name || 'Unknown';
        item.logo = m.src || '';
        item.status = m.isLive ? 'LIVE' : 'UPCOMING';
        if (m.dai_url) item.allUrls.push({name: 'DAI', url: m.dai_url});
        if (m.pub_url) item.allUrls.push({name: 'PUB', url: m.pub_url});
        item.streamUrl = item.allUrls.length > 0 ? item.allUrls[0].url : '';
      } else if (currentExtSource === 'tapmad') {
        item.title = m.VideoName || 'Unknown';
        item.logo = m.ThumbnailStandard || '';
        item.status = (m.Status || '').toUpperCase();
        if (m.StreamUrl) item.allUrls.push({name: 'Stream 1', url: m.StreamUrl});
        if (m.VideoUrl) item.allUrls.push({name: 'Video', url: m.VideoUrl});
        item.streamUrl = item.allUrls.length > 0 ? item.allUrls[0].url : '';
      } else if (currentExtSource === 'willow' || currentExtSource === 'primevideo') {
        item.title = m.title || 'Unknown';
        item.logo = m.cover_image || '';
        item.status = (m.status || '').toUpperCase();
        if (m.stream_url_alpha) item.allUrls.push({name: 'Alpha', url: m.stream_url_alpha});
        if (m.match_url) item.allUrls.push({name: 'Match', url: m.match_url});
        item.streamUrl = item.allUrls.length > 0 ? item.allUrls[0].url : '';
        item.keyHex = m.drm_key || '';
      } else if (currentExtSource === 'jiostb') {
        item.title = m.name || 'Unknown';
        item.logo = m.logo || '';
        item.status = 'LIVE';
        if (m.stream_url) item.allUrls.push({name: 'Stream', url: m.stream_url});
        item.streamUrl = item.allUrls.length > 0 ? item.allUrls[0].url : '';
        if (m.key_id && m.key) {
          item.keyHex = m.key_id + ':' + m.key;
        }
        if (m.cookie) {
          item.headers = m.cookie;
        }
      }
      return item;
    });
    
    extCurrentPage = 1;
    renderExtPage();
  } catch (err) {
    loading.innerHTML = '<span style="color:#ef4444; font-weight:600;">Error fetching data: ' + err.message + '</span>';
  }
}

function renderExtPage() {
  const grid = document.getElementById('ext-grid');
  const loading = document.getElementById('ext-loading');
  loading.style.display = 'none';
  grid.innerHTML = '';
  
  if (extAllMatches.length === 0) {
    grid.innerHTML = '<div style="grid-column: 1/-1; padding: 40px; text-align: center; color: #64748b; font-size: 14px;">No matches found for this source.</div>';
    document.getElementById('ext-pagination').style.display = 'none';
    return;
  }
  
  const totalPages = Math.ceil(extAllMatches.length / extItemsPerPage);
  document.getElementById('ext-pagination').style.display = totalPages > 1 ? 'flex' : 'none';
  document.getElementById('ext-page-info').innerText = 'Page ' + extCurrentPage + ' of ' + totalPages;
  document.getElementById('ext-prev-btn').disabled = extCurrentPage === 1;
  document.getElementById('ext-next-btn').disabled = extCurrentPage === totalPages;
  
  const start = (extCurrentPage - 1) * extItemsPerPage;
  const end = start + extItemsPerPage;
  const pageMatches = extAllMatches.slice(start, end);
  
  pageMatches.forEach(match => {
    const card = document.createElement('div');
    card.style.cssText = 'background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 12px; display: flex; flex-direction: column; gap: 8px; position: relative; cursor: pointer; transition: all 0.2s ease; box-shadow: 0 1px 3px rgba(0,0,0,0.04);';
    card.onmouseover = function() { this.style.borderColor = '#2563eb'; this.style.boxShadow = '0 6px 16px rgba(37,99,235,0.08)'; };
    card.onmouseout = function() { this.style.borderColor = '#e2e8f0'; this.style.boxShadow = '0 1px 3px rgba(0,0,0,0.04)'; };
    card.onclick = function() { openExtDetailsModal(match.id); };
    
    // Top right: LIVE / UPCOMING badge
    let statusBadgeHtml = '';
    if (match.status) {
      let bColor = match.status.includes('LIVE') ? '#dc2626' : '#2563eb';
      statusBadgeHtml = '<div style="position: absolute; top: 0; right: 0; background: ' + bColor + '; color: #fff; font-size: 10px; font-weight: 700; padding: 3px 7px; border-radius: 0 0 0 8px; z-index: 2;">' + match.status + '</div>';
    }

    // Top left: Auto-detected stream type pill
    const typeInfo = detectStreamTypeInfo(match.streamUrl, match.headers, match.keyHex);
    let typePillHtml = '<div style="position: absolute; top: 0; left: 0; padding: 3px 7px; border-radius: 0 0 8px 0; font-size: 10px; font-weight: 700; z-index: 2;" class="stream-pill ' + typeInfo.badgeClass + '">' + typeInfo.icon + ' ' + typeInfo.label + '</div>';

    card.innerHTML = '<div style="position: relative; width: 100%; aspect-ratio: 16/9; border-radius: 8px; overflow: hidden; margin-bottom: 6px; background: #f1f5f9;">' +
      typePillHtml + statusBadgeHtml +
      '<img src="' + match.logo + '" loading="lazy" style="width: 100%; height: 100%; object-fit: cover;" onerror="this.onerror=null;this.src=&quot;https://placehold.co/320x180/f1f5f9/475569?text=Live+Match&quot;">' +
      '</div>' +
      '<div style="font-size: 13px; font-weight: 700; color: #0f172a; line-height: 1.4; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;" title="' + match.title.replace(/"/g, '&quot;') + '">' + match.title + '</div>' +
      '<div style="font-size: 11px; color: #64748b; font-family: monospace; word-break: break-all; margin-top: auto; display: -webkit-box; -webkit-line-clamp: 1; -webkit-box-orient: vertical; overflow: hidden;">' + (match.streamUrl ? match.streamUrl : 'No Stream URL') + '</div>';
    grid.appendChild(card);
  });
}

function prevExtPage() { if (extCurrentPage > 1) { extCurrentPage--; renderExtPage(); } }
function nextExtPage() { const t = Math.ceil(extAllMatches.length / extItemsPerPage); if (extCurrentPage < t) { extCurrentPage++; renderExtPage(); } }

let currentExtMatch = null;

function openExtDetailsModal(matchId) {
  const match = extAllMatches.find(m => m.id === matchId);
  if (!match) return;
  currentExtMatch = match;
  
  document.getElementById('ext-details-modal').style.display = 'flex';
  document.getElementById('ext-modal-logo').src = match.logo;
  document.getElementById('ext-modal-title').innerText = match.title;
  document.getElementById('ext-modal-edit-title').value = match.title;
  
  const statusEl = document.getElementById('ext-modal-status');
  if (match.status) {
    statusEl.innerText = match.status;
    statusEl.style.background = match.status.includes('LIVE') ? '#dc2626' : '#2563eb';
    statusEl.style.color = '#fff';
    statusEl.style.display = 'inline-block';
  } else {
    statusEl.style.display = 'none';
  }
  
  const urlSelect = document.getElementById('ext-modal-url-select');
  urlSelect.innerHTML = '';
  if (match.allUrls.length > 0) {
    match.allUrls.forEach((u, i) => {
      const opt = document.createElement('option');
      opt.value = u.url;
      opt.innerText = '[' + u.name + '] ' + u.url;
      urlSelect.appendChild(opt);
    });
  } else {
    const opt = document.createElement('option');
    opt.value = match.streamUrl;
    opt.innerText = match.streamUrl ? match.streamUrl : 'No URL provided';
    urlSelect.appendChild(opt);
  }
  
  document.getElementById('ext-modal-keys').value = match.keyHex || '';
  document.getElementById('ext-modal-headers').value = match.headers || '';
  
  document.getElementById('ext-tester-container').style.display = 'none';
  document.getElementById('ext-tester-iframe').src = '';
  
  autoDetectExtStreamType();
}

function autoDetectExtStreamType() {
  const urlSelect = document.getElementById('ext-modal-url-select');
  const url = urlSelect ? urlSelect.value : '';
  const hd = document.getElementById('ext-modal-headers')?.value || '';
  const keys = document.getElementById('ext-modal-keys')?.value || '';
  const typeSelect = document.getElementById('ext-modal-stream-type');
  const pill = document.getElementById('ext-stream-type-pill');
  const banner = document.getElementById('ext-stream-type-banner');

  const detected = detectStreamTypeInfo(url, hd, keys);

  if (pill) {
    pill.style.display = 'inline-flex';
    pill.className = 'stream-pill ' + detected.badgeClass;
    pill.innerHTML = detected.icon + ' ' + detected.label;
  }

  if (banner) {
    banner.style.display = 'block';
    if (detected.type === 'fancode') {
      banner.style.background = '#f3e8ff';
      banner.style.color = '#7e22ce';
      banner.style.border = '1px solid #e9d5ff';
      banner.innerHTML = '⚡ Auto-Detected <strong>FanCode Stream</strong>. Direct FanCode playback active.';
    } else if (detected.type === 'hls') {
      banner.style.background = '#ecfdf5';
      banner.style.color = '#047857';
      banner.style.border = '1px solid #a7f3d0';
      banner.innerHTML = '▶ Auto-Detected <strong>HLS Stream (.m3u8)</strong>. Native HLS playback active.';
    } else if (detected.type === 'mpd_cookie') {
      banner.style.background = '#fffbeb';
      banner.style.color = '#b45309';
      banner.style.border = '1px solid #fde68a';
      banner.innerHTML = '🍪 Auto-Detected <strong>MPD + Cookie Stream</strong>. Session tokens will be forwarded.';
    } else {
      banner.style.background = '#eff6ff';
      banner.style.color = '#1d4ed8';
      banner.style.border = '1px solid #bfdbfe';
      banner.innerHTML = '🎬 Auto-Detected <strong>MPD (DASH) Stream</strong>. DASH playback pipeline active.';
    }
  }
}

function onExtStreamTypeChange() {
  const typeSelect = document.getElementById('ext-modal-stream-type');
  if (typeSelect && typeSelect.value !== 'auto') {
    const pill = document.getElementById('ext-stream-type-pill');
    const banner = document.getElementById('ext-stream-type-banner');
    const selVal = typeSelect.value;
    const labels = {
      hls: { label: 'HLS (.m3u8)', cls: 'badge-hls', icon: '▶' },
      mpd_cookie: { label: 'MPD + Cookie', cls: 'badge-mpd-cookie', icon: '🍪' },
      mpd: { label: 'MPD (DASH)', cls: 'badge-mpd', icon: '🎬' },
      fancode: { label: 'FanCode', cls: 'badge-fancode', icon: '⚡' }
    };
    const chosen = labels[selVal];
    if (chosen) {
      if (pill) {
        pill.style.display = 'inline-flex';
        pill.className = 'stream-pill ' + chosen.cls;
        pill.innerHTML = chosen.icon + ' ' + chosen.label;
      }
      if (banner) {
        banner.style.display = 'block';
        banner.style.background = '#f8fafc';
        banner.style.color = '#334155';
        banner.style.border = '1px solid #e2e8f0';
        banner.innerHTML = 'Manual Stream Type Override: <strong>' + chosen.label + '</strong>';
      }
    }
  } else {
    autoDetectExtStreamType();
  }
}

function closeExtDetailsModal() {
  document.getElementById('ext-details-modal').style.display = 'none';
  document.getElementById('ext-tester-iframe').src = '';
}

async function testExtStream() {
  if (!currentExtMatch) return;
  const btn = document.getElementById('btn-test-stream');
  const originalHtml = btn.innerHTML;
  btn.innerHTML = '⏳ Preparing Preview...';
  btn.disabled = true;
  
  const statusPill = document.getElementById('preview-status-pill');
  if (statusPill) {
    statusPill.innerText = 'Connecting to Stream...';
    statusPill.className = 'stream-pill badge-hls';
  }
  
  const streamUrl = document.getElementById('ext-modal-url-select').value;
  const streamType = document.getElementById('ext-modal-stream-type').value;
  const keys = document.getElementById('ext-modal-keys').value.trim();
  const hd = document.getElementById('ext-modal-headers').value.trim();
  const domain = document.getElementById('ext-modal-domain').value || window.location.hostname;
  
  const detected = detectStreamTypeInfo(streamUrl, hd, keys);
  const effectiveType = (streamType && streamType !== 'auto') ? streamType : detected.type;
  
  const formData = new URLSearchParams();
  formData.append('action', 'create');
  formData.append('password', '@hariom@00');
  formData.append('ajax', 'true');
  formData.append('title', 'Preview Test - ' + currentExtMatch.title);
  formData.append('ssid', 'test_preview_temp');
  formData.append('domain', domain);
  formData.append('streamUrl', streamUrl);
  formData.append('logo', currentExtMatch.logo || '');
  formData.append('streamType', effectiveType);
  if (keys) formData.append('keyHex', keys);
  if (hd) formData.append('headers', hd);
  
  try {
    const res = await fetch('/api/get/admin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: formData.toString()
    });
    
    let playUrl = '';
    try {
      const data = await res.json();
      if (data && data.playUrl) {
        playUrl = data.playUrl;
      }
    } catch (e) { }
    
    if (!playUrl) {
      playUrl = '/?id=test_preview_temp&t=' + Date.now();
    }
    
    document.getElementById('ext-tester-container').style.display = 'block';
    document.getElementById('ext-tester-iframe').src = playUrl;
    if (statusPill) {
      statusPill.innerText = '● LIVE PREVIEW (' + detected.label + ')';
      statusPill.className = 'stream-pill ' + detected.badgeClass;
    }
  } catch (e) {
    alert('Error setting up preview: ' + e.message);
  } finally {
    btn.innerHTML = originalHtml;
    btn.disabled = false;
  }
}

async function publishExtMatch() {
  if (!currentExtMatch) return;
  const title = document.getElementById('ext-modal-edit-title').value.trim();
  const domain = document.getElementById('ext-modal-domain').value.trim();
  if (!title) return alert('Match title is required.');
  if (!domain) return alert('Domain is required.');
  
  // Show confirmation modal
  document.getElementById('confirm-title').innerText = title;
  document.getElementById('confirm-domain').innerText = domain;
  document.getElementById('confirmation-modal').style.display = 'flex';
  
  document.getElementById('confirm-submit-btn').onclick = async function() {
    document.getElementById('confirmation-modal').style.display = 'none';
    
    const btn = document.getElementById('btn-publish-stream');
    const originalText = btn.innerHTML;
    btn.innerHTML = '⏳ Publishing...';
    btn.disabled = true;
    
    const shortSource = currentExtSource.substring(0, 3);
    const randomSuffix = Math.floor(10000 + Math.random() * 90000);
    const ssid = 'auto_' + shortSource + '_' + randomSuffix;
    
    const streamUrl = document.getElementById('ext-modal-url-select').value;
    const streamType = document.getElementById('ext-modal-stream-type').value;
    const keys = document.getElementById('ext-modal-keys').value.trim();
    const hd = document.getElementById('ext-modal-headers').value.trim();
    
    const detected = detectStreamTypeInfo(streamUrl, hd, keys);
    const effectiveType = (streamType && streamType !== 'auto') ? streamType : detected.type;
    
    const formData = new URLSearchParams();
    formData.append('action', 'create');
    formData.append('password', '@hariom@00');
    formData.append('ajax', 'true');
    formData.append('title', title);
    formData.append('ssid', ssid);
    formData.append('domain', domain);
    formData.append('streamUrl', streamUrl);
    formData.append('logo', currentExtMatch.logo || '');
    formData.append('streamType', effectiveType);
    if (keys) formData.append('keyHex', keys);
    if (hd) formData.append('headers', hd);
  
    try {
      const res = await fetch('/api/get/admin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
        body: formData.toString()
      });
      
      const data = await res.json();
      if (data && data.success) {
        alert('Match successfully created with ID: ' + (data.ssid || ssid));
        window.location.reload();
      } else {
        alert('Failed to create match: ' + (data.error || 'Server error.'));
        btn.innerHTML = originalText;
        btn.disabled = false;
      }
    } catch (e) {
      alert('Error creating match: ' + e.message);
      btn.innerHTML = originalText;
      btn.disabled = false;
    }
  };
}

// Confirmation Modal for Manual Match Creation Form
async function submitManualForm(form) {
  const submitBtn = form.querySelector('button[type="submit"]');
  const originalText = submitBtn.innerHTML;
  submitBtn.innerHTML = '⏳ Creating Match...';
  submitBtn.disabled = true;

  const urlVal = form.querySelector('[name="streamUrl"]').value;
  const cookieVal = form.querySelector('[name="cookie"]')?.value || '';
  const keysVal = form.querySelector('[name="keys"]')?.value || '';
  let streamTypeVal = form.querySelector('[name="streamType"]')?.value || 'auto';
  
  if (streamTypeVal === 'auto') {
    const detected = detectStreamTypeInfo(urlVal, cookieVal, keysVal);
    streamTypeVal = detected.type;
  }

  const formData = new FormData(form);
  formData.set('password', '@hariom@00');
  formData.set('action', 'create');
  formData.set('ajax', 'true');
  formData.set('streamType', streamTypeVal);

  try {
    const res = await fetch('/api/get/admin', {
      method: 'POST',
      headers: { 'Accept': 'application/json' },
      body: formData
    });
    const result = await res.json();
    if (result && result.success) {
      alert('Match successfully created! SSID: ' + result.ssid);
      window.location.reload();
    } else {
      alert('Failed to create match. ' + (result.error || 'Please check inputs and try again.'));
      submitBtn.innerHTML = originalText;
      submitBtn.disabled = false;
    }
  } catch (e) {
    alert('Error creating match: ' + e.message);
    submitBtn.innerHTML = originalText;
    submitBtn.disabled = false;
  }
}

function showConfirmationModal(form) {
  const title = form.querySelector('[name="title"]').value;
  const domain = form.querySelector('[name="domain"]').value;
  document.getElementById('confirm-title').innerText = title;
  document.getElementById('confirm-domain').innerText = domain;
  document.getElementById('confirmation-modal').style.display = 'flex';
  
  document.getElementById('confirm-submit-btn').onclick = function() {
    document.getElementById('confirmation-modal').style.display = 'none';
    submitManualForm(form);
  };
}

// LocalStorage & UI Initialization
document.addEventListener('DOMContentLoaded', () => {
  // Populate Domain Selects
  const currentHost = window.location.hostname;
  const domainOptions = Array.from(new Set([currentHost, ...ALLOWED_DOMAINS_LIST])).filter(Boolean);
  
  const manualDomainSelect = document.getElementById('manual-domain-select');
  const extDomainSelect = document.getElementById('ext-modal-domain');
  
  if (manualDomainSelect) {
    manualDomainSelect.innerHTML = '';
    domainOptions.forEach(dom => {
      const opt = document.createElement('option');
      opt.value = dom;
      opt.innerText = dom;
      if (dom === currentHost || dom === 'nibbu.arabba.workers.dev') opt.selected = true;
      manualDomainSelect.appendChild(opt);
    });
  }
  
  if (extDomainSelect) {
    extDomainSelect.innerHTML = '';
    domainOptions.forEach(dom => {
      const opt = document.createElement('option');
      opt.value = dom;
      opt.innerText = dom;
      if (dom === currentHost || dom === 'nibbu.arabba.workers.dev') opt.selected = true;
      extDomainSelect.appendChild(opt);
    });
  }

  const savedTab = localStorage.getItem('nibba_admin_tab') || 'matches';
  switchTab(savedTab, true);
  
  const savedExtTab = localStorage.getItem('nibba_admin_ext_source') || 'fancode';
  switchExtTab(savedExtTab, true);
  
  autoDetectManualStreamType();
});
</script>
</body>
</html>`;

    return new Response(dashboardHtml, {
        status: 200,
        headers: {
            "Content-Type": "text/html;charset=UTF-8",
            "Set-Cookie": "__sz_admin_pass=@hariom@00; Path=/; HttpOnly; Secure; SameSite=Lax"
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

        const queryUrl = url.searchParams.get("url") || "";
        const queryData = url.searchParams.get("data") || "";
        let directUrl = queryUrl;
        if (!directUrl && queryData) {
            try { directUrl = atob(queryData); } catch (e) { }
        }
        if (directUrl && isFancodeUrl(directUrl)) {
            return new Response(getFancodePlayerHtml(directUrl), {
                headers: {
                    "Content-Type": "text/html;charset=UTF-8",
                    "Access-Control-Allow-Origin": "*"
                }
            });
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
                let sbCustomData = await fetchSupabaseTable(SUPABASE_TABLE, '?select=*');

                if (Array.isArray(sbCustomData) && sbCustomData.length > 0) {
                    for (const row of sbCustomData) {
                        const title = row.title || row.matchName || "";
                        const ssid = row.ssid || "";
                        const streamUrl = (row.stream_url || row.streamUrl || row.url || "").trim().replace(/[\r\n\t\s]/g, '');
                        const keys = row.keys || row.key || "";
                        const cookie = row.cookie || row.token || "";
                        const isHls = (row.is_hls !== undefined) ? !!row.is_hls : ((row.isHls !== undefined) ? !!row.isHls : streamUrl.includes(".m3u8"));
                        const isMpd = (row.is_mpd !== undefined) ? !!row.is_mpd : ((row.isMpd !== undefined) ? !!row.isMpd : (!isHls || streamUrl.includes(".mpd")));

                        if (ssid) {
                            const customId = ssid;
                            const dataToSign = `${domain}|${timeBlock}|${customId}|unknown`;
                            const token = await generateHMAC(dataToSign, SECRET_KEY);

                            const linkCustom = `https://${domain}/?id=${encodeURIComponent(customId)}&token=${token}`;
                            addChannelItem(customId, linkCustom, isHls, isMpd, title || customId);
                        }
                    }
                }
            } catch (e) {
                console.error("Supabase custom collection fetch error in /api/get/channels", e);
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

        const isPreviewTest = (channelId === "test_preview_temp");

        if (!isPreviewTest && !isAllowedRef && navFetchDest !== "iframe" && navFetchSite === "none") {
            return new Response("403 Forbidden - Direct Access Not Allowed. Stream can only be embedded via iframe on authorized domains.", {
                status: 403,
                headers: { "Content-Type": "text/plain", "Access-Control-Allow-Origin": "*" }
            });
        }

        if (!channelId || (!providedToken && !isPreviewTest)) {
            return new Response("403 Forbidden", { status: 403 });
        }

        const domainsToCheck = Array.from(new Set([domain, ...ALLOWED_DOMAINS]));
        let isTokenValid = isPreviewTest;

        const prevTimeBlock = timeBlock - 1;

        if (!isTokenValid) {
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

        if (!channelData && !ALLOWED_CHANNELS.includes(channelId) && !BROBP_CHANNELS.includes(channelId)) {
            try {
                const cleanChId = (channelId || "").trim();
                let sbCustomData = await fetchSupabaseTable(SUPABASE_TABLE, `?select=*&or=(ssid.eq.${encodeURIComponent(cleanChId)},id.eq.${encodeURIComponent(cleanChId)})`);

                if (!sbCustomData || !Array.isArray(sbCustomData) || sbCustomData.length === 0) {
                    sbCustomData = await fetchSupabaseTable(SUPABASE_TABLE, '?select=*');
                }

                if (Array.isArray(sbCustomData) && sbCustomData.length > 0) {
                    for (const row of sbCustomData) {
                        const ssid = String(row.ssid || "").trim();
                        const docId = String(row.id || "").trim();
                        const lowerChId = cleanChId.toLowerCase();

                        if (ssid === cleanChId || docId === cleanChId || (ssid && lowerChId === ssid.toLowerCase())) {
                            const title = row.title || "";
                            const rawStreamUrl = (row.stream_url || row.streamUrl || "").trim().replace(/[\r\n\t\s]/g, '');
                            const keys = row.keys || row.key || "";
                            const cookie = row.cookie || row.token || "";
                            const isHls = (row.is_hls !== undefined) ? !!row.is_hls : ((row.isHls !== undefined) ? !!row.isHls : rawStreamUrl.includes(".m3u8"));
                            const isMpd = (row.is_mpd !== undefined) ? !!row.is_mpd : ((row.isMpd !== undefined) ? !!row.isMpd : (!isHls || rawStreamUrl.includes(".mpd")));

                            let keyId = "";
                            let keyVal = "";
                            if (keys && keys.includes(':')) {
                                const parts = keys.split(':');
                                keyId = parts[0].trim();
                                keyVal = parts[1].trim();
                            } else if (keys) {
                                keyVal = keys.trim();
                            }

                            const rowStreamType = (row.stream_type || row.streamType || "").toLowerCase();
                            channelData = {
                                name: title || ssid,
                                streamUrl: rawStreamUrl,
                                isMpd: isMpd,
                                isHls: isHls,
                                isIframe: false,
                                streamType: rowStreamType,
                                keyId: keyId,
                                key: keyVal,
                                token: cookie,
                                isAdminCustom: true
                            };
                            break;
                        }
                    }
                }
            } catch (e) {
                console.error("Supabase custom channel fetch error", e);
            }

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

        const isFancode = isFancodeUrl(finalStreamUrl) ||
            (channelData.streamType === "fancode") ||
            (channelData.name && channelData.name.toLowerCase().includes("fancode")) ||
            (channelId && channelId.toLowerCase().includes("fancode"));

        if (isFancode) {
            return new Response(getFancodePlayerHtml(finalStreamUrl), {
                headers: {
                    "Content-Type": "text/html;charset=UTF-8",
                    "Access-Control-Allow-Origin": "*"
                }
            });
        }

        if (proxiedChannel.isMpd && !hasCookie) {
            const mpdStreamUrl = proxiedChannel.streamUrl || "";
            const mpdKeyParam = (channelData.keyId && channelData.key && !channelData.keyId.includes("Error")) ? `${channelData.keyId}:${channelData.key}` : "";
            const mpdPlayerHtml = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <title>Nibba - MEDIA PLAYER</title>

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
  <script src="https://pl30385588.profitableratecpmnetwork.com/cf/ee/7f/cfee7f9e07d31ef68a8b933dede5bcf7.js"></script>

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
     * 3. AD CLICK FREQUENCY CAP (Every 2 Clicks)
     * ============================================
     */
    let adClk = 0;
    const playerContainer = document.querySelector('.shaka-video-container');
    if (playerContainer) {
        playerContainer.addEventListener('click', function(e) {
            adClk++;
            if (adClk % 2 !== 0) {
                // Prevent bubbling to document where the ad script listens
                e.stopPropagation();
            }
        });
    }

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
    <script src="https://pl30385588.profitableratecpmnetwork.com/cf/ee/7f/cfee7f9e07d31ef68a8b933dede5bcf7.js"></script>

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

    let adClkHls = 0;
    const hlsContainer = document.getElementById('player') || document.body;
    hlsContainer.addEventListener('click', function(e) {
        adClkHls++;
        if (adClkHls % 2 !== 0) {
            e.stopPropagation();
        } else {
            triggerAd();
        }
    });

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

        // Removed legacy manual triggerAd logic because new ad script handles clicks automatically.

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
