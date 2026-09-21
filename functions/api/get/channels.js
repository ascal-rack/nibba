export async function onRequest(context) {
    const { request, env } = context;

    const viewerIp = request.headers.get('CF-Connecting-IP') || 'unknown';

    const apiKey = env.API_SECRET_KEY || 'G5*bN#8zK2@vX9$mP1^qL4!cH7&yR3(t';
    const workerBase = env.WORKER_URL || "https://nibbu.arabba.workers.dev";
    const workerUrl = `${workerBase}/api/channels?client_ip=${viewerIp}`;
    
    try {
        const response = await fetch(workerUrl, {
            headers: { 
                "X-API-Key": apiKey,
                "User-Agent": "Cloudflare-Worker"
            }
        });

        if (!response.ok) {
            const errorText = await response.text();
            return new Response(JSON.stringify({ 
                error: `Backend returned status ${response.status}`,
                detail: errorText,
                status: response.status
            }), { status: response.status });
        }

        const base64Data = await response.text();
        const binaryString = atob(base64Data);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }

        const iv = bytes.slice(0, 12);
        const encryptedData = bytes.slice(12);

        const encryptionKeyStr = env.ENCRYPTION_KEY || 'wD@4jB9!vN2$xP7*kM5^qL8#cT3(hF1&';
        
        const cryptoKey = await crypto.subtle.importKey(
            "raw", new TextEncoder().encode(encryptionKeyStr),
            { name: "AES-GCM" },
            false, ["decrypt"]
        );

        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            cryptoKey,
            encryptedData
        );

        const jsonText = new TextDecoder().decode(decryptedBuffer);
        const channels = JSON.parse(jsonText);

        const grouped = {
            "as-test": { "pre-ssid": "custom" },
            "as-brobp1": { "pre-ssid": "j and jp" },
            "as-cxblbp": { "pre-ssid": "mh-" },
            "as-cxfiosbp": { "pre-ssid": "ios-" },
            "as-cksbp": { "pre-ssid": "sz-" },
            "as-stflx": { "pre-ssid": "st-" },
            "as-cjbp": { "pre-ssid": "cj-" },
            "firebase": { "pre-ssid": "custom" }
        };

        // Sort keys to put 'j' first, then 'jp', then alphabetical
        const sortedKeys = Object.keys(channels).sort((a, b) => {
            const aIsJ = a.startsWith('j') && !a.startsWith('jp');
            const bIsJ = b.startsWith('j') && !b.startsWith('jp');
            if (aIsJ && !bIsJ) return -1;
            if (!aIsJ && bIsJ) return 1;

            const aIsJp = a.startsWith('jp');
            const bIsJp = b.startsWith('jp');
            if (aIsJp && !bIsJp) return -1;
            if (!aIsJp && bIsJp) return 1;

            return a.localeCompare(b);
        });

        const formatCleanItem = (key, item) => {
            if (!item) return item;
            if (typeof item !== 'object') return item;
            return {
                name: item.name || item.title || key,
                ssid: item.ssid || key,
                link: item.link || item.url || "",
                type: item.type || (item.isMpd || item.ismpd ? "mpd" : item.isHls || item.ishls ? "hls" : "unknown")
            };
        };

        for (const key of sortedKeys) {
            const rawVal = channels[key];
            if (key === 'as-test' || key === 'as-cjbp') {
                const targetGroup = key === 'as-test' ? "as-test" : "as-cjbp";
                if (rawVal && typeof rawVal === 'object') {
                    for (const subKey in rawVal) {
                        if (subKey === "pre-ssid") continue;
                        grouped[targetGroup][subKey] = formatCleanItem(subKey, rawVal[subKey]);
                    }
                }
            } else {
                const val = formatCleanItem(key, rawVal);
                if (key.startsWith('mh-')) {
                    grouped["as-cxblbp"][key] = val;
                } else if (key.startsWith('sz-')) {
                    grouped["as-cksbp"][key] = val;
                } else if (key.startsWith('ios-')) {
                    grouped["as-cxfiosbp"][key] = val;
                } else if (key.startsWith('st-')) {
                    grouped["as-stflx"][key] = val;
                } else if (key.startsWith('cj-')) {
                    grouped["as-cjbp"][key] = val;
                } else if (key.startsWith('j') || key.startsWith('jp')) {
                    grouped["as-brobp1"][key] = val;
                } else if (channels["as-test"] && channels["as-test"][key]) {
                    continue;
                } else {
                    grouped["firebase"][key] = val;
                }
            }
        }

        function formatSingleLineJson(obj) {
            const lines = ["{"];
            const categories = Object.keys(obj);
            categories.forEach((cat, cIdx) => {
                const catObj = obj[cat];
                lines.push(`  "${cat}": {`);
                const itemKeys = Object.keys(catObj);
                itemKeys.forEach((key, kIdx) => {
                    const val = catObj[key];
                    const comma = kIdx < itemKeys.length - 1 ? "," : "";
                    if (typeof val === 'object' && val !== null) {
                        lines.push(`    "${key}": ${JSON.stringify(val)}${comma}`);
                    } else {
                        lines.push(`    "${key}": ${JSON.stringify(val)}${comma}`);
                    }
                });
                const catComma = cIdx < categories.length - 1 ? "," : "";
                lines.push(`  }${catComma}`);
            });
            lines.push("}");
            return lines.join("\n");
        }

        return new Response(formatSingleLineJson(grouped), {
            headers: { 
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            }
        });

    } catch (err) {
        return new Response(JSON.stringify({ error: "Decryption failed or internal error", detail: err.message }), { 
            status: 500,
            headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            }
        });
    }
}
