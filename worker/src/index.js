const SUSPICIOUS_PATHS = [
  "/.env", "/wp-admin", "/wp-login", "/phpmyadmin",
  "/admin", "/.git", "/config", "/backup",
];

const SUSPICIOUS_UA_PATTERNS = [
  "masscan", "nikto", "sqlmap", "nmap", "zgrab",
  "python-requests", "go-http-client", "curl/",
];

// in-memory IP counter — resets when isolate restarts
const ipHitCount = new Map();

function trackIP(ip) {
  const count = (ipHitCount.get(ip) || 0) + 1;
  ipHitCount.set(ip, count);
  if (ipHitCount.size > 10000) {
    const firstKey = ipHitCount.keys().next().value;
    ipHitCount.delete(firstKey);
  }
  return count;
}

function isSuspicious(request, ip, hitCount) {
  const ua = (request.headers.get("User-Agent") || "").toLowerCase();
  const url = request.url.toLowerCase();

  // high request rate from same IP
  if (hitCount > 15) return true;

  // blank or very short user agent
  if (ua.length < 5) return true;

  // known attack tool user agents
  if (SUSPICIOUS_UA_PATTERNS.some(p => ua.includes(p))) return true;

  // scanning known vulnerable paths
  if (SUSPICIOUS_PATHS.some(p => url.includes(p))) return true;

  return false;
}

async function forwardToFastAPI(env, payload) {
  try {
    await fetch(env.FASTAPI_URL, {
      method:  "POST",
      headers: {
        "Content-Type":    "application/json",
        "X-Worker-Secret": env.WORKER_SECRET,
      },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error("Failed to forward event:", err.message);
  }
}

export default {
  async fetch(request, env, ctx) {
    const ip      = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
    const cf      = request.cf || {};
    const hitCount = trackIP(ip);

    // always proxy the request to your actual origin first
    const response = fetch(request);

    // only forward suspicious events to save free tier quota
    if (isSuspicious(request, ip, hitCount)) {
      const payload = {
        timestamp:             new Date().toISOString(),
        ip,
        country:               cf.country        || "XX",
        city:                  cf.city           || "",
        latitude:              parseFloat(cf.latitude)  || 0.0,
        longitude:             parseFloat(cf.longitude) || 0.0,
        asn:                   cf.asn            || 0,
        asn_org:               cf.asOrganization || "",
        url:                   request.url,
        method:                request.method,
        user_agent:            request.headers.get("User-Agent") || "",
        tls_version:           cf.tlsVersion     || "",
        http_protocol:         cf.httpProtocol   || "",
        requests_this_isolate: hitCount,
      };

      // fire and forget — doesn't block the proxied response
      ctx.waitUntil(forwardToFastAPI(env, payload));
    }

    return response;
  },
};