/**
 * URL analysis for SSRF detection and credential endpoint identification.
 */

/** Private/internal IP ranges (RFC 1918, link-local, loopback). */
const INTERNAL_IP_PATTERNS = [
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,                    // 10.0.0.0/8
  /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/,        // 172.16.0.0/12
  /^192\.168\.\d{1,3}\.\d{1,3}$/,                         // 192.168.0.0/16
  /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,                    // 127.0.0.0/8
  /^169\.254\.\d{1,3}\.\d{1,3}$/,                         // link-local
  /^0\.0\.0\.0$/,                                          // unspecified
];

/** Hostnames that resolve to internal addresses. */
const INTERNAL_HOSTNAMES = new Set([
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
]);

/** Cloud metadata endpoints (SSRF targets). */
const METADATA_ENDPOINTS = [
  /^169\.254\.169\.254/,                                   // AWS/GCP metadata
  /^metadata\.google\.internal/,                           // GCP
  /^100\.100\.100\.200/,                                   // Alibaba Cloud
  /^169\.254\.170\.2/,                                     // AWS ECS task metadata
];

/** Credential-related URL path patterns. */
const CREDENTIAL_PATH_PATTERNS = [
  /\/latest\/meta-data\/iam/i,
  /\/computeMetadata\//i,
  /\/metadata\/instance/i,
  /\/oauth\/token/i,
  /\/token$/i,
  /\/credentials/i,
  /\/secret/i,
  /\/api-?key/i,
];

export interface URLAnalysis {
  /** Whether the URL targets an internal/private network address. */
  isInternal: boolean;
  /** Whether the URL targets a cloud metadata endpoint. */
  isMetadataEndpoint: boolean;
  /** Whether the URL path suggests credential access. */
  isCredentialEndpoint: boolean;
  /** The parsed hostname, if any. */
  hostname: string | null;
  /** The parsed port, if any. */
  port: number | null;
}

/**
 * Extract hostname and port from a URL string.
 */
function parseURL(url: string): { hostname: string | null; port: number | null; pathname: string } {
  try {
    const parsed = new URL(url);
    return {
      hostname: parsed.hostname,
      port: parsed.port ? parseInt(parsed.port, 10) : null,
      pathname: parsed.pathname,
    };
  } catch {
    // Try to extract hostname from non-standard URL formats
    const match = url.match(/^(?:\w+:\/\/)?([^:/\s]+)(?::(\d+))?(.*)$/);
    if (match) {
      return {
        hostname: match[1],
        port: match[2] ? parseInt(match[2], 10) : null,
        pathname: match[3] || "/",
      };
    }
    return { hostname: null, port: null, pathname: "/" };
  }
}

/**
 * Check if a hostname is an internal/private IP address.
 */
function isInternalHost(hostname: string): boolean {
  if (INTERNAL_HOSTNAMES.has(hostname.toLowerCase())) return true;
  if (INTERNAL_IP_PATTERNS.some((p) => p.test(hostname))) return true;

  // IPv6 loopback
  if (hostname === "::1" || hostname === "[::1]") return true;

  // Hex-encoded IPs (e.g., 0x7f000001 = 127.0.0.1)
  if (/^0x[0-9a-f]+$/i.test(hostname)) {
    const num = parseInt(hostname, 16);
    // 127.0.0.0/8
    if ((num >>> 24) === 127) return true;
    // 10.0.0.0/8
    if ((num >>> 24) === 10) return true;
    // 192.168.0.0/16
    if ((num >>> 16) === 0xc0a8) return true;
  }

  // Octal-encoded IPs (e.g., 0177.0.0.1 = 127.0.0.1)
  if (/^0\d+\./.test(hostname)) return true;

  return false;
}

/**
 * Check if a hostname matches a cloud metadata endpoint.
 */
function isMetadataHost(hostname: string): boolean {
  return METADATA_ENDPOINTS.some((p) => p.test(hostname));
}

/**
 * Analyze a URL for security-relevant features.
 */
export function analyzeURL(url: string): URLAnalysis {
  const { hostname, port, pathname } = parseURL(url);

  const isInternal = hostname ? isInternalHost(hostname) : false;
  const isMetadataEndpoint = hostname ? isMetadataHost(hostname) : false;
  const isCredentialEndpoint = CREDENTIAL_PATH_PATTERNS.some((p) =>
    p.test(pathname),
  );

  return {
    isInternal,
    isMetadataEndpoint,
    isCredentialEndpoint,
    hostname,
    port,
  };
}
