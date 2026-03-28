/**
 * URL decomposition for the Sigma-style rule engine.
 *
 * Provides structural decomposition:
 * - host, port, path, scheme from URL
 * - isPrivateIP: RFC 1918/loopback/link-local (RFC standard fact, not security judgment)
 *
 * Security judgments (which hosts are "metadata", which paths are "credential")
 * belong in YAML rules.
 */

import type { URLDecomposition } from "../config.js";

/** Private/internal IP ranges (RFC 1918, link-local, loopback). */
const INTERNAL_IP_PATTERNS = [
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/,
  /^192\.168\.\d{1,3}\.\d{1,3}$/,
  /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  /^169\.254\.\d{1,3}\.\d{1,3}$/,
  /^0\.0\.0\.0$/,
];

/** Hostnames that resolve to internal addresses. */
const INTERNAL_HOSTNAMES = new Set([
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
]);

/**
 * Check if a hostname is an internal/private IP address (RFC 1918 fact).
 */
export function isPrivateIP(hostname: string): boolean {
  if (INTERNAL_HOSTNAMES.has(hostname.toLowerCase())) return true;
  if (INTERNAL_IP_PATTERNS.some((p) => p.test(hostname))) return true;

  // IPv6 loopback
  if (hostname === "::1" || hostname === "[::1]") return true;

  // Hex-encoded IPs (e.g., 0x7f000001 = 127.0.0.1)
  if (/^0x[0-9a-f]+$/i.test(hostname)) {
    const num = parseInt(hostname, 16);
    if ((num >>> 24) === 127) return true;
    if ((num >>> 24) === 10) return true;
    if ((num >>> 16) === 0xc0a8) return true;
  }

  // Octal-encoded IPs (e.g., 0177.0.0.1 = 127.0.0.1)
  if (/^0\d+\./.test(hostname)) return true;

  return false;
}

/**
 * Parse a URL string into components.
 */
function parseURL(url: string): { hostname: string | null; port: number | null; pathname: string; protocol: string } {
  try {
    const parsed = new URL(url);
    return {
      hostname: parsed.hostname,
      port: parsed.port ? parseInt(parsed.port, 10) : null,
      pathname: parsed.pathname,
      protocol: parsed.protocol.replace(/:$/, ""),
    };
  } catch {
    const match = url.match(/^(?:(\w+):\/\/)?([^:/\s]+)(?::(\d+))?(.*)$/);
    if (match) {
      return {
        hostname: match[2],
        port: match[3] ? parseInt(match[3], 10) : null,
        pathname: match[4] || "/",
        protocol: match[1] || "",
      };
    }
    return { hostname: null, port: null, pathname: "/", protocol: "" };
  }
}

/**
 * Decompose a URL into host, port, path, scheme, and isPrivateIP.
 */
export function decomposeURL(url: string): URLDecomposition {
  const { hostname, port, pathname, protocol } = parseURL(url);

  return {
    host: hostname || "",
    port,
    path: pathname,
    scheme: protocol,
    isPrivateIP: hostname ? isPrivateIP(hostname) : false,
  };
}
