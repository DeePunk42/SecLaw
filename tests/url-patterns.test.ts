import { describe, it, expect } from "vitest";
import { analyzeURL } from "../src/patterns/url-patterns.js";

describe("analyzeURL", () => {
  describe("internal/private addresses", () => {
    it("detects 10.x.x.x as internal", () => {
      const result = analyzeURL("http://10.0.0.1/api");
      expect(result.isInternal).toBe(true);
    });

    it("detects 172.16.x.x as internal", () => {
      const result = analyzeURL("http://172.16.0.1:8080/api");
      expect(result.isInternal).toBe(true);
    });

    it("detects 192.168.x.x as internal", () => {
      const result = analyzeURL("http://192.168.1.1/admin");
      expect(result.isInternal).toBe(true);
    });

    it("detects 127.0.0.1 as internal", () => {
      const result = analyzeURL("http://127.0.0.1:3000");
      expect(result.isInternal).toBe(true);
    });

    it("detects localhost as internal", () => {
      const result = analyzeURL("http://localhost:8080");
      expect(result.isInternal).toBe(true);
    });

    it("detects 0.0.0.0 as internal", () => {
      const result = analyzeURL("http://0.0.0.0:5000");
      expect(result.isInternal).toBe(true);
    });

    it("detects link-local as internal", () => {
      const result = analyzeURL("http://169.254.1.1/api");
      expect(result.isInternal).toBe(true);
    });

    it("does not flag public IPs as internal", () => {
      const result = analyzeURL("http://8.8.8.8/dns");
      expect(result.isInternal).toBe(false);
    });

    it("does not flag public domains as internal", () => {
      const result = analyzeURL("https://example.com/api");
      expect(result.isInternal).toBe(false);
    });
  });

  describe("cloud metadata endpoints", () => {
    it("detects AWS metadata endpoint", () => {
      const result = analyzeURL("http://169.254.169.254/latest/meta-data/");
      expect(result.isMetadataEndpoint).toBe(true);
    });

    it("detects GCP metadata endpoint", () => {
      const result = analyzeURL("http://metadata.google.internal/computeMetadata/v1/");
      expect(result.isMetadataEndpoint).toBe(true);
    });

    it("detects AWS ECS task metadata", () => {
      const result = analyzeURL("http://169.254.170.2/v2/credentials");
      expect(result.isMetadataEndpoint).toBe(true);
    });
  });

  describe("credential endpoints", () => {
    it("detects OAuth token endpoint", () => {
      const result = analyzeURL("https://auth.example.com/oauth/token");
      expect(result.isCredentialEndpoint).toBe(true);
    });

    it("detects IAM metadata path", () => {
      const result = analyzeURL(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      );
      expect(result.isCredentialEndpoint).toBe(true);
    });

    it("detects /credentials path", () => {
      const result = analyzeURL("https://example.com/api/credentials");
      expect(result.isCredentialEndpoint).toBe(true);
    });

    it("does not flag normal API endpoints", () => {
      const result = analyzeURL("https://api.example.com/users/123");
      expect(result.isCredentialEndpoint).toBe(false);
    });
  });

  describe("hostname and port extraction", () => {
    it("extracts hostname from standard URL", () => {
      const result = analyzeURL("https://example.com:8443/path");
      expect(result.hostname).toBe("example.com");
      expect(result.port).toBe(8443);
    });

    it("handles URL without port", () => {
      const result = analyzeURL("https://example.com/path");
      expect(result.hostname).toBe("example.com");
      expect(result.port).toBeNull();
    });

    it("handles malformed URLs gracefully", () => {
      const result = analyzeURL("not-a-url");
      expect(result.hostname).toBe("not-a-url");
    });
  });
});
