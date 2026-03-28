import { describe, it, expect } from "vitest";
import { decomposeURL, isPrivateIP } from "../src/patterns/url-patterns.js";

describe("isPrivateIP", () => {
  it("detects 10.x.x.x as private", () => {
    expect(isPrivateIP("10.0.0.1")).toBe(true);
  });

  it("detects 192.168.x.x as private", () => {
    expect(isPrivateIP("192.168.1.1")).toBe(true);
  });

  it("detects 127.0.0.1 as private", () => {
    expect(isPrivateIP("127.0.0.1")).toBe(true);
  });

  it("detects localhost as private", () => {
    expect(isPrivateIP("localhost")).toBe(true);
  });

  it("does not flag public IPs", () => {
    expect(isPrivateIP("8.8.8.8")).toBe(false);
  });

  it("detects hex-encoded IPs", () => {
    expect(isPrivateIP("0x7f000001")).toBe(true); // 127.0.0.1
  });

  it("detects octal-encoded IPs", () => {
    expect(isPrivateIP("0177.0.0.1")).toBe(true); // 127.0.0.1
  });
});

describe("decomposeURL", () => {
  it("decomposes standard URL", () => {
    const result = decomposeURL("https://example.com:8443/api/data");
    expect(result.host).toBe("example.com");
    expect(result.port).toBe(8443);
    expect(result.path).toBe("/api/data");
    expect(result.scheme).toBe("https");
    expect(result.isPrivateIP).toBe(false);
  });

  it("detects private IP in URL", () => {
    const result = decomposeURL("http://192.168.1.1/admin");
    expect(result.host).toBe("192.168.1.1");
    expect(result.isPrivateIP).toBe(true);
  });

  it("detects localhost in URL", () => {
    const result = decomposeURL("http://localhost:8080");
    expect(result.host).toBe("localhost");
    expect(result.isPrivateIP).toBe(true);
  });

  it("handles URL without port", () => {
    const result = decomposeURL("https://example.com/path");
    expect(result.host).toBe("example.com");
    expect(result.port).toBeNull();
  });

  it("handles malformed URLs gracefully", () => {
    const result = decomposeURL("not-a-url");
    expect(result.host).toBe("not-a-url");
  });

  it("handles cloud metadata URL", () => {
    const result = decomposeURL("http://169.254.169.254/latest/meta-data/");
    expect(result.host).toBe("169.254.169.254");
    expect(result.path).toBe("/latest/meta-data/");
    expect(result.isPrivateIP).toBe(true);
  });
});
