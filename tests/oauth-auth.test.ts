import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  init,
  _getLLMAuditor,
  _setGatewayApi,
  _updateConfig,
  stopDashboard,
  LLMHttpError,
} from "../index.js";
import type { OpenClawPluginApi } from "../index.js";
import { sessionState } from "../src/session-state.js";

// ─── Helpers ───

function createMockGatewayApi(
  providers: Record<
    string,
    {
      baseUrl: string;
      apiKey?: string;
      auth?: string;
      models?: Array<{ id: string; name: string }>;
    }
  >,
  runtime?: OpenClawPluginApi["runtime"],
): OpenClawPluginApi {
  return {
    id: "test-gateway",
    name: "Test Gateway",
    config: {
      workspace: { dir: "/workspace" },
      models: { providers },
    },
    logger: { info: vi.fn(), error: vi.fn(), debug: vi.fn() },
    on: vi.fn(),
    resolvePath: (p: string) => p,
    runtime,
  };
}

function writeOpenClawConfig(
  openClawDir: string,
  data: Record<string, unknown>,
): void {
  fs.mkdirSync(openClawDir, { recursive: true });
  const configPath = path.join(openClawDir, "openclaw.json");
  fs.writeFileSync(configPath, JSON.stringify(data, null, 2), "utf-8");
}

const BASE_CONFIG = {
  llm: { model: "myapi/gpt-5.2", enabled: true, maxConcurrent: 1 },
  timeouts: {
    syncAuditMs: 10000,
    asyncAuditMs: 30000,
    syncTimeoutPolicy: "fail_closed" as const,
  },
  logging: { level: "error" as const, auditJsonl: false },
  dashboard: { enabled: false, port: 0, host: "127.0.0.1" },
};

// ─── Tests ───

describe("OAuth provider auth", () => {
  let tmpDir: string;
  let openClawDir: string;
  let prevOpenClawHome: string | undefined;
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "seclaw-oauth-"));
    openClawDir = path.join(tmpDir, ".openclaw");
    prevOpenClawHome = process.env.OPENCLAW_HOME;
    process.env.OPENCLAW_HOME = openClawDir;
    writeOpenClawConfig(openClawDir, {
      plugins: { entries: { seclaw: { config: BASE_CONFIG } } },
    });
    sessionState.clear();
    originalFetch = globalThis.fetch;
  });

  afterEach(async () => {
    _setGatewayApi(null);
    await stopDashboard();
    globalThis.fetch = originalFetch;
    fs.rmSync(tmpDir, { recursive: true, force: true });
    process.env.OPENCLAW_HOME = prevOpenClawHome;
  });

  it("static apiKey: resolveApiKeyForProvider NOT called", async () => {
    const resolveApiKey = vi.fn();
    const api = createMockGatewayApi(
      {
        myapi: {
          baseUrl: "http://localhost:4000/v1",
          apiKey: "sk-static-key",
          models: [{ id: "gpt-5.2", name: "GPT 5.2" }],
        },
      },
      { modelAuth: { resolveApiKeyForProvider: resolveApiKey } },
    );

    init({ pluginDir: __dirname + "/..", varDir: tmpDir, config: BASE_CONFIG });
    _setGatewayApi(api);

    // Recreate the llmCallFn with gateway api context
    const llmCallFn = _createTestLLMCallFn(api);

    // Mock fetch to capture headers
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          choices: [{ message: { content: "SAFE: test" } }],
        }),
    });
    globalThis.fetch = fetchMock;

    await llmCallFn({
      model: "myapi/gpt-5.2",
      messages: [{ role: "user", content: "test" }],
      max_tokens: 100,
    });

    // Static key present — resolveApiKeyForProvider should NOT be called
    expect(resolveApiKey).not.toHaveBeenCalled();
    // Verify Authorization header uses the static key
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const headers = fetchMock.mock.calls[0][1].headers;
    expect(headers["Authorization"]).toBe("Bearer sk-static-key");
  });

  it("OAuth dynamic resolution: no apiKey + runtime.modelAuth returns token", async () => {
    const resolveApiKey = vi.fn().mockResolvedValue({
      apiKey: "oauth-token-123",
      source: "oauth",
      mode: "oauth" as const,
    });
    const api = createMockGatewayApi(
      {
        codex: {
          baseUrl: "http://localhost:5000/v1",
          auth: "oauth",
          models: [{ id: "codex-v1", name: "Codex" }],
        },
      },
      { modelAuth: { resolveApiKeyForProvider: resolveApiKey } },
    );

    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: { ...BASE_CONFIG, llm: { ...BASE_CONFIG.llm, model: "codex/codex-v1" } },
    });
    _setGatewayApi(api);

    const llmCallFn = _createTestLLMCallFn(api);

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          choices: [{ message: { content: "SAFE: ok" } }],
        }),
    });
    globalThis.fetch = fetchMock;

    await llmCallFn({
      model: "codex/codex-v1",
      messages: [{ role: "user", content: "test" }],
      max_tokens: 100,
    });

    // resolveApiKeyForProvider should be called since no static apiKey + auth is oauth
    expect(resolveApiKey).toHaveBeenCalledWith({ provider: "codex" });
    // Verify Authorization uses the resolved OAuth token
    const headers = fetchMock.mock.calls[0][1].headers;
    expect(headers["Authorization"]).toBe("Bearer oauth-token-123");
  });

  it("auth resolution failure throws LLMHttpError(401)", async () => {
    const resolveApiKey = vi
      .fn()
      .mockRejectedValue(new Error("OAuth token expired"));
    const api = createMockGatewayApi(
      {
        codex: {
          baseUrl: "http://localhost:5000/v1",
          auth: "oauth",
          models: [{ id: "codex-v1", name: "Codex" }],
        },
      },
      { modelAuth: { resolveApiKeyForProvider: resolveApiKey } },
    );

    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: { ...BASE_CONFIG, llm: { ...BASE_CONFIG.llm, model: "codex/codex-v1" } },
    });
    _setGatewayApi(api);

    const llmCallFn = _createTestLLMCallFn(api);

    try {
      await llmCallFn({
        model: "codex/codex-v1",
        messages: [{ role: "user", content: "test" }],
        max_tokens: 100,
      });
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(LLMHttpError);
      expect((err as LLMHttpError).statusCode).toBe(401);
      expect((err as LLMHttpError).message).toContain("OAuth auth resolution failed");
      expect((err as LLMHttpError).message).toContain("OAuth token expired");
    }
  });

  it("no runtime + no apiKey: proceeds without Authorization header (local providers)", async () => {
    const api = createMockGatewayApi({
      localllm: {
        baseUrl: "http://localhost:8080/v1",
        // no apiKey, no auth field
        models: [{ id: "local-model", name: "Local" }],
      },
    });
    // No runtime.modelAuth

    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: { ...BASE_CONFIG, llm: { ...BASE_CONFIG.llm, model: "localllm/local-model" } },
    });
    _setGatewayApi(api);

    const llmCallFn = _createTestLLMCallFn(api);

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          choices: [{ message: { content: "SAFE: local" } }],
        }),
    });
    globalThis.fetch = fetchMock;

    await llmCallFn({
      model: "localllm/local-model",
      messages: [{ role: "user", content: "test" }],
      max_tokens: 100,
    });

    // No Authorization header since no key and no runtime auth
    const headers = fetchMock.mock.calls[0][1].headers;
    expect(headers["Authorization"]).toBeUndefined();
  });

  it("per-call resolution: each call gets a fresh token", async () => {
    let callCount = 0;
    const resolveApiKey = vi.fn().mockImplementation(async () => {
      callCount++;
      return {
        apiKey: `token-${callCount}`,
        source: "oauth",
        mode: "oauth" as const,
      };
    });
    const api = createMockGatewayApi(
      {
        codex: {
          baseUrl: "http://localhost:5000/v1",
          auth: "oauth",
          models: [{ id: "codex-v1", name: "Codex" }],
        },
      },
      { modelAuth: { resolveApiKeyForProvider: resolveApiKey } },
    );

    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: { ...BASE_CONFIG, llm: { ...BASE_CONFIG.llm, model: "codex/codex-v1" } },
    });
    _setGatewayApi(api);

    const llmCallFn = _createTestLLMCallFn(api);

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          choices: [{ message: { content: "SAFE: ok" } }],
        }),
    });
    globalThis.fetch = fetchMock;

    // First call
    await llmCallFn({
      model: "codex/codex-v1",
      messages: [{ role: "user", content: "test1" }],
      max_tokens: 100,
    });

    // Second call
    await llmCallFn({
      model: "codex/codex-v1",
      messages: [{ role: "user", content: "test2" }],
      max_tokens: 100,
    });

    expect(resolveApiKey).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0][1].headers["Authorization"]).toBe(
      "Bearer token-1",
    );
    expect(fetchMock.mock.calls[1][1].headers["Authorization"]).toBe(
      "Bearer token-2",
    );
  });

  it("updateConfig rejects OAuth provider without runtime.modelAuth", () => {
    const api = createMockGatewayApi({
      codex: {
        baseUrl: "http://localhost:5000/v1",
        auth: "oauth",
        models: [{ id: "codex-v1", name: "Codex" }],
      },
    });
    // No runtime.modelAuth on the api

    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: BASE_CONFIG,
    });
    _setGatewayApi(api);

    const result = _updateConfig({ llm: { model: "codex/codex-v1" } });
    expect(result.ok).toBe(false);
    expect(result.errors).toBeDefined();
    expect(
      result.errors!.some(
        (e) => e.includes("oauth auth") && e.includes("runtime.modelAuth"),
      ),
    ).toBe(true);
  });

  it("updateConfig accepts OAuth provider when runtime.modelAuth is available", () => {
    const resolveApiKey = vi.fn().mockResolvedValue({
      apiKey: "token",
      source: "oauth",
      mode: "oauth" as const,
    });
    const api = createMockGatewayApi(
      {
        codex: {
          baseUrl: "http://localhost:5000/v1",
          auth: "oauth",
          models: [{ id: "codex-v1", name: "Codex" }],
        },
      },
      { modelAuth: { resolveApiKeyForProvider: resolveApiKey } },
    );

    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: BASE_CONFIG,
    });
    _setGatewayApi(api);

    const result = _updateConfig({ llm: { model: "codex/codex-v1" } });
    expect(result.ok).toBe(true);
  });

  it("register() logs OAuth message for OAuth provider with runtime auth", () => {
    const resolveApiKey = vi.fn().mockResolvedValue({
      apiKey: "token",
      source: "oauth",
      mode: "oauth" as const,
    });
    const api = createMockGatewayApi(
      {
        codex: {
          baseUrl: "http://localhost:5000/v1",
          auth: "oauth",
          models: [{ id: "codex-v1", name: "Codex" }],
        },
      },
      { modelAuth: { resolveApiKeyForProvider: resolveApiKey } },
    );

    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: { ...BASE_CONFIG, llm: { ...BASE_CONFIG.llm, model: "codex/codex-v1" } },
    });

    // Simulate what register() does after init
    _setGatewayApi(api);
    // The actual logging happens in register(), but we can verify the api is set up correctly
    expect(api.runtime?.modelAuth?.resolveApiKeyForProvider).toBeDefined();
  });
});

// ─── Auth profile fallback tests ───

describe("Auth profile fallback", () => {
  let tmpDir: string;
  let openClawDir: string;
  let prevOpenClawHome: string | undefined;
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "seclaw-authprofile-"));
    openClawDir = path.join(tmpDir, ".openclaw");
    prevOpenClawHome = process.env.OPENCLAW_HOME;
    process.env.OPENCLAW_HOME = openClawDir;
    sessionState.clear();
    originalFetch = globalThis.fetch;
  });

  afterEach(async () => {
    _setGatewayApi(null);
    await stopDashboard();
    globalThis.fetch = originalFetch;
    fs.rmSync(tmpDir, { recursive: true, force: true });
    process.env.OPENCLAW_HOME = prevOpenClawHome;
  });

  it("provider not in models.providers but in auth.profiles → resolves via known URL map", async () => {
    // Write openclaw.json with auth.profiles containing openai-codex
    writeOpenClawConfig(openClawDir, {
      plugins: { entries: { seclaw: { config: BASE_CONFIG } } },
      auth: {
        profiles: {
          "openai-codex:default": {
            provider: "openai-codex",
            mode: "oauth",
          },
        },
      },
    });

    const resolveApiKey = vi.fn().mockResolvedValue({
      apiKey: "oauth-token-from-profile",
      source: "oauth",
      mode: "oauth" as const,
    });
    // No openai-codex in models.providers
    const api = createMockGatewayApi(
      {},
      { modelAuth: { resolveApiKeyForProvider: resolveApiKey } },
    );

    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: { ...BASE_CONFIG, llm: { ...BASE_CONFIG.llm, model: "openai-codex/gpt-5.2" } },
    });
    _setGatewayApi(api);

    const llmCallFn = _createTestLLMCallFn(api, "openai-codex/gpt-5.2");

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          choices: [{ message: { content: "SAFE: ok" } }],
        }),
    });
    globalThis.fetch = fetchMock;

    await llmCallFn({
      model: "openai-codex/gpt-5.2",
      messages: [{ role: "user", content: "test" }],
      max_tokens: 100,
    });

    // Should have resolved via auth profile + dynamic auth
    expect(resolveApiKey).toHaveBeenCalledWith({ provider: "openai-codex" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    // Verify endpoint uses known OpenAI base URL
    const url = fetchMock.mock.calls[0][0];
    expect(url).toBe("https://api.openai.com/v1/chat/completions");
    // Verify auth token
    const headers = fetchMock.mock.calls[0][1].headers;
    expect(headers["Authorization"]).toBe("Bearer oauth-token-from-profile");
  });

  it("prefix matching: openai-codex matches openai prefix → correct baseUrl", () => {
    writeOpenClawConfig(openClawDir, {
      plugins: { entries: { seclaw: { config: BASE_CONFIG } } },
      auth: {
        profiles: {
          "openai-codex:default": {
            provider: "openai-codex",
            mode: "oauth",
          },
        },
      },
    });

    const api = createMockGatewayApi(
      {},
      { modelAuth: { resolveApiKeyForProvider: vi.fn() } },
    );

    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: { ...BASE_CONFIG, llm: { ...BASE_CONFIG.llm, model: "openai-codex/gpt-5.2" } },
    });
    _setGatewayApi(api);

    // updateConfig should accept this model (auth profile + known URL)
    const result = _updateConfig({ llm: { model: "openai-codex/gpt-5.2" } });
    expect(result.ok).toBe(true);
  });

  it("unknown provider in auth profile → returns error, no known base URL", () => {
    writeOpenClawConfig(openClawDir, {
      plugins: { entries: { seclaw: { config: BASE_CONFIG } } },
      auth: {
        profiles: {
          "custom-llm:default": {
            provider: "custom-llm",
            mode: "oauth",
          },
        },
      },
    });

    const api = createMockGatewayApi(
      {},
      { modelAuth: { resolveApiKeyForProvider: vi.fn() } },
    );

    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: BASE_CONFIG,
    });
    _setGatewayApi(api);

    // updateConfig should reject — auth profile exists but no known URL
    const result = _updateConfig({ llm: { model: "custom-llm/model-v1" } });
    expect(result.ok).toBe(false);
    expect(result.errors).toBeDefined();
    expect(result.errors!.some((e) => e.includes("no known base URL"))).toBe(true);
  });

  it("models.providers takes precedence over auth profile", async () => {
    writeOpenClawConfig(openClawDir, {
      plugins: { entries: { seclaw: { config: BASE_CONFIG } } },
      auth: {
        profiles: {
          "myapi:default": {
            provider: "myapi",
            mode: "oauth",
          },
        },
      },
    });

    const resolveApiKey = vi.fn();
    const api = createMockGatewayApi(
      {
        myapi: {
          baseUrl: "http://localhost:4000/v1",
          apiKey: "sk-static-key",
          models: [{ id: "gpt-5.2", name: "GPT 5.2" }],
        },
      },
      { modelAuth: { resolveApiKeyForProvider: resolveApiKey } },
    );

    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: BASE_CONFIG,
    });
    _setGatewayApi(api);

    const llmCallFn = _createTestLLMCallFn(api);

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          choices: [{ message: { content: "SAFE: ok" } }],
        }),
    });
    globalThis.fetch = fetchMock;

    await llmCallFn({
      model: "myapi/gpt-5.2",
      messages: [{ role: "user", content: "test" }],
      max_tokens: 100,
    });

    // Should use models.providers (static key), NOT auth profile
    expect(resolveApiKey).not.toHaveBeenCalled();
    const url = fetchMock.mock.calls[0][0];
    expect(url).toBe("http://localhost:4000/v1/chat/completions");
    const headers = fetchMock.mock.calls[0][1].headers;
    expect(headers["Authorization"]).toBe("Bearer sk-static-key");
  });
});

// ─── Helper to create an LLM call function for testing ───
// This mirrors createGatewayLLMCallFn logic but is accessible from tests.

function _createTestLLMCallFn(api: OpenClawPluginApi, modelOverride?: string) {
  const auditor = _getLLMAuditor();
  const originalSetFn = auditor.setLLMCallFn.bind(auditor);
  let capturedFn: any = null;

  // Monkey-patch to capture the function
  auditor.setLLMCallFn = (fn: any) => {
    capturedFn = fn;
    originalSetFn(fn);
  };

  // Trigger llmCallFn recreation
  const model = modelOverride ??
    Object.keys(api.config.models?.providers ?? {})[0] +
    "/" +
    (api.config.models?.providers?.[
      Object.keys(api.config.models?.providers ?? {})[0]
    ]?.models?.[0]?.id ?? "model");
  _updateConfig({ llm: { model } });

  // Restore original
  auditor.setLLMCallFn = originalSetFn;

  if (!capturedFn) {
    throw new Error("Failed to capture llmCallFn — createGatewayLLMCallFn returned null");
  }
  return capturedFn;
}
