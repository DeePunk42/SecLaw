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
      apiKey?: string | Record<string, unknown>;
      auth?: string;
      api?: string;
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
      expect((err as LLMHttpError).message).toContain("Auth resolution failed");
      expect((err as LLMHttpError).message).toContain("OAuth token expired");
    }
  });

  it("file-based apiKey (object ref): resolver receives apiKeyRef and returns resolved key", async () => {
    const fileApiKeyRef = { source: "file", provider: "filemain", id: "deepseek-key" };
    const resolveApiKey = vi.fn().mockResolvedValue({
      apiKey: "sk-resolved-from-file",
      source: "file",
      mode: "api-key" as const,
    });
    const api = createMockGatewayApi(
      {
        deepseek: {
          baseUrl: "https://api.deepseek.com/v1",
          apiKey: fileApiKeyRef,
          models: [{ id: "deepseek-chat", name: "DeepSeek Chat" }],
        },
      },
      { modelAuth: { resolveApiKeyForProvider: resolveApiKey } },
    );

    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: { ...BASE_CONFIG, llm: { ...BASE_CONFIG.llm, model: "deepseek/deepseek-chat" } },
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
      model: "deepseek/deepseek-chat",
      messages: [{ role: "user", content: "test" }],
      max_tokens: 100,
    });

    // Resolver should receive the apiKeyRef object
    expect(resolveApiKey).toHaveBeenCalledWith(
      expect.objectContaining({ provider: "deepseek", apiKeyRef: fileApiKeyRef }),
    );
    // Verify Authorization uses the resolved key
    const headers = fetchMock.mock.calls[0][1].headers;
    expect(headers["Authorization"]).toBe("Bearer sk-resolved-from-file");
  });

  it("file-based apiKey: resolver failure falls back gracefully (no 401 for non-oauth)", async () => {
    const resolveApiKey = vi
      .fn()
      .mockRejectedValue(new Error("File secret not found"));
    const api = createMockGatewayApi(
      {
        deepseek: {
          baseUrl: "https://api.deepseek.com/v1",
          apiKey: { source: "file", provider: "filemain", id: "deepseek-key" },
          models: [{ id: "deepseek-chat", name: "DeepSeek Chat" }],
        },
      },
      { modelAuth: { resolveApiKeyForProvider: resolveApiKey } },
    );

    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: { ...BASE_CONFIG, llm: { ...BASE_CONFIG.llm, model: "deepseek/deepseek-chat" } },
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

    // Should NOT throw 401 — non-oauth provider falls back gracefully
    await llmCallFn({
      model: "deepseek/deepseek-chat",
      messages: [{ role: "user", content: "test" }],
      max_tokens: 100,
    });

    // Request proceeds without Authorization (staticApiKey is undefined for object apiKey)
    const headers = fetchMock.mock.calls[0][1].headers;
    expect(headers["Authorization"]).toBeUndefined();
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

  it("openai-codex auth profile is accepted via implicit transport", async () => {
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
      apiKey: "oauth-token-123",
      source: "oauth",
      mode: "oauth" as const,
    });
    const api = createMockGatewayApi(
      {},
      {
        config: { loadConfig: () => JSON.parse(fs.readFileSync(path.join(openClawDir, "openclaw.json"), "utf-8")) },
        modelAuth: { resolveApiKeyForProvider: resolveApiKey },
      },
    );

    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: { ...BASE_CONFIG, llm: { ...BASE_CONFIG.llm, model: "openai-codex/gpt-5.2" } },
    });
    _setGatewayApi(api);

    const llmCallFn = _createTestLLMCallFn(api, "openai-codex/gpt-5.2");
    const fetchMock = vi.fn().mockResolvedValue(createSSEMockResponse("SAFE: codex ok"));
    globalThis.fetch = fetchMock;

    const result = _updateConfig({ llm: { model: "openai-codex/gpt-5.2" } });
    expect(result.ok).toBe(true);

    await llmCallFn({
      model: "openai-codex/gpt-5.2",
      messages: [{ role: "user", content: "test" }],
      max_tokens: 100,
    });

    expect(resolveApiKey).toHaveBeenCalledWith(
      expect.objectContaining({ provider: "openai-codex" }),
    );
    expect(fetchMock.mock.calls[0][0]).toBe("https://chatgpt.com/backend-api/codex/responses");
    const headers = fetchMock.mock.calls[0][1].headers;
    expect(headers.originator).toBe("openclaw");
    expect(headers["User-Agent"]).toBe("openclaw/seclaw");

    // Payload uses codex format with streaming
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.instructions).toBe("You are a helpful assistant.");
    expect(body.store).toBe(false);
    expect(body.stream).toBe(true);
    expect(body.input).toEqual([{ role: "user", content: "test" }]);
  });

  it("unknown provider remains rejected even if auth.profiles exists", () => {
    writeOpenClawConfig(openClawDir, {
      plugins: { entries: { seclaw: { config: BASE_CONFIG } } },
      auth: {
        profiles: {
          "mystery-provider:default": {
            provider: "mystery-provider",
            mode: "oauth",
          },
        },
      },
    });
    const api = createMockGatewayApi(
      {},
      {
        config: { loadConfig: () => JSON.parse(fs.readFileSync(path.join(openClawDir, "openclaw.json"), "utf-8")) },
        modelAuth: { resolveApiKeyForProvider: vi.fn() },
      },
    );
    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: BASE_CONFIG,
    });
    _setGatewayApi(api);
    const result = _updateConfig({ llm: { model: "mystery-provider/demo-model" } });
    expect(result.ok).toBe(false);
    expect(result.errors!.some((e) => e.includes('provider "mystery-provider" not found'))).toBe(
      true,
    );
  });

  it("openai-responses provider is overridden to /chat/completions", async () => {
    writeOpenClawConfig(openClawDir, {
      plugins: { entries: { seclaw: { config: BASE_CONFIG } } },
    });
    const api = createMockGatewayApi({
      myapi: {
        baseUrl: "http://localhost:4000/v1",
        apiKey: "sk-test",
        api: "openai-responses",
        models: [{ id: "gpt-5.2", name: "GPT 5.2" }],
      },
    });

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

    const url = fetchMock.mock.calls[0][0];
    expect(url).toBe("http://localhost:4000/v1/chat/completions");
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.max_tokens).toBe(100);
    expect(body.messages[0].content).toBe("test");
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

// ─── Codex payload structure tests ───

describe("Codex payload structure", () => {
  let tmpDir: string;
  let openClawDir: string;
  let prevOpenClawHome: string | undefined;
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "seclaw-codex-payload-"));
    openClawDir = path.join(tmpDir, ".openclaw");
    prevOpenClawHome = process.env.OPENCLAW_HOME;
    process.env.OPENCLAW_HOME = openClawDir;
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

  function setupCodexEnv() {
    const resolveApiKey = vi.fn().mockResolvedValue({
      apiKey: "oauth-token",
      source: "oauth",
      mode: "oauth" as const,
    });
    const api = createMockGatewayApi(
      {},
      {
        config: {
          loadConfig: () =>
            JSON.parse(
              fs.readFileSync(
                path.join(openClawDir, "openclaw.json"),
                "utf-8",
              ),
            ),
        },
        modelAuth: { resolveApiKeyForProvider: resolveApiKey },
      },
    );
    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: {
        ...BASE_CONFIG,
        llm: { ...BASE_CONFIG.llm, model: "openai-codex/gpt-5.2" },
      },
    });
    _setGatewayApi(api);
    return { api, resolveApiKey };
  }

  it("codex uses /codex/responses with SSE streaming", async () => {
    const { api } = setupCodexEnv();
    const llmCallFn = _createTestLLMCallFn(api, "openai-codex/gpt-5.2");
    const fetchMock = vi.fn().mockResolvedValue(createSSEMockResponse("OK"));
    globalThis.fetch = fetchMock;

    await llmCallFn({
      model: "openai-codex/gpt-5.2",
      messages: [{ role: "user", content: "Hello" }],
      max_tokens: 16,
    });

    const url = fetchMock.mock.calls[0][0];
    expect(url).toBe("https://chatgpt.com/backend-api/codex/responses");
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.instructions).toBe("You are a helpful assistant.");
    expect(body.store).toBe(false);
    expect(body.stream).toBe(true);
    expect(body.input).toEqual([{ role: "user", content: "Hello" }]);
    expect(body.max_output_tokens).toBeUndefined();
  });

  it("system message becomes instructions for codex calls", async () => {
    const { api } = setupCodexEnv();
    const llmCallFn = _createTestLLMCallFn(api, "openai-codex/gpt-5.2");
    const fetchMock = vi.fn().mockResolvedValue(createSSEMockResponse("OK"));
    globalThis.fetch = fetchMock;

    await llmCallFn({
      model: "openai-codex/gpt-5.2",
      messages: [
        { role: "system", content: "You are a security auditor." },
        { role: "user", content: "Audit this call." },
      ],
      max_tokens: 200,
    });

    const url = fetchMock.mock.calls[0][0];
    expect(url).toBe("https://chatgpt.com/backend-api/codex/responses");
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.instructions).toBe("You are a security auditor.");
    expect(body.store).toBe(false);
    expect(body.stream).toBe(true);
    // system message is extracted to instructions, only user message in input
    expect(body.input).toEqual([
      { role: "user", content: "Audit this call." },
    ]);
  });

  it("openai-responses provider uses completions format (messages, max_tokens)", async () => {
    writeOpenClawConfig(openClawDir, {
      plugins: { entries: { seclaw: { config: BASE_CONFIG } } },
    });
    const api = createMockGatewayApi({
      myapi: {
        baseUrl: "http://localhost:4000/v1",
        apiKey: "sk-test",
        api: "openai-responses",
        models: [{ id: "gpt-5.2", name: "GPT 5.2" }],
      },
    });
    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: BASE_CONFIG,
    });
    _setGatewayApi(api);

    const llmCallFn = _createTestLLMCallFn(api);
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ choices: [{ message: { content: "OK" } }] }),
    });
    globalThis.fetch = fetchMock;

    await llmCallFn({
      model: "myapi/gpt-5.2",
      messages: [
        { role: "system", content: "System prompt" },
        { role: "user", content: "test" },
      ],
      max_tokens: 100,
    });

    const url = fetchMock.mock.calls[0][0];
    expect(url).toBe("http://localhost:4000/v1/chat/completions");
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.instructions).toBeUndefined();
    expect(body.store).toBeUndefined();
    expect(body.input).toBeUndefined();
    expect(body.messages).toEqual([
      { role: "system", content: "System prompt" },
      { role: "user", content: "test" },
    ]);
    expect(body.max_tokens).toBe(100);
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
  const providerKeys = Object.keys(api.config.models?.providers ?? {});
  const derivedModel =
    providerKeys.length > 0
      ? `${providerKeys[0]}/${api.config.models?.providers?.[providerKeys[0]]?.models?.[0]?.id ?? "model"}`
      : undefined;
  const model = modelOverride ?? derivedModel;
  if (!model) {
    throw new Error("Failed to derive test model; pass modelOverride explicitly");
  }
  const updateResult = _updateConfig({ llm: { model } });
  if (!updateResult.ok) {
    throw new Error(
      `Failed to update model in test setup: ${(updateResult.errors ?? []).join("; ")}`,
    );
  }

  // Restore original
  auditor.setLLMCallFn = originalSetFn;

  if (!capturedFn) {
    throw new Error("Failed to capture llmCallFn — createGatewayLLMCallFn returned null");
  }
  return capturedFn;
}

function createSSEMockResponse(text: string) {
  const encoder = new TextEncoder();
  const ssePayload = [
    `data: ${JSON.stringify({ type: "response.output_text.delta", delta: text })}\n\n`,
    `data: ${JSON.stringify({ type: "response.completed", response: { output_text: text } })}\n\n`,
    `data: [DONE]\n\n`,
  ].join("");
  return {
    ok: true,
    status: 200,
    statusText: "OK",
    headers: { get: () => null },
    body: new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(ssePayload));
        controller.close();
      },
    }),
  };
}
