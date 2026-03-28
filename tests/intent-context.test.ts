import { describe, it, expect, beforeEach } from "vitest";
import { parseUserMessage, onUserMessage, getIntentContext } from "../src/intent-context.js";
import { sessionState } from "../src/session-state.js";

describe("parseUserMessage", () => {
  it("returns plain text unchanged", () => {
    const result = parseUserMessage("Hello, build me a web app");
    expect(result.userMessage).toBe("Hello, build me a web app");
    expect(result.senderLabel).toBeUndefined();
  });

  it("strips Conversation info block", () => {
    const raw = `Conversation info (untrusted metadata):
\`\`\`json
{"chatId": 123, "chatType": "private"}
\`\`\`
Build me a web app`;

    const result = parseUserMessage(raw);
    expect(result.userMessage).toBe("Build me a web app");
    expect(result.senderLabel).toBeUndefined();
  });

  it("strips Sender block and extracts label", () => {
    const raw = `Sender (untrusted metadata):
\`\`\`json
{"userId": 42, "label": "Alice (admin)", "username": "alice"}
\`\`\`
Deploy the service`;

    const result = parseUserMessage(raw);
    expect(result.userMessage).toBe("Deploy the service");
    expect(result.senderLabel).toBe("Alice (admin)");
  });

  it("strips both blocks and extracts label", () => {
    const raw = `Conversation info (untrusted metadata):
\`\`\`json
{"chatId": 123, "chatType": "group"}
\`\`\`
Sender (untrusted metadata):
\`\`\`json
{"userId": 42, "label": "Bob", "username": "bob"}
\`\`\`
Run npm test`;

    const result = parseUserMessage(raw);
    expect(result.userMessage).toBe("Run npm test");
    expect(result.senderLabel).toBe("Bob");
  });

  it("handles Conversation block without Sender block", () => {
    const raw = `Conversation info (untrusted metadata):
\`\`\`json
{"chatId": 999}
\`\`\`
Just the message`;

    const result = parseUserMessage(raw);
    expect(result.userMessage).toBe("Just the message");
    expect(result.senderLabel).toBeUndefined();
  });

  it("handles malformed JSON in Sender block gracefully", () => {
    const raw = `Sender (untrusted metadata):
\`\`\`json
{not valid json}
\`\`\`
Still works`;

    const result = parseUserMessage(raw);
    expect(result.userMessage).toBe("Still works");
    expect(result.senderLabel).toBeUndefined();
  });

  it("handles Sender block without label field", () => {
    const raw = `Sender (untrusted metadata):
\`\`\`json
{"userId": 42, "username": "alice"}
\`\`\`
No label here`;

    const result = parseUserMessage(raw);
    expect(result.userMessage).toBe("No label here");
    expect(result.senderLabel).toBeUndefined();
  });

  it("returns original trimmed text if stripping leaves empty string", () => {
    const raw = `Conversation info (untrusted metadata):
\`\`\`json
{"chatId": 123}
\`\`\`
`;

    const result = parseUserMessage(raw);
    // After stripping, only whitespace remains, so falls back to raw.trim()
    expect(result.userMessage).toBeTruthy();
  });
});

describe("onUserMessage integration", () => {
  beforeEach(() => {
    sessionState.clear();
  });

  it("strips metadata and sets userGoal and senderLabel", () => {
    const raw = `Conversation info (untrusted metadata):
\`\`\`json
{"chatId": 123}
\`\`\`
Sender (untrusted metadata):
\`\`\`json
{"userId": 1, "label": "TestUser"}
\`\`\`
Do something useful`;

    onUserMessage("sess-1", raw);
    const ctx = getIntentContext("sess-1");
    expect(ctx.userGoal).toBe("Do something useful");
    expect(ctx.senderLabel).toBe("TestUser");
    expect(ctx.turnNumber).toBe(1);
  });

  it("works with plain messages (no metadata)", () => {
    onUserMessage("sess-2", "Simple instruction");
    const ctx = getIntentContext("sess-2");
    expect(ctx.userGoal).toBe("Simple instruction");
    expect(ctx.senderLabel).toBeUndefined();
  });
});
