/**
 * Claude Agent SDK backend for DocBrief.
 *
 * Uses the real `@anthropic-ai/claude-agent-sdk` -- the agentic runtime, not
 * the raw `@anthropic-ai/sdk` HTTP client. AgentBox exists to secure
 * *agentic* applications, so a starter built on a bare client would not
 * exercise what AgentBox protects.
 *
 * Unlike the Python package, this one is a plain npm dependency with no
 * platform-specific wheel problem, so it works on the Alpine base image.
 *
 * SecureProxy: configureSecureProxy binds ANTHROPIC_API_KEY and
 * ANTHROPIC_BASE_URL in process.env before the SDK starts, so every model
 * call is brokered by SecureProxy. Direct provider fallback is refused.
 */

import { query } from "@anthropic-ai/claude-agent-sdk";
import { buildUserText, instructionsWithSkills, parseResult } from "./shared.js";
import { configureSecureProxy } from "./secureproxy.js";

/**
 * Pull assistant text out of whatever the SDK yields.
 *
 * The SDK streams several message shapes (assistant turns, tool activity, a
 * final result). Reading whatever carries text keeps this starter off SDK
 * internals that move between versions.
 */
function textOf(message) {
  if (typeof message?.result === "string" && message.result.trim()) {
    return message.result;
  }
  const content = message?.content;
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((block) => (typeof block?.text === "string" ? block.text : ""))
      .filter(Boolean)
      .join("\n");
  }
  return "";
}

export async function run(document, question) {
  configureSecureProxy("anthropic");

  // The date is fixed for the life of the request, so it goes in the system
  // prompt rather than costing a tool round trip on every call.
  const today = new Date().toISOString().slice(0, 10);
  const instructions =
    `${await instructionsWithSkills()}\n\n` +
    `Today's date in ISO 8601 format is ${today}.`;

  const chunks = [];
  for await (const message of query({
    prompt: buildUserText(document, question),
    options: {
      systemPrompt: instructions,
      maxTurns: 6,
      model: process.env.DOCBRIEF_CLAUDE_MODEL ?? "claude-sonnet-4-5",
    },
  })) {
    const text = textOf(message);
    if (text) chunks.push(text);
  }

  if (chunks.length === 0) {
    throw new Error(
      "claude-agent-sdk returned no assistant text; the bundled CLI may be unavailable in this image",
    );
  }
  return parseResult(chunks.length === 1 ? chunks[0] : chunks.join("\n"));
}


/**
 * Assistant content blocks, wherever this SDK version puts them.
 *
 * Checked in both places on purpose: the SDK nests assistant content under
 * `.message.content` on some message shapes and exposes `.content` directly on
 * others, and a stream that reads only one of them is silently empty against
 * the other.
 */
function contentBlocks(message) {
  if (Array.isArray(message?.content)) return message.content;
  if (Array.isArray(message?.message?.content)) return message.message.content;
  return [];
}

/**
 * Yield the agent's turns as they happen, for POST /process/stream.
 *
 * Deliberately NOT built on `textOf`: that helper returns the final result
 * message's `result`, which is the complete answer again, so a stream built on
 * it would replay every token a second time at the end. Here the final result
 * is emitted once as its own `result` event and the incremental text comes
 * only from assistant content blocks.
 */
export async function* runStream(document, question) {
  configureSecureProxy("anthropic");

  const today = new Date().toISOString().slice(0, 10);
  const instructions =
    `${await instructionsWithSkills()}\n\n` +
    `Today's date in ISO 8601 format is ${today}.`;

  for await (const message of query({
    prompt: buildUserText(document, question),
    options: {
      systemPrompt: instructions,
      maxTurns: 6,
      model: process.env.DOCBRIEF_CLAUDE_MODEL ?? "claude-sonnet-4-5",
    },
  })) {
    if (typeof message?.result === "string" && message.result.trim()) {
      yield { type: "result", text: message.result };
      continue;
    }
    for (const block of contentBlocks(message)) {
      if (block?.type === "tool_use") {
        yield {
          type: "tool",
          name: String(block.name ?? "tool"),
          input: block.input ?? {},
        };
        continue;
      }
      if (typeof block?.text === "string" && block.text.trim()) {
        yield { type: "token", text: block.text };
      }
    }
  }
}
