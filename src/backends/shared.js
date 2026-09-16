import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const BASE_INSTRUCTIONS =
  "You are DocBrief. Return only JSON with summary, action_items, and answer. " +
  "action_items must be an array of concise strings, never objects. " +
  "Use only the supplied document when answering a question.";

function normalizeActionItem(item) {
  if (typeof item === "string") return item.trim();
  if (item == null) return "";
  if (typeof item !== "object") return String(item);

  const owner = item.owner ?? item.assignee;
  const action = item.action ?? item.task ?? item.description ?? item.text ?? item.item;
  const due = item.due ?? item.deadline;
  if (action != null && typeof action !== "object") {
    return `${owner ? `${owner}: ` : ""}${action}${due ? ` (due ${due})` : ""}`;
  }
  return JSON.stringify(item);
}

async function collectSkillFiles(root) {
  const result = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) result.push(...(await collectSkillFiles(full)));
    if (entry.isFile() && entry.name === "SKILL.md") result.push(full);
  }
  return result;
}

export async function instructionsWithSkills() {
  const root = (process.env.AGENTBOX_SKILLS_ROOT ?? "").trim();
  if (!root) return BASE_INSTRUCTIONS;
  try {
    const files = await collectSkillFiles(root);
    const skills = await Promise.all(files.sort().map((file) => readFile(file, "utf8")));
    return skills.length
      ? `${BASE_INSTRUCTIONS}\n\nApproved app-scoped skills:\n${skills.join("\n\n")}`
      : BASE_INSTRUCTIONS;
  } catch {
    return BASE_INSTRUCTIONS;
  }
}

export function buildUserText(document, question) {
  return `Document:\n${document}${question ? `\n\nQuestion: ${question}` : ""}`;
}

export function parseResult(text) {
  const candidate = text.trim().replace(/^```(?:json)?\s*|\s*```$/g, "");
  try {
    const data = JSON.parse(candidate);
    return {
      summary: String(data.summary ?? ""),
      action_items: Array.isArray(data.action_items)
        ? data.action_items.map(normalizeActionItem).filter(Boolean)
        : [],
      answer: data.answer ?? null,
    };
  } catch {
    return { summary: text.trim(), action_items: [], answer: null };
  }
}
