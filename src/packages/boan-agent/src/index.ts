import type { OpenClawPluginApi, LLMUseRequest, LLMUseResponse } from "./types.js";
import { registerMountCommand, mountTool } from "./commands/mount.js";
import { registerSessionCommand, sessionTool } from "./commands/session.js";
import { registerAuditCommand, auditTool } from "./commands/audit.js";
import {
  computerScreenshotTool,
  computerClickTool,
  computerDoubleClickTool,
  computerRightClickTool,
  computerScrollTool,
  computerTypeTool,
  computerKeyTool,
  computerMoveTool,
  computerClickQueryTool,
} from "./commands/computer-use.js";
import { GitGuard } from "./git/guard.js";
import { safeFetch } from "./ssrf.js";

async function llmUseTool(
  input: Record<string, unknown>
): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
  const proxyUrl = process.env.BOAN_PROXY_ADMIN ?? "http://boan-proxy:18080";
  const sessionId = process.env.BOAN_SESSION_ID ?? "default";

  const request: LLMUseRequest = {
    model: (input.model as string) ?? "default",
    prompt: (input.prompt as string) ?? "",
    sessionId,
    maxTokens: input.maxTokens as number | undefined,
    temperature: input.temperature as number | undefined,
    allowedTools: input.allowedTools as string[] | undefined,
    sandboxed: true,
  };

  if (!request.prompt) {
    return {
      content: [{ type: "text", text: "Missing required parameter: prompt" }],
      isError: true,
    };
  }

  const allowedSuffixes = process.env.BOAN_ALLOWED_SUFFIXES
    ? process.env.BOAN_ALLOWED_SUFFIXES.split(",").map((s) => s.trim())
    : [".anthropic.com", ".openai.com", ".googleapis.com"];

  try {
    const response = await safeFetch(
      `${proxyUrl}/api/llm-use`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
        signal: AbortSignal.timeout(30000),
      },
      { allowedSuffixes }
    );

    if (!response.ok) {
      return {
        content: [
          {
            type: "text",
            text: `LLM use request rejected: ${response.status} ${await response.text()}`,
          },
        ],
        isError: true,
      };
    }

    const result = (await response.json()) as LLMUseResponse;
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  } catch (e) {
    return {
      content: [
        {
          type: "text",
          text: `LLM use request failed: ${e instanceof Error ? e.message : String(e)}`,
        },
      ],
      isError: true,
    };
  }
}

export default function register(api: OpenClawPluginApi): void {
  const proxyUrl = process.env.BOAN_PROXY_URL ?? "http://boan-proxy:18080";
  process.env.HTTP_PROXY = proxyUrl;
  process.env.HTTPS_PROXY = proxyUrl;
  // BOAN_PROXY_ADMIN points to the admin port (18081) for computer-use/session APIs.
  // Only set default if not already configured via environment.
  if (!process.env.BOAN_PROXY_ADMIN) {
    process.env.BOAN_PROXY_ADMIN = proxyUrl.replace(/:18080$/, ":18081");
  }

  const guard = new GitGuard(api.logger);
  guard.install();

  api.registerCommand({
    name: "boanclaw",
    description: "BoanClaw security controls",
    acceptsArgs: true,
    handler: async (ctx) => {
      const [sub, ...args] = (ctx.args ?? "").split(" ").filter(Boolean);
      switch (sub) {
        case "mount":
          return registerMountCommand(ctx, args, api);
        case "session":
          return registerSessionCommand(ctx, api);
        case "audit":
          return registerAuditCommand(ctx, api);
        default:
          return { text: "Usage: /boanclaw [mount|session|audit]" };
      }
    },
  });

  api.registerTool({
    name: "mount",
    description: "Mount a workspace path through boan-proxy security layer",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute path to mount" },
        readOnly: { type: "boolean", description: "Mount as read-only" },
      },
      required: ["path"],
    },
    handler: mountTool,
  });

  api.registerTool({
    name: "audit",
    description: "Run security audit via boan-proxy /status endpoint",
    inputSchema: {
      type: "object",
      properties: {},
    },
    handler: auditTool,
  });

  api.registerTool({
    name: "llm-use",
    description: "Route LLM usage request through boan-proxy for policy enforcement",
    inputSchema: {
      type: "object",
      properties: {
        prompt: { type: "string", description: "The prompt to send" },
        model: { type: "string", description: "Model identifier" },
        maxTokens: { type: "number", description: "Maximum tokens" },
        temperature: { type: "number", description: "Sampling temperature" },
        allowedTools: {
          type: "array",
          items: { type: "string" },
          description: "List of allowed tool names",
        },
      },
      required: ["prompt"],
    },
    handler: llmUseTool,
  });

  api.registerTool({
    name: "session",
    description: "Manage BoanClaw session (start/stop/status)",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["start", "stop", "status"],
          description: "Session action",
        },
      },
    },
    handler: sessionTool,
  });

  // ── Computer Use Tools ──────────────────────────────────────────────────
  api.registerTool({
    name: "computer_screenshot",
    description: "Take a screenshot of the user's GCP workstation remote desktop. Returns the current screen state as an image.",
    inputSchema: { type: "object", properties: {} },
    handler: computerScreenshotTool,
  });

  api.registerTool({
    name: "computer_click",
    description: "Click at (x, y) coordinates on the GCP workstation screen.",
    inputSchema: {
      type: "object",
      properties: {
        x: { type: "number", description: "X coordinate (pixels from left edge of desktop)" },
        y: { type: "number", description: "Y coordinate (pixels from top edge of desktop)" },
        button: { type: "string", enum: ["left", "right", "middle"], description: "Mouse button (default: left)" },
      },
      required: ["x", "y"],
    },
    handler: computerClickTool,
  });

  api.registerTool({
    name: "computer_double_click",
    description: "Double-click at (x, y) on the GCP workstation screen.",
    inputSchema: {
      type: "object",
      properties: {
        x: { type: "number", description: "X coordinate" },
        y: { type: "number", description: "Y coordinate" },
      },
      required: ["x", "y"],
    },
    handler: computerDoubleClickTool,
  });

  api.registerTool({
    name: "computer_right_click",
    description: "Right-click at (x, y) on the GCP workstation screen.",
    inputSchema: {
      type: "object",
      properties: {
        x: { type: "number", description: "X coordinate" },
        y: { type: "number", description: "Y coordinate" },
      },
      required: ["x", "y"],
    },
    handler: computerRightClickTool,
  });

  api.registerTool({
    name: "computer_scroll",
    description: "Scroll the mouse wheel at (x, y) on the GCP workstation screen.",
    inputSchema: {
      type: "object",
      properties: {
        x: { type: "number", description: "X coordinate" },
        y: { type: "number", description: "Y coordinate" },
        direction: { type: "string", enum: ["up", "down"], description: "Scroll direction (default: down)" },
        amount: { type: "number", description: "Number of scroll ticks (default: 3)" },
      },
      required: ["x", "y"],
    },
    handler: computerScrollTool,
  });

  api.registerTool({
    name: "computer_type",
    description: "Type text into the GCP workstation (sends keyboard input).",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string", description: "Text to type" },
      },
      required: ["text"],
    },
    handler: computerTypeTool,
  });

  api.registerTool({
    name: "computer_key",
    description: "Press a special key or keyboard shortcut on the GCP workstation. Examples: 'Return', 'Tab', 'Escape', 'Ctl-C', 'Ctl-V', 'F5', 'Delete'.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Key name (e.g. Return, Tab, Escape, Ctl-C, Ctl-V, F5, Delete, BackSpace)" },
      },
      required: ["name"],
    },
    handler: computerKeyTool,
  });

  api.registerTool({
    name: "computer_move",
    description: "Move the mouse cursor to (x, y) on the GCP workstation screen.",
    inputSchema: {
      type: "object",
      properties: {
        x: { type: "number", description: "X coordinate" },
        y: { type: "number", description: "Y coordinate" },
      },
      required: ["x", "y"],
    },
    handler: computerMoveTool,
  });

  api.registerTool({
    name: "computer_click_query",
    description: "Find a UI element by natural language description and click it. Uses OCR to locate the element on screen.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Natural language description of the element to click (e.g. 'test-text.txt file icon on desktop')" },
        double: { type: "boolean", description: "If true, double-click instead of single click" },
      },
      required: ["query"],
    },
    handler: computerClickQueryTool,
  });

  api.logger.info("+-------------------------------------------------+");
  api.logger.info("|  BoanClaw Agent v1.0.0 registered                |");
  api.logger.info(`|  Proxy : ${proxyUrl.padEnd(39)}|`);
  api.logger.info("|  Tools : mount, audit, llm-use, session          |");
  api.logger.info("|  Computer Use : screenshot, click, type, key...  |");
  api.logger.info("|  Git Guard : active                              |");
  api.logger.info("+-------------------------------------------------+");
}
