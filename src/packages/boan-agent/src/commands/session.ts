import { randomUUID } from "node:crypto";
import type {
  PluginCommandContext,
  PluginCommandResult,
  OpenClawPluginApi,
  SessionInfo,
} from "../types.js";

const CREDENTIAL_ENV_KEYS = [
  "BOAN_SESSION_ID",
  "BOAN_WORKSPACE",
  "BOAN_TOKEN",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "GH_TOKEN",
  "GITHUB_TOKEN",
  "NPM_TOKEN",
];

let sessionStartedAt: string | null = null;

function buildSessionInfo(): SessionInfo {
  return {
    sessionId: process.env.BOAN_SESSION_ID ?? "unknown",
    status: process.env.BOAN_SESSION_ID ? "active" : "unknown",
    workspace: process.env.BOAN_WORKSPACE ?? "(not mounted)",
    proxy: process.env.HTTP_PROXY ?? "(not set)",
    startedAt: sessionStartedAt ?? "(not started)",
    gitBranch: `boanclaw/${process.env.BOAN_SESSION_ID ?? "default"}`,
    mountedPaths: process.env.BOAN_WORKSPACE
      ? [process.env.BOAN_WORKSPACE]
      : [],
  };
}

function startSession(api: OpenClawPluginApi): SessionInfo {
  const sessionId = randomUUID();
  process.env.BOAN_SESSION_ID = sessionId;
  sessionStartedAt = new Date().toISOString();
  api.logger.info(`session started: ${sessionId}`);
  return buildSessionInfo();
}

function stopSession(api: OpenClawPluginApi): string {
  const sessionId = process.env.BOAN_SESSION_ID ?? "unknown";
  api.logger.info(`session stopping: ${sessionId}`);

  for (const key of CREDENTIAL_ENV_KEYS) {
    if (process.env[key]) {
      delete process.env[key];
    }
  }

  sessionStartedAt = null;
  api.logger.info("session stopped — credentials cleared");
  return sessionId;
}

function formatSessionInfo(info: SessionInfo): string {
  return [
    "BoanClaw Session",
    `  Session ID : ${info.sessionId}`,
    `  Status     : ${info.status}`,
    `  Workspace  : ${info.workspace}`,
    `  Proxy      : ${info.proxy}`,
    `  Started At : ${info.startedAt}`,
    `  Git Branch : ${info.gitBranch}`,
    `  Mounted    : ${info.mountedPaths.length > 0 ? info.mountedPaths.join(", ") : "(none)"}`,
  ].join("\n");
}

export async function registerSessionCommand(
  ctx: PluginCommandContext,
  api: OpenClawPluginApi
): Promise<PluginCommandResult> {
  const args = (ctx.args ?? "").split(" ").filter(Boolean);
  const subcommand = args[1] ?? "status";

  switch (subcommand) {
    case "start": {
      const info = startSession(api);
      return { text: `Session started.\n${formatSessionInfo(info)}` };
    }
    case "stop": {
      const stoppedId = stopSession(api);
      return {
        text: `Session ${stoppedId} stopped.\nAll credentials cleared from environment.`,
      };
    }
    case "status":
    default: {
      const info = buildSessionInfo();
      return { text: formatSessionInfo(info) };
    }
  }
}

export async function sessionTool(
  input: Record<string, unknown>
): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
  const action = (input.action as string) ?? "status";

  switch (action) {
    case "start": {
      const sessionId = randomUUID();
      process.env.BOAN_SESSION_ID = sessionId;
      sessionStartedAt = new Date().toISOString();
      const info = buildSessionInfo();
      return {
        content: [{ type: "text", text: JSON.stringify(info, null, 2) }],
      };
    }
    case "stop": {
      const stoppedId = process.env.BOAN_SESSION_ID ?? "unknown";
      for (const key of CREDENTIAL_ENV_KEYS) {
        if (process.env[key]) {
          delete process.env[key];
        }
      }
      sessionStartedAt = null;
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ stopped: stoppedId, credentialsCleared: true }),
          },
        ],
      };
    }
    case "status":
    default: {
      const info = buildSessionInfo();
      return {
        content: [{ type: "text", text: JSON.stringify(info, null, 2) }],
      };
    }
  }
}
