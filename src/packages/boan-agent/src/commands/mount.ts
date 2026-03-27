import { existsSync, realpathSync } from "node:fs";
import type {
  PluginCommandContext,
  PluginCommandResult,
  OpenClawPluginApi,
  MountRequest,
  MountResponse,
} from "../types.js";

const DEFAULT_ALLOWED_DIRS = [
  "/workspace",
  "/home",
  "/tmp/boan",
];

function getAllowedDirs(): string[] {
  const envDirs = process.env.BOAN_ALLOWED_DIRS;
  if (envDirs) {
    return envDirs.split(":").filter(Boolean);
  }
  return DEFAULT_ALLOWED_DIRS;
}

function isWithinAllowedDirs(targetPath: string): boolean {
  const allowedDirs = getAllowedDirs();
  let resolved: string;
  try {
    resolved = realpathSync(targetPath);
  } catch {
    resolved = targetPath;
  }
  return allowedDirs.some((dir) => resolved.startsWith(dir));
}

async function requestProxyMount(req: MountRequest): Promise<MountResponse> {
  const proxyUrl = process.env.BOAN_PROXY_ADMIN ?? "http://boan-proxy:18080";
  const response = await fetch(`${proxyUrl}/api/mount`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!response.ok) {
    return {
      success: false,
      mountPoint: "",
      sessionId: req.sessionId,
      error: `Proxy returned ${response.status}: ${await response.text()}`,
    };
  }
  return (await response.json()) as MountResponse;
}

export async function registerMountCommand(
  ctx: PluginCommandContext,
  args: string[],
  api: OpenClawPluginApi
): Promise<PluginCommandResult> {
  const path = args[0];
  if (!path) {
    return {
      text: "Usage: /boanclaw mount <path>\nExample: /boanclaw mount /workspace/project",
    };
  }

  if (!existsSync(path)) {
    return { text: `Path not found: ${path}` };
  }

  if (!isWithinAllowedDirs(path)) {
    api.logger.warn(`mount blocked — path outside allowed dirs: ${path}`);
    return {
      text: `Access denied: ${path} is not within allowed directories.\nAllowed: ${getAllowedDirs().join(", ")}`,
    };
  }

  const sessionId = process.env.BOAN_SESSION_ID ?? "default";

  try {
    const result = await requestProxyMount({
      path,
      sessionId,
      readOnly: false,
    });

    if (!result.success) {
      api.logger.error(`mount failed: ${result.error}`);
      return { text: `Mount failed: ${result.error}` };
    }

    process.env.BOAN_WORKSPACE = path;
    api.logger.info(`workspace mounted: ${path} (session: ${sessionId})`);

    return {
      text: [
        `Workspace mounted: ${path}`,
        `Mount point: ${result.mountPoint}`,
        `Session: ${sessionId}`,
      ].join("\n"),
    };
  } catch (e) {
    api.logger.warn(`proxy mount request failed, falling back to local: ${e}`);
    process.env.BOAN_WORKSPACE = path;
    return {
      text: [
        `Workspace mounted locally: ${path}`,
        `(boan-proxy unreachable — local mount only)`,
      ].join("\n"),
    };
  }
}

export async function mountTool(
  input: Record<string, unknown>
): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
  const path = input.path as string;
  if (!path) {
    return {
      content: [{ type: "text", text: "Missing required parameter: path" }],
      isError: true,
    };
  }

  if (!existsSync(path)) {
    return {
      content: [{ type: "text", text: `Path not found: ${path}` }],
      isError: true,
    };
  }

  if (!isWithinAllowedDirs(path)) {
    return {
      content: [
        {
          type: "text",
          text: `Access denied: ${path} is not within allowed directories.`,
        },
      ],
      isError: true,
    };
  }

  const sessionId = process.env.BOAN_SESSION_ID ?? "default";
  const readOnly = (input.readOnly as boolean) ?? false;

  try {
    const result = await requestProxyMount({ path, sessionId, readOnly });
    if (!result.success) {
      return {
        content: [{ type: "text", text: `Mount failed: ${result.error}` }],
        isError: true,
      };
    }
    process.env.BOAN_WORKSPACE = path;
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ mounted: path, mountPoint: result.mountPoint, sessionId }),
        },
      ],
    };
  } catch {
    process.env.BOAN_WORKSPACE = path;
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ mounted: path, local: true, sessionId }),
        },
      ],
    };
  }
}
