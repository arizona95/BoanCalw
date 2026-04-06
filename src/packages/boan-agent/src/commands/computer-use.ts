/**
 * Computer Use tools — control the GCP workstation via the browser-side
 * command queue. boan-proxy queues each command and the admin-console
 * frontend executes it directly inside the already-open Guacamole iframe,
 * so no new RDP session is opened and the user's screen stays connected.
 */

type ToolResult = { content: Array<{ type: string; text: string }>; isError?: boolean };

function proxyAdmin(): string {
  return process.env.BOAN_PROXY_ADMIN ?? "http://localhost:18081";
}

async function cuExecute(params: Record<string, unknown>): Promise<ToolResult> {
  const url = `${proxyAdmin()}/api/computer-use/execute`;
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(params),
      signal: AbortSignal.timeout(50000),
    });
    const text = await resp.text();
    if (!resp.ok) {
      return { content: [{ type: "text", text: `computer-use failed (${resp.status}): ${text}` }], isError: true };
    }
    return { content: [{ type: "text", text: text }] };
  } catch (e) {
    return { content: [{ type: "text", text: `computer-use error: ${e instanceof Error ? e.message : String(e)}` }], isError: true };
  }
}

export async function computerScreenshotTool(
  _input: Record<string, unknown>
): Promise<ToolResult> {
  const url = `${proxyAdmin()}/api/computer-use/execute`;
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "screenshot" }),
      signal: AbortSignal.timeout(50000),
    });
    if (!resp.ok) {
      const text = await resp.text();
      return { content: [{ type: "text", text: `screenshot failed (${resp.status}): ${text}` }], isError: true };
    }
    const data = (await resp.json()) as { image: string; width: number; height: number; media_type?: string };
    return {
      content: [
        {
          type: "image",
          source: {
            type: "base64",
            media_type: data.media_type ?? "image/png",
            data: data.image,
          },
        } as unknown as { type: string; text: string },
        { type: "text", text: `Screenshot: ${data.width}x${data.height}` },
      ],
    };
  } catch (e) {
    return { content: [{ type: "text", text: `screenshot error: ${e instanceof Error ? e.message : String(e)}` }], isError: true };
  }
}

export async function computerClickTool(input: Record<string, unknown>): Promise<ToolResult> {
  return cuExecute({ action: "click", x: input.x, y: input.y, button: input.button ?? "left" });
}

export async function computerDoubleClickTool(input: Record<string, unknown>): Promise<ToolResult> {
  return cuExecute({ action: "double_click", x: input.x, y: input.y });
}

export async function computerRightClickTool(input: Record<string, unknown>): Promise<ToolResult> {
  return cuExecute({ action: "right_click", x: input.x, y: input.y });
}

export async function computerScrollTool(input: Record<string, unknown>): Promise<ToolResult> {
  return cuExecute({ action: "scroll", x: input.x, y: input.y, direction: input.direction ?? "down", amount: input.amount ?? 3 });
}

export async function computerTypeTool(input: Record<string, unknown>): Promise<ToolResult> {
  return cuExecute({ action: "type", text: input.text });
}

export async function computerKeyTool(input: Record<string, unknown>): Promise<ToolResult> {
  return cuExecute({ action: "key", name: input.name });
}

export async function computerMoveTool(input: Record<string, unknown>): Promise<ToolResult> {
  return cuExecute({ action: "move", x: input.x, y: input.y });
}

export async function computerClickQueryTool(input: Record<string, unknown>): Promise<ToolResult> {
  return cuExecute({ action: "click_query", query: input.query, double: input.double ?? false });
}
