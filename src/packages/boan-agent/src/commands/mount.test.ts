import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mountTool, registerMountCommand } from "./mount.js";
import type { OpenClawPluginApi, PluginCommandContext } from "../types.js";

const tmpRoot = "/tmp/boan-agent-mount-test";

function mockApi(): OpenClawPluginApi {
  const noop = () => {};
  return {
    id: "test",
    name: "test",
    logger: { info: noop, warn: noop, error: noop, debug: noop },
    registerCommand: noop,
    registerTool: noop,
  };
}

describe("mount command", () => {
  beforeEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
    mkdirSync(join(tmpRoot, "workspace", "boanclaw", "project"), { recursive: true });
    mkdirSync(join(tmpRoot, "workspace", "other"), { recursive: true });
    writeFileSync(join(tmpRoot, "workspace", "boanclaw", "project", "README.md"), "ok");
    vi.restoreAllMocks();
    process.env.BOAN_PROXY_ADMIN = "http://proxy.test";
    process.env.BOAN_SESSION_ID = "session-test";
  });

  afterEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it("allows paths within policy mount root", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({
          org_id: "sds-corp",
          mount_root: join(tmpRoot, "workspace", "boanclaw"),
          allowedDirs: [join(tmpRoot, "workspace", "boanclaw")],
        }), { status: 200, headers: { "Content-Type": "application/json" } })
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({
          success: true,
          mountPoint: "/workspace/boanclaw/project",
          sessionId: "session-test",
        }), { status: 200, headers: { "Content-Type": "application/json" } })
      );
    vi.stubGlobal("fetch", fetchMock);

    const result = await mountTool({ path: join(tmpRoot, "workspace", "boanclaw", "project") });
    expect(result.isError).toBeUndefined();
    expect(result.content[0]?.text).toContain("\"mountPoint\":\"/workspace/boanclaw/project\"");
  });

  it("blocks paths outside policy mount root", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
      new Response(JSON.stringify({
        org_id: "sds-corp",
        mount_root: join(tmpRoot, "workspace", "boanclaw"),
        allowedDirs: [join(tmpRoot, "workspace", "boanclaw")],
      }), { status: 200, headers: { "Content-Type": "application/json" } })
    ));

    const result = await registerMountCommand(
      { args: join(tmpRoot, "workspace", "other"), commandBody: "", channel: "test", isAuthorizedSender: true, config: {} } satisfies PluginCommandContext,
      [join(tmpRoot, "workspace", "other")],
      mockApi()
    );
    expect(result.text).toContain("Access denied");
    expect(result.text).toContain(join(tmpRoot, "workspace", "boanclaw"));
  });

  it("fails closed when proxy mount policy is unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("proxy unavailable")));

    const result = await mountTool({ path: join(tmpRoot, "workspace", "boanclaw", "project") });
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain("boan-proxy mount policy unavailable");
  });
});
