import type {
  PluginCommandContext,
  PluginCommandResult,
  OpenClawPluginApi,
  AuditResult,
} from "../types.js";

function getAdminApiUrl(): string {
  return process.env.BOAN_PROXY_ADMIN ?? "http://boan-proxy:18080";
}

async function fetchProxyStatus(): Promise<AuditResult> {
  const url = `${getAdminApiUrl()}/status`;
  const response = await fetch(url, {
    method: "GET",
    headers: { Accept: "application/json" },
    signal: AbortSignal.timeout(10000),
  });

  if (!response.ok) {
    throw new Error(`Proxy returned ${response.status}: ${await response.text()}`);
  }

  return (await response.json()) as AuditResult;
}

function formatAuditResult(result: AuditResult): string {
  const lines: string[] = [];

  const statusIcon =
    result.status === "healthy"
      ? "[OK]"
      : result.status === "degraded"
        ? "[WARN]"
        : "[FAIL]";

  lines.push(`${statusIcon} System Status: ${result.status.toUpperCase()}`);
  lines.push(`  Proxy Online   : ${result.proxyOnline ? "yes" : "no"}`);
  lines.push(`  Git Guard      : ${result.gitGuardActive ? "active" : "inactive"}`);
  lines.push(`  Session Active : ${result.sessionActive ? "yes" : "no"}`);
  lines.push(`  Checked At     : ${result.checkedAt}`);

  if (result.findings.length === 0) {
    lines.push(`  Findings       : none`);
    return lines.join("\n");
  }

  const failed = result.findings.filter((f) => !f.pass);
  const passed = result.findings.filter((f) => f.pass);

  lines.push(`  Checks Passed  : ${passed.length}/${result.findings.length}`);

  if (failed.length > 0) {
    lines.push("");
    lines.push("Failed Checks:");
    for (const f of failed) {
      lines.push(`  [${f.severity.toUpperCase()}] ${f.id}: ${f.message}`);
    }
  }

  return lines.join("\n");
}

export async function registerAuditCommand(
  _ctx: PluginCommandContext,
  api: OpenClawPluginApi
): Promise<PluginCommandResult> {
  try {
    const result = await fetchProxyStatus();
    return { text: formatAuditResult(result) };
  } catch (e) {
    api.logger.warn(`audit failed: ${e}`);
    return {
      text: "Could not run security audit. Is boan-proxy running?",
    };
  }
}

export async function auditTool(
  _input: Record<string, unknown>
): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
  try {
    const result = await fetchProxyStatus();
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  } catch (e) {
    return {
      content: [
        {
          type: "text",
          text: `Audit failed: ${e instanceof Error ? e.message : String(e)}`,
        },
      ],
      isError: true,
    };
  }
}
