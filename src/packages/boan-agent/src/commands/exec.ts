import { ApprovalClient } from "../approval.js";

const HIGH_RISK_COMMANDS = [
  "rm", "sudo", "chmod", "chown", "dd", "mkfs", "fdisk", "kill", "pkill",
];

export async function guardedExec(
  command: string,
  args: string[],
  api: { sessionId: string }
): Promise<{ allowed: boolean; reason?: string }> {
  const requireAll = process.env.BOAN_EXEC_APPROVAL_REQUIRED === "1";
  const isHighRisk = HIGH_RISK_COMMANDS.includes(command);

  if (!requireAll && !isHighRisk) {
    return { allowed: true };
  }

  const adminUrl = process.env.BOAN_ADMIN_URL ?? "http://boan-admin:18090";
  const client = new ApprovalClient(adminUrl, api.sessionId);

  let request;
  try {
    request = await client.requestApproval(command, args);
  } catch (e) {
    return {
      allowed: false,
      reason: `approval request failed: ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  const decision = await client.waitForDecision(request.id);

  if (decision === "approved") {
    return { allowed: true };
  }

  return {
    allowed: false,
    reason: `exec rejected by admin for command: ${command}`,
  };
}
