export interface ApprovalRequest {
  id: string;
  sessionId: string;
  command: string;
  args: string[];
  requester: string;
  requestedAt: string;
  status: "pending" | "approved" | "rejected";
  decidedBy?: string;
  decidedAt?: string;
}

export class ApprovalClient {
  constructor(
    private readonly adminUrl: string,
    private readonly sessionId: string
  ) {}

  async requestApproval(command: string, args: string[]): Promise<ApprovalRequest> {
    const body: Omit<ApprovalRequest, "id" | "status"> = {
      sessionId: this.sessionId,
      command,
      args,
      requester: process.env.BOAN_AGENT_ID ?? "boan-agent",
      requestedAt: new Date().toISOString(),
    };

    const res = await fetch(`${this.adminUrl}/api/approvals`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      throw new Error(`approval request failed: ${res.status} ${await res.text()}`);
    }

    return res.json() as Promise<ApprovalRequest>;
  }

  async waitForDecision(id: string, timeoutMs = 5 * 60 * 1000): Promise<"approved" | "rejected"> {
    const deadline = Date.now() + timeoutMs;
    const pollInterval = 3000;

    while (Date.now() < deadline) {
      const res = await fetch(`${this.adminUrl}/api/approvals/${id}`);
      if (res.ok) {
        const req = (await res.json()) as ApprovalRequest;
        if (req.status !== "pending") {
          return req.status === "approved" ? "approved" : "rejected";
        }
      }
      await new Promise((resolve) => setTimeout(resolve, pollInterval));
    }

    return "rejected";
  }
}
