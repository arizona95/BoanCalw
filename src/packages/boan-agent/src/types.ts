export interface PluginLogger {
  info(msg: string): void;
  warn(msg: string): void;
  error(msg: string): void;
  debug(msg: string): void;
}

export interface PluginCommandContext {
  args?: string;
  commandBody: string;
  channel: string;
  isAuthorizedSender: boolean;
  config: Record<string, unknown>;
}

export interface PluginCommandResult {
  text?: string;
}

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (input: Record<string, unknown>) => Promise<McpToolResult>;
}

export interface McpToolResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

export interface OpenClawPluginApi {
  id: string;
  name: string;
  logger: PluginLogger;
  registerCommand(def: {
    name: string;
    description: string;
    acceptsArgs?: boolean;
    handler: (ctx: PluginCommandContext) => PluginCommandResult | Promise<PluginCommandResult>;
  }): void;
  registerTool(def: McpToolDefinition): void;
}

export interface BoanConfig {
  proxyUrl: string;
  allowedDirs: string[];
  sessionId: string;
  workspacePath: string;
  adminApiUrl: string;
  autoCommit: boolean;
  gitGuardEnabled: boolean;
}

export interface MountRequest {
  path: string;
  sessionId: string;
  readOnly: boolean;
  allowedExtensions?: string[];
}

export interface MountResponse {
  success: boolean;
  mountPoint: string;
  sessionId: string;
  error?: string;
}

export interface AuditFinding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  message: string;
  pass: boolean;
  timestamp: string;
}

export interface AuditResult {
  status: "healthy" | "degraded" | "unhealthy";
  findings: AuditFinding[];
  proxyOnline: boolean;
  gitGuardActive: boolean;
  sessionActive: boolean;
  checkedAt: string;
}

export interface SessionInfo {
  sessionId: string;
  status: "active" | "stopped" | "unknown";
  workspace: string;
  proxy: string;
  startedAt: string;
  gitBranch: string;
  mountedPaths: string[];
}

export interface LLMUseRequest {
  model: string;
  prompt: string;
  sessionId: string;
  maxTokens?: number;
  temperature?: number;
  allowedTools?: string[];
  sandboxed: boolean;
}

export interface LLMUseResponse {
  requestId: string;
  approved: boolean;
  reason?: string;
  filteredPrompt?: string;
  routedVia: string;
}
