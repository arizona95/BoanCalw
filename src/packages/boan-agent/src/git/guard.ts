import { execSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import type { PluginLogger } from "../types.js";

const BLOCKED_PATTERNS: string[][] = [
  ["reset", "--hard"],
  ["push", "--force"],
  ["push", "-f"],
  ["push", "--force-with-lease"],
  ["rebase", "-i"],
  ["rebase", "--interactive"],
  ["commit", "--amend"],
  ["clean", "-fd"],
  ["clean", "-f"],
  ["checkout", "--", "."],
  ["rm", "-rf", ".git"],
];

const AUDIT_LOG_PATH = "/tmp/boan-audit.log";
const REAL_GIT = "/usr/bin/git";

export class GitGuard {
  constructor(private log: PluginLogger) {}

  install(): void {
    const orig = process.env.PATH ?? "";
    process.env.PATH = `/usr/local/bin/boan-git:${orig}`;
    this.log.info("git guard: PATH override active");
  }

  isBlocked(args: string[]): boolean {
    const normalized = args.map((a) => a.toLowerCase().trim());
    return BLOCKED_PATTERNS.some((pattern) =>
      pattern.every((p) => normalized.includes(p))
    );
  }

  getBlockedPattern(args: string[]): string | null {
    const normalized = args.map((a) => a.toLowerCase().trim());
    for (const pattern of BLOCKED_PATTERNS) {
      if (pattern.every((p) => normalized.includes(p))) {
        return pattern.join(" ");
      }
    }
    return null;
  }

  logBlocked(args: string[]): void {
    const pattern = this.getBlockedPattern(args);
    const entry = JSON.stringify({
      timestamp: new Date().toISOString(),
      event: "git_blocked",
      command: `git ${args.join(" ")}`,
      pattern,
      sessionId: process.env.BOAN_SESSION_ID ?? "unknown",
    });
    this.log.warn(`git guard blocked: git ${args.join(" ")}`);
    try {
      appendFileSync(AUDIT_LOG_PATH, entry + "\n");
    } catch {}
  }

  execGit(workdir: string, gitArgs: string[]): string {
    return execSync(`${REAL_GIT} -C "${workdir}" ${gitArgs.join(" ")}`, {
      encoding: "utf-8",
      stdio: "pipe",
    });
  }

  ensureBranch(workdir: string, sessionId: string): void {
    const branch = `boanclaw/${sessionId}`;
    try {
      const current = this.execGit(workdir, ["branch", "--show-current"]).trim();
      if (current === branch) {
        return;
      }
      try {
        this.execGit(workdir, ["checkout", branch]);
      } catch {
        this.execGit(workdir, ["checkout", "-b", branch]);
      }
    } catch (e) {
      this.log.warn(`ensureBranch failed: ${e}`);
    }
  }

  autoCommit(workdir: string, sessionId: string, message: string): void {
    try {
      this.ensureBranch(workdir, sessionId);

      const status = this.execGit(workdir, ["status", "--porcelain"]).trim();
      if (!status) {
        return;
      }

      this.execGit(workdir, ["add", "-A"]);
      this.execGit(workdir, [
        "commit",
        "-m",
        `"[boanclaw] ${message}"`,
        "--allow-empty",
      ]);

      const entry = JSON.stringify({
        timestamp: new Date().toISOString(),
        event: "auto_commit",
        branch: `boanclaw/${sessionId}`,
        message,
      });
      try {
        appendFileSync(AUDIT_LOG_PATH, entry + "\n");
      } catch {}

      this.log.info(`auto-commit on boanclaw/${sessionId}: ${message}`);
    } catch (e) {
      this.log.warn(`auto-commit failed: ${e}`);
    }
  }

  runGuarded(args: string[]): { blocked: boolean; output?: string; error?: string } {
    if (this.isBlocked(args)) {
      this.logBlocked(args);
      return {
        blocked: true,
        error: `BoanClaw git-guard: "git ${args.join(" ")}" is blocked by security policy.`,
      };
    }

    const workdir = process.env.BOAN_WORKSPACE ?? process.cwd();
    try {
      const output = this.execGit(workdir, args);
      return { blocked: false, output };
    } catch (e) {
      return {
        blocked: false,
        error: e instanceof Error ? e.message : String(e),
      };
    }
  }
}
