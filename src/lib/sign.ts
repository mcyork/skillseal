// SkillSeal — GPG signing
// Wraps gpg --detach-sign --armor to produce SKILL.sig from SKILL.md

import { join } from "node:path";

export interface SignResult {
  success: boolean;
  sigPath: string;
  error?: string;
}

export async function signSkill(skillDir: string, fingerprint?: string): Promise<SignResult> {
  const skillMdPath = join(skillDir, "SKILL.md");
  const sigPath = join(skillDir, "SKILL.sig");

  const file = Bun.file(skillMdPath);
  if (!(await file.exists())) {
    return { success: false, sigPath, error: "SKILL.md not found" };
  }

  // Remove existing signature if present
  const existingSig = Bun.file(sigPath);
  if (await existingSig.exists()) {
    const { unlink } = await import("node:fs/promises");
    await unlink(sigPath);
  }

  const gpgArgs = ["gpg", "--detach-sign", "--armor"];
  if (fingerprint) {
    gpgArgs.push("--local-user", fingerprint);
  }
  gpgArgs.push("--output", sigPath, "--", skillMdPath);

  const proc = Bun.spawn(
    gpgArgs,
    {
      stdout: "pipe",
      stderr: "pipe",
    }
  );

  const exitCode = await proc.exited;
  if (exitCode !== 0) {
    const stderr = await new Response(proc.stderr).text();
    return { success: false, sigPath, error: `gpg signing failed: ${stderr.trim()}` };
  }

  return { success: true, sigPath };
}

export async function getSigningFingerprint(): Promise<string | null> {
  const proc = Bun.spawn(
    ["gpg", "--list-secret-keys", "--with-colons"],
    {
      stdout: "pipe",
      stderr: "pipe",
    }
  );

  const exitCode = await proc.exited;
  if (exitCode !== 0) return null;

  const output = await new Response(proc.stdout).text();
  const lines = output.split("\n");

  // Find the first fingerprint line (fpr) after a secret key (sec)
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith("sec:") || lines[i].startsWith("sec#:")) {
      // Look for the fpr line that follows
      for (let j = i + 1; j < lines.length; j++) {
        if (lines[j].startsWith("fpr:")) {
          const parts = lines[j].split(":");
          return parts[9] || null;
        }
        if (lines[j].startsWith("sec:") || lines[j].startsWith("sec#:")) break;
      }
    }
  }

  return null;
}

export async function getKeyUid(fingerprint: string): Promise<{ name?: string; email?: string } | null> {
  const proc = Bun.spawn(
    ["gpg", "--list-keys", "--with-colons", fingerprint],
    {
      stdout: "pipe",
      stderr: "pipe",
    }
  );

  const exitCode = await proc.exited;
  if (exitCode !== 0) return null;

  const output = await new Response(proc.stdout).text();
  const lines = output.split("\n");

  for (const line of lines) {
    if (line.startsWith("uid:")) {
      const parts = line.split(":");
      const uidField = parts[9] || "";
      // Parse "Name <email>" format
      const match = uidField.match(/^(.+?)\s*<(.+?)>$/);
      if (match) {
        return { name: match[1].trim(), email: match[2].trim() };
      }
      return { name: uidField };
    }
  }

  return null;
}
