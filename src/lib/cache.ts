// SkillSeal — key cache
// Caches fetched GPG and SSH keys locally for offline verification
// v0.3.0: Cache never expires — refreshes opportunistically when online

import { join } from "node:path";
import { homedir } from "node:os";
import { mkdir } from "node:fs/promises";

const CACHE_DIR = join(homedir(), ".skillseal", "key-cache");

export type CacheKeyType = "gpg" | "ssh";

function cachePath(type: CacheKeyType, github: string): string {
  const ext = type === "gpg" ? "asc" : "json";
  return join(CACHE_DIR, type, `${github}.${ext}`);
}

export async function readCache(type: CacheKeyType, github: string): Promise<string | null> {
  const path = cachePath(type, github);
  const file = Bun.file(path);
  if (!(await file.exists())) return null;
  return file.text();
}

export async function writeCache(type: CacheKeyType, github: string, data: string): Promise<void> {
  const dir = join(CACHE_DIR, type);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await Bun.write(cachePath(type, github), data);
}
