// SkillSeal v0.2.5 — key cache tests

import { test, expect, describe, afterEach } from "bun:test";
import { readCache, writeCache } from "../src/lib/cache";
import { join } from "node:path";
import { homedir } from "node:os";
import { rm } from "node:fs/promises";

const TEST_USER = "__skillseal_test_user__";
const CACHE_DIR = join(homedir(), ".skillseal", "key-cache");

async function cleanupTestUser(): Promise<void> {
  const gpgPath = join(CACHE_DIR, "gpg", `${TEST_USER}.asc`);
  const sshPath = join(CACHE_DIR, "ssh", `${TEST_USER}.json`);
  await rm(gpgPath, { force: true }).catch(() => {});
  await rm(sshPath, { force: true }).catch(() => {});
}

describe("cache", () => {
  afterEach(async () => {
    await cleanupTestUser();
  });

  test("writeCache creates GPG cache file and readCache reads it back", async () => {
    const gpgData = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmocked-gpg-key-data\n-----END PGP PUBLIC KEY BLOCK-----";

    await writeCache("gpg", TEST_USER, gpgData);
    const result = await readCache("gpg", TEST_USER);

    expect(result).not.toBeNull();
    expect(result).toBe(gpgData);
  });

  test("writeCache creates SSH cache file and readCache reads it back", async () => {
    const sshData = JSON.stringify([
      { id: 1, key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test@host" },
    ]);

    await writeCache("ssh", TEST_USER, sshData);
    const result = await readCache("ssh", TEST_USER);

    expect(result).not.toBeNull();
    expect(result).toBe(sshData);
  });

  test("readCache returns null for non-existent cache entry", async () => {
    const result = await readCache("gpg", "__skillseal_nonexistent_user__");

    expect(result).toBeNull();
  });

  test("writeCache overwrites existing cache entry", async () => {
    const originalData = "original-key-data";
    const updatedData = "updated-key-data";

    await writeCache("gpg", TEST_USER, originalData);
    const first = await readCache("gpg", TEST_USER);
    expect(first).toBe(originalData);

    await writeCache("gpg", TEST_USER, updatedData);
    const second = await readCache("gpg", TEST_USER);
    expect(second).toBe(updatedData);
  });

  test("writeCache handles special characters in key data (PGP armor)", async () => {
    const pgpArmor = [
      "-----BEGIN PGP PUBLIC KEY BLOCK-----",
      "",
      "mQINBGAAAAEBEAC7+b3p3EZgfXaTwsBJ2fGxBJyK2FrGzEMR2sCfVh0hcn5gA==",
      "=XyZa",
      "-----END PGP PUBLIC KEY BLOCK-----",
    ].join("\n");

    await writeCache("gpg", TEST_USER, pgpArmor);
    const result = await readCache("gpg", TEST_USER);

    expect(result).not.toBeNull();
    expect(result).toBe(pgpArmor);
  });

  test("readCache/writeCache round-trip preserves exact content", async () => {
    const contentWithVariousChars = [
      "line1: normal text",
      "line2: special chars !@#$%^&*(){}[]|\\:\";<>?,./~`",
      "line3: unicode \u00e9\u00e8\u00ea\u00eb \u00fc\u00f6\u00e4",
      "line4: tabs\there\tand\tthere",
      "line5: trailing spaces   ",
      "",
      "line7: after blank line",
      "line8: base64-like ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/==",
    ].join("\n");

    await writeCache("ssh", TEST_USER, contentWithVariousChars);
    const result = await readCache("ssh", TEST_USER);

    expect(result).not.toBeNull();
    expect(result).toBe(contentWithVariousChars);
    expect(result!.length).toBe(contentWithVariousChars.length);
  });
});
