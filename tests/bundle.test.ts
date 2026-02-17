// SkillSeal v0.2.6 — trust bundle application tests

import { test, expect, describe } from "bun:test";
import { applyBundle } from "../src/lib/bundle";
import type { TrustStore, TrustedEntity } from "../src/lib/trust";
import type { TrustBundleData } from "../src/lib/bundle";

function makeStore(overrides?: Partial<TrustStore>): TrustStore {
  return {
    schema_version: "0.2.6",
    trusted_authors: {},
    trusted_reviewers: {},
    policies: {
      unsigned: "refuse",
      signature_invalid: "refuse",
      unknown_author: "prompt",
      known_author_no_attestations: "allow",
      known_author_with_attestations: "allow",
      known_author_stale_attestations: "prompt",
      trusted_reviewer_attested: "allow",
      trusted_reviewer_destatement: "refuse",
    },
    overrides: [],
    bundles: [],
    ...overrides,
  };
}

function makeBundle(overrides?: Partial<TrustBundleData>): TrustBundleData {
  return {
    bundle: "skillseal/community-trust",
    version: 1,
    updated: "2026-02-17T00:00:00Z",
    trusted_authors: {},
    trusted_reviewers: {},
    revoked_fingerprints: [],
    ...overrides,
  };
}

function makeEntity(overrides?: Partial<TrustedEntity>): TrustedEntity {
  return {
    name: "Test User",
    keys: [{ type: "gpg", fingerprint: "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555" }],
    trust_level: "author",
    added_at: "2026-02-17T00:00:00Z",
    ...overrides,
  };
}

describe("applyBundle", () => {
  test("adds new authors from bundle to empty store", () => {
    const store = makeStore();
    const bundle = makeBundle({
      trusted_authors: {
        alice: makeEntity({ name: "Alice", trust_level: "author" }),
      },
    });

    applyBundle(bundle, store);

    expect(store.trusted_authors["alice"]).toBeDefined();
    expect(store.trusted_authors["alice"].name).toBe("Alice");
    expect(store.trusted_authors["alice"].keys).toHaveLength(1);
  });

  test("adds new reviewers from bundle to empty store", () => {
    const store = makeStore();
    const bundle = makeBundle({
      trusted_reviewers: {
        bob: makeEntity({ name: "Bob", trust_level: "reviewer" }),
      },
    });

    applyBundle(bundle, store);

    expect(store.trusted_reviewers["bob"]).toBeDefined();
    expect(store.trusted_reviewers["bob"].name).toBe("Bob");
    expect(store.trusted_reviewers["bob"].trust_level).toBe("reviewer");
  });

  test("does NOT overwrite existing authors (preserves local trust)", () => {
    const localAuthor = makeEntity({
      name: "Alice Local",
      keys: [{ type: "gpg", fingerprint: "LOCAL_FINGERPRINT_1234" }],
    });
    const store = makeStore({
      trusted_authors: { alice: localAuthor },
    });
    const bundle = makeBundle({
      trusted_authors: {
        alice: makeEntity({
          name: "Alice Bundle",
          keys: [{ type: "gpg", fingerprint: "BUNDLE_FINGERPRINT_5678" }],
        }),
      },
    });

    applyBundle(bundle, store);

    expect(store.trusted_authors["alice"].name).toBe("Alice Local");
    expect(store.trusted_authors["alice"].keys[0].fingerprint).toBe("LOCAL_FINGERPRINT_1234");
  });

  test("does NOT overwrite existing reviewers", () => {
    const localReviewer = makeEntity({
      name: "Bob Local",
      trust_level: "reviewer",
      keys: [{ type: "ssh", fingerprint: "SHA256:localkey123" }],
    });
    const store = makeStore({
      trusted_reviewers: { bob: localReviewer },
    });
    const bundle = makeBundle({
      trusted_reviewers: {
        bob: makeEntity({
          name: "Bob Bundle",
          trust_level: "reviewer",
          keys: [{ type: "ssh", fingerprint: "SHA256:bundlekey456" }],
        }),
      },
    });

    applyBundle(bundle, store);

    expect(store.trusted_reviewers["bob"].name).toBe("Bob Local");
    expect(store.trusted_reviewers["bob"].keys[0].fingerprint).toBe("SHA256:localkey123");
  });

  test("returns correct addedAuthors count", () => {
    const store = makeStore({
      trusted_authors: {
        existing: makeEntity({ name: "Existing" }),
      },
    });
    const bundle = makeBundle({
      trusted_authors: {
        existing: makeEntity({ name: "Existing Bundle" }),
        newauthor: makeEntity({ name: "New Author" }),
      },
    });

    const result = applyBundle(bundle, store);

    expect(result.addedAuthors).toBe(1);
  });

  test("returns correct addedReviewers count", () => {
    const store = makeStore({
      trusted_reviewers: {
        existing: makeEntity({ name: "Existing", trust_level: "reviewer" }),
      },
    });
    const bundle = makeBundle({
      trusted_reviewers: {
        existing: makeEntity({ name: "Existing Bundle", trust_level: "reviewer" }),
        newreviewer1: makeEntity({ name: "New Reviewer 1", trust_level: "reviewer" }),
        newreviewer2: makeEntity({ name: "New Reviewer 2", trust_level: "reviewer" }),
      },
    });

    const result = applyBundle(bundle, store);

    expect(result.addedReviewers).toBe(2);
  });

  test("adds multiple authors and reviewers in one operation", () => {
    const store = makeStore();
    const bundle = makeBundle({
      trusted_authors: {
        alice: makeEntity({ name: "Alice" }),
        charlie: makeEntity({ name: "Charlie" }),
        dave: makeEntity({ name: "Dave" }),
      },
      trusted_reviewers: {
        bob: makeEntity({ name: "Bob", trust_level: "reviewer" }),
        eve: makeEntity({ name: "Eve", trust_level: "reviewer" }),
      },
    });

    const result = applyBundle(bundle, store);

    expect(result.addedAuthors).toBe(3);
    expect(result.addedReviewers).toBe(2);
    expect(Object.keys(store.trusted_authors)).toHaveLength(3);
    expect(Object.keys(store.trusted_reviewers)).toHaveLength(2);
  });

  test("revokes keys matching revoked_fingerprints from authors", () => {
    const store = makeStore({
      trusted_authors: {
        alice: makeEntity({
          name: "Alice",
          keys: [
            { type: "gpg", fingerprint: "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555" },
            { type: "ssh", fingerprint: "SHA256:keepthiskey" },
          ],
        }),
      },
    });
    const bundle = makeBundle({
      revoked_fingerprints: ["AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"],
    });

    applyBundle(bundle, store);

    expect(store.trusted_authors["alice"].keys).toHaveLength(1);
    expect(store.trusted_authors["alice"].keys[0].fingerprint).toBe("SHA256:keepthiskey");
  });

  test("revokes keys matching revoked_fingerprints from reviewers", () => {
    const store = makeStore({
      trusted_reviewers: {
        bob: makeEntity({
          name: "Bob",
          trust_level: "reviewer",
          keys: [
            { type: "gpg", fingerprint: "REVOKEME1234" },
            { type: "ssh", fingerprint: "SHA256:keepme5678" },
          ],
        }),
      },
    });
    const bundle = makeBundle({
      revoked_fingerprints: ["REVOKEME1234"],
    });

    applyBundle(bundle, store);

    expect(store.trusted_reviewers["bob"].keys).toHaveLength(1);
    expect(store.trusted_reviewers["bob"].keys[0].fingerprint).toBe("SHA256:keepme5678");
  });

  test("removes entity entirely when all keys are revoked", () => {
    const store = makeStore({
      trusted_authors: {
        alice: makeEntity({
          name: "Alice",
          keys: [{ type: "gpg", fingerprint: "ONLY_KEY_TO_REVOKE" }],
        }),
      },
    });
    const bundle = makeBundle({
      revoked_fingerprints: ["ONLY_KEY_TO_REVOKE"],
    });

    applyBundle(bundle, store);

    expect(store.trusted_authors["alice"]).toBeUndefined();
  });

  test("returns correct revokedKeys count", () => {
    const store = makeStore({
      trusted_authors: {
        alice: makeEntity({
          keys: [
            { type: "gpg", fingerprint: "REVOKE_A" },
            { type: "gpg", fingerprint: "REVOKE_B" },
            { type: "ssh", fingerprint: "SHA256:keep" },
          ],
        }),
      },
      trusted_reviewers: {
        bob: makeEntity({
          trust_level: "reviewer",
          keys: [{ type: "gpg", fingerprint: "REVOKE_C" }],
        }),
      },
    });
    const bundle = makeBundle({
      revoked_fingerprints: ["REVOKE_A", "REVOKE_B", "REVOKE_C"],
    });

    const result = applyBundle(bundle, store);

    expect(result.revokedKeys).toBe(3);
  });

  test("handles case-insensitive fingerprint matching for revocation", () => {
    const store = makeStore({
      trusted_authors: {
        alice: makeEntity({
          keys: [
            { type: "gpg", fingerprint: "aabb1122ccdd3344eeff" },
            { type: "ssh", fingerprint: "SHA256:keepme" },
          ],
        }),
      },
    });
    const bundle = makeBundle({
      revoked_fingerprints: ["AABB1122CCDD3344EEFF"],
    });

    applyBundle(bundle, store);

    expect(store.trusted_authors["alice"].keys).toHaveLength(1);
    expect(store.trusted_authors["alice"].keys[0].fingerprint).toBe("SHA256:keepme");
  });

  test("handles fingerprints with spaces in revocation matching", () => {
    const store = makeStore({
      trusted_authors: {
        alice: makeEntity({
          keys: [
            { type: "gpg", fingerprint: "AAAA 1111 BBBB 2222 CCCC" },
            { type: "ssh", fingerprint: "SHA256:safe" },
          ],
        }),
      },
    });
    const bundle = makeBundle({
      revoked_fingerprints: ["AAAA1111BBBB2222CCCC"],
    });

    applyBundle(bundle, store);

    expect(store.trusted_authors["alice"].keys).toHaveLength(1);
    expect(store.trusted_authors["alice"].keys[0].fingerprint).toBe("SHA256:safe");
  });

  test("empty revoked_fingerprints array — no keys removed", () => {
    const store = makeStore({
      trusted_authors: {
        alice: makeEntity({
          keys: [{ type: "gpg", fingerprint: "KEEP_THIS" }],
        }),
      },
    });
    const bundle = makeBundle({
      revoked_fingerprints: [],
    });

    const result = applyBundle(bundle, store);

    expect(result.revokedKeys).toBe(0);
    expect(store.trusted_authors["alice"].keys).toHaveLength(1);
  });

  test("no revoked_fingerprints field — no keys removed", () => {
    const store = makeStore({
      trusted_authors: {
        alice: makeEntity({
          keys: [{ type: "gpg", fingerprint: "KEEP_THIS_TOO" }],
        }),
      },
    });
    const bundleData = makeBundle();
    // Remove the field entirely to simulate a bundle without it
    delete (bundleData as Record<string, unknown>)["revoked_fingerprints"];

    const result = applyBundle(bundleData, store);

    expect(result.revokedKeys).toBe(0);
    expect(store.trusted_authors["alice"].keys).toHaveLength(1);
  });

  test("combined: adds new entities AND revokes keys in same operation", () => {
    const store = makeStore({
      trusted_authors: {
        compromised: makeEntity({
          name: "Compromised",
          keys: [{ type: "gpg", fingerprint: "COMPROMISED_KEY" }],
        }),
      },
    });
    const bundle = makeBundle({
      trusted_authors: {
        newauthor: makeEntity({ name: "New Author" }),
      },
      trusted_reviewers: {
        newreviewer: makeEntity({ name: "New Reviewer", trust_level: "reviewer" }),
      },
      revoked_fingerprints: ["COMPROMISED_KEY"],
    });

    const result = applyBundle(bundle, store);

    expect(result.addedAuthors).toBe(1);
    expect(result.addedReviewers).toBe(1);
    expect(result.revokedKeys).toBe(1);
    expect(store.trusted_authors["newauthor"]).toBeDefined();
    expect(store.trusted_reviewers["newreviewer"]).toBeDefined();
    expect(store.trusted_authors["compromised"]).toBeUndefined();
  });

  test("bundle with empty authors and reviewers — returns all zeros", () => {
    const store = makeStore();
    const bundle = makeBundle({
      trusted_authors: {},
      trusted_reviewers: {},
      revoked_fingerprints: [],
    });

    const result = applyBundle(bundle, store);

    expect(result.addedAuthors).toBe(0);
    expect(result.addedReviewers).toBe(0);
    expect(result.revokedKeys).toBe(0);
  });

  test("revocation removes key from multi-key entity but keeps remaining keys", () => {
    const store = makeStore({
      trusted_authors: {
        alice: makeEntity({
          name: "Alice",
          keys: [
            { type: "gpg", fingerprint: "KEY_TO_REVOKE" },
            { type: "ssh", fingerprint: "SHA256:keepA" },
            { type: "gpg", fingerprint: "ANOTHER_GOOD_KEY" },
          ],
        }),
      },
    });
    const bundle = makeBundle({
      revoked_fingerprints: ["KEY_TO_REVOKE"],
    });

    applyBundle(bundle, store);

    expect(store.trusted_authors["alice"]).toBeDefined();
    expect(store.trusted_authors["alice"].keys).toHaveLength(2);
    const fingerprints = store.trusted_authors["alice"].keys.map((k) => k.fingerprint);
    expect(fingerprints).toContain("SHA256:keepA");
    expect(fingerprints).toContain("ANOTHER_GOOD_KEY");
    expect(fingerprints).not.toContain("KEY_TO_REVOKE");
  });
});
