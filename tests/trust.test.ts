// SkillSeal — trust store policy evaluation engine tests
// Tests the security-critical heart of SkillSeal: evaluatePolicy, isAuthorTrusted, isReviewerTrusted

import { test, expect, describe } from "bun:test";
import {
  evaluatePolicy,
  isAuthorTrusted,
  isReviewerTrusted,
  type TrustStore,
  type TrustedEntity,
  type PolicyAction,
  type PolicyScenario,
} from "../src/lib/trust";
import type { TrustJson } from "../src/lib/verify";

// ---------------------------------------------------------------------------
// Test fixture helpers
// ---------------------------------------------------------------------------

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

function makeTrust(github: string, fingerprint: string): TrustJson {
  return {
    schema_version: "0.2.0",
    author: {
      name: `${github} Author`,
      github,
      keys: [
        {
          type: "gpg",
          fingerprint,
          key_url: `https://github.com/${github}.gpg`,
        },
      ],
    },
  };
}

function makeAttestation(
  reviewerGithub: string,
  reviewerFingerprint: string,
  opts?: Partial<{
    valid: boolean;
    stale: boolean;
    signatureValid: boolean;
    verdict: "approve" | "reject";
    date: string;
    statement: string;
  }>
) {
  return {
    valid: opts?.valid ?? true,
    stale: opts?.stale ?? false,
    signatureValid: opts?.signatureValid ?? true,
    verdict: (opts?.verdict ?? "approve") as "approve" | "reject",
    bundle: {
      statement: {
        reviewer: {
          github: reviewerGithub,
          fingerprint: reviewerFingerprint,
        },
        attestation: {
          date: opts?.date ?? "2026-01-15",
          statement: opts?.statement ?? "Code review passed all checks",
        },
      },
    },
  };
}

function makeEntity(
  fingerprint: string,
  trustLevel: "author" | "reviewer" = "author",
  opts?: { name?: string; keyType?: string }
): TrustedEntity {
  return {
    keys: [
      {
        type: opts?.keyType ?? "gpg",
        fingerprint,
      },
    ],
    trust_level: trustLevel,
    name: opts?.name,
    added_at: "2026-01-01T00:00:00Z",
  };
}

function makeMultiKeyEntity(
  keys: Array<{ type: string; fingerprint: string }>,
  trustLevel: "author" | "reviewer" = "author"
): TrustedEntity {
  return {
    keys,
    trust_level: trustLevel,
    added_at: "2026-01-01T00:00:00Z",
  };
}

// ---------------------------------------------------------------------------
// isAuthorTrusted
// ---------------------------------------------------------------------------

describe("isAuthorTrusted", () => {
  test("returns true when author is in store with matching fingerprint", () => {
    const fp = "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234";
    const store = makeStore({
      trusted_authors: {
        alice: makeEntity(fp),
      },
    });

    expect(isAuthorTrusted(store, "alice", fp)).toBe(true);
  });

  test("returns false when author is not in store", () => {
    const store = makeStore({
      trusted_authors: {
        alice: makeEntity("ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"),
      },
    });

    expect(isAuthorTrusted(store, "bob", "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234")).toBe(false);
  });

  test("returns false when fingerprint does not match", () => {
    const store = makeStore({
      trusted_authors: {
        alice: makeEntity("ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"),
      },
    });

    expect(isAuthorTrusted(store, "alice", "9999888877776666555544443333222211110000")).toBe(false);
  });

  test("handles case-insensitive fingerprint comparison", () => {
    const store = makeStore({
      trusted_authors: {
        alice: makeEntity("ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"),
      },
    });

    expect(isAuthorTrusted(store, "alice", "abcd1234abcd1234abcd1234abcd1234abcd1234")).toBe(true);
  });

  test("handles fingerprint with spaces (normalized)", () => {
    const store = makeStore({
      trusted_authors: {
        alice: makeEntity("ABCD 1234 ABCD 1234 ABCD 1234 ABCD 1234 ABCD 1234"),
      },
    });

    expect(isAuthorTrusted(store, "alice", "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234")).toBe(true);
  });

  test("matches against any key in multi-key entity (GPG key matches)", () => {
    const gpgFp = "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111";
    const sshFp = "SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    const store = makeStore({
      trusted_authors: {
        alice: makeMultiKeyEntity([
          { type: "gpg", fingerprint: gpgFp },
          { type: "ssh", fingerprint: sshFp },
        ]),
      },
    });

    expect(isAuthorTrusted(store, "alice", gpgFp)).toBe(true);
  });

  test("matches against any key in multi-key entity (SSH key matches)", () => {
    const gpgFp = "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111";
    const sshFp = "SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    const store = makeStore({
      trusted_authors: {
        alice: makeMultiKeyEntity([
          { type: "gpg", fingerprint: gpgFp },
          { type: "ssh", fingerprint: sshFp },
        ]),
      },
    });

    expect(isAuthorTrusted(store, "alice", sshFp)).toBe(true);
  });

  test("returns false when no key fingerprint matches despite multiple keys", () => {
    const store = makeStore({
      trusted_authors: {
        alice: makeMultiKeyEntity([
          { type: "gpg", fingerprint: "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111" },
          { type: "ssh", fingerprint: "SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
        ]),
      },
    });

    expect(isAuthorTrusted(store, "alice", "ZZZZ0000ZZZZ0000ZZZZ0000ZZZZ0000ZZZZ0000")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// isReviewerTrusted
// ---------------------------------------------------------------------------

describe("isReviewerTrusted", () => {
  test("returns true when reviewer is in store with matching fingerprint", () => {
    const fp = "DEED5678DEED5678DEED5678DEED5678DEED5678";
    const store = makeStore({
      trusted_reviewers: {
        reviewer1: makeEntity(fp, "reviewer"),
      },
    });

    expect(isReviewerTrusted(store, "reviewer1", fp)).toBe(true);
  });

  test("returns false when reviewer is not in store", () => {
    const store = makeStore({
      trusted_reviewers: {
        reviewer1: makeEntity("DEED5678DEED5678DEED5678DEED5678DEED5678", "reviewer"),
      },
    });

    expect(isReviewerTrusted(store, "unknown-reviewer", "DEED5678DEED5678DEED5678DEED5678DEED5678")).toBe(false);
  });

  test("returns false when fingerprint does not match", () => {
    const store = makeStore({
      trusted_reviewers: {
        reviewer1: makeEntity("DEED5678DEED5678DEED5678DEED5678DEED5678", "reviewer"),
      },
    });

    expect(isReviewerTrusted(store, "reviewer1", "0000000000000000000000000000000000000000")).toBe(false);
  });

  test("matches against any key in multi-key reviewer entity", () => {
    const gpgFp = "BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222";
    const sshFp = "SHA256:yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";
    const store = makeStore({
      trusted_reviewers: {
        reviewer1: makeMultiKeyEntity(
          [
            { type: "gpg", fingerprint: gpgFp },
            { type: "ssh", fingerprint: sshFp },
          ],
          "reviewer"
        ),
      },
    });

    expect(isReviewerTrusted(store, "reviewer1", gpgFp)).toBe(true);
    expect(isReviewerTrusted(store, "reviewer1", sshFp)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// evaluatePolicy
// ---------------------------------------------------------------------------

describe("evaluatePolicy", () => {
  // -----------------------------------------------------------------------
  // Signature scenarios
  // -----------------------------------------------------------------------

  describe("signature scenarios", () => {
    test("invalid signature returns signature_invalid with refuse action", () => {
      const store = makeStore();
      const trust = makeTrust("alice", "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234");

      const result = evaluatePolicy(store, trust, false);

      expect(result.scenario).toBe("signature_invalid");
      expect(result.action).toBe("refuse");
    });

    test("invalid signature with custom policy returns signature_invalid with custom action", () => {
      const store = makeStore({
        policies: {
          unsigned: "refuse",
          signature_invalid: "prompt",
          unknown_author: "prompt",
          known_author_no_attestations: "allow",
          known_author_with_attestations: "allow",
          known_author_stale_attestations: "prompt",
          trusted_reviewer_attested: "allow",
          trusted_reviewer_destatement: "refuse",
        },
      });
      const trust = makeTrust("alice", "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234");

      const result = evaluatePolicy(store, trust, false);

      expect(result.scenario).toBe("signature_invalid");
      expect(result.action).toBe("prompt");
    });
  });

  // -----------------------------------------------------------------------
  // Destatement scenarios
  // -----------------------------------------------------------------------

  describe("destatement scenarios", () => {
    const authorFp = "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111";
    const reviewerFp = "RRRR4444RRRR4444RRRR4444RRRR4444RRRR4444";

    test("destatement from trusted reviewer with no override returns trusted_reviewer_destatement, refuse", () => {
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
        trusted_reviewers: { secbot: makeEntity(reviewerFp, "reviewer") },
      });
      const trust = makeTrust("alice", authorFp);
      const attestations = [
        makeAttestation("secbot", reviewerFp, { verdict: "reject", statement: "Malicious code detected" }),
      ];

      const result = evaluatePolicy(store, trust, true, attestations);

      expect(result.scenario).toBe("trusted_reviewer_destatement");
      expect(result.action).toBe("refuse");
    });

    test("destatement from trusted reviewer with matching skill override bypasses destatement", () => {
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
        trusted_reviewers: { secbot: makeEntity(reviewerFp, "reviewer") },
        overrides: [
          { skill: "my-skill", despite: "secbot", reason: "False positive" },
        ],
      });
      const trust = makeTrust("alice", authorFp);
      const attestations = [
        makeAttestation("secbot", reviewerFp, { verdict: "reject" }),
      ];

      const result = evaluatePolicy(store, trust, true, attestations, "my-skill");

      // Destatement bypassed, so should continue to positive evaluation
      // Author is trusted, no valid approvals (only reject), so known_author_no_attestations
      expect(result.scenario).toBe("known_author_no_attestations");
      expect(result.action).toBe("allow");
    });

    test("destatement from trusted reviewer with 'all' override bypasses destatement", () => {
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
        trusted_reviewers: { secbot: makeEntity(reviewerFp, "reviewer") },
        overrides: [
          { skill: "all", despite: "secbot", reason: "Global override for secbot" },
        ],
      });
      const trust = makeTrust("alice", authorFp);
      const attestations = [
        makeAttestation("secbot", reviewerFp, { verdict: "reject" }),
      ];

      const result = evaluatePolicy(store, trust, true, attestations, "any-skill");

      expect(result.scenario).toBe("known_author_no_attestations");
      expect(result.action).toBe("allow");
    });

    test("destatement from trusted reviewer with override for different skill is NOT bypassed", () => {
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
        trusted_reviewers: { secbot: makeEntity(reviewerFp, "reviewer") },
        overrides: [
          { skill: "other-skill", despite: "secbot", reason: "Only for other-skill" },
        ],
      });
      const trust = makeTrust("alice", authorFp);
      const attestations = [
        makeAttestation("secbot", reviewerFp, { verdict: "reject", statement: "Vulnerability found" }),
      ];

      const result = evaluatePolicy(store, trust, true, attestations, "my-skill");

      expect(result.scenario).toBe("trusted_reviewer_destatement");
      expect(result.action).toBe("refuse");
    });

    test("destatement from trusted reviewer with override for different reviewer is NOT bypassed", () => {
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
        trusted_reviewers: {
          secbot: makeEntity(reviewerFp, "reviewer"),
          otherbot: makeEntity("OOOO5555OOOO5555OOOO5555OOOO5555OOOO5555", "reviewer"),
        },
        overrides: [
          { skill: "my-skill", despite: "otherbot", reason: "Override for otherbot, not secbot" },
        ],
      });
      const trust = makeTrust("alice", authorFp);
      const attestations = [
        makeAttestation("secbot", reviewerFp, { verdict: "reject" }),
      ];

      const result = evaluatePolicy(store, trust, true, attestations, "my-skill");

      expect(result.scenario).toBe("trusted_reviewer_destatement");
      expect(result.action).toBe("refuse");
    });

    test("destatement from untrusted reviewer is ignored and continues to positive evaluation", () => {
      const untrustedFp = "UUUU6666UUUU6666UUUU6666UUUU6666UUUU6666";
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
        // No trusted reviewers — the destatement reviewer is untrusted
      });
      const trust = makeTrust("alice", authorFp);
      const attestations = [
        makeAttestation("untrusted-reviewer", untrustedFp, { verdict: "reject" }),
      ];

      const result = evaluatePolicy(store, trust, true, attestations);

      // Untrusted reviewer destatement is ignored; only reject attestation present,
      // so validApprovals is empty, resulting in known_author_no_attestations
      expect(result.scenario).toBe("known_author_no_attestations");
      expect(result.action).toBe("allow");
    });

    test("multiple destatements with only one overridden still blocks on remaining destatement", () => {
      const reviewer2Fp = "SSSS7777SSSS7777SSSS7777SSSS7777SSSS7777";
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
        trusted_reviewers: {
          secbot: makeEntity(reviewerFp, "reviewer"),
          auditor: makeEntity(reviewer2Fp, "reviewer"),
        },
        overrides: [
          { skill: "my-skill", despite: "secbot", reason: "Override secbot only" },
        ],
      });
      const trust = makeTrust("alice", authorFp);
      const attestations = [
        makeAttestation("secbot", reviewerFp, { verdict: "reject" }),
        makeAttestation("auditor", reviewer2Fp, { verdict: "reject", statement: "Audit failed" }),
      ];

      const result = evaluatePolicy(store, trust, true, attestations, "my-skill");

      // secbot's destatement is overridden, but auditor's is not
      expect(result.scenario).toBe("trusted_reviewer_destatement");
      expect(result.action).toBe("refuse");
      expect(result.destatement?.reviewer).toBe("auditor");
    });

    test("destatement with custom policy (allow instead of refuse) returns custom action", () => {
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
        trusted_reviewers: { secbot: makeEntity(reviewerFp, "reviewer") },
        policies: {
          unsigned: "refuse",
          signature_invalid: "refuse",
          unknown_author: "prompt",
          known_author_no_attestations: "allow",
          known_author_with_attestations: "allow",
          known_author_stale_attestations: "prompt",
          trusted_reviewer_attested: "allow",
          trusted_reviewer_destatement: "allow",
        },
      });
      const trust = makeTrust("alice", authorFp);
      const attestations = [
        makeAttestation("secbot", reviewerFp, { verdict: "reject" }),
      ];

      const result = evaluatePolicy(store, trust, true, attestations);

      expect(result.scenario).toBe("trusted_reviewer_destatement");
      expect(result.action).toBe("allow");
    });

    test("destatement returns reviewer info in DestatementInfo", () => {
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
        trusted_reviewers: { secbot: makeEntity(reviewerFp, "reviewer") },
      });
      const trust = makeTrust("alice", authorFp);
      const attestations = [
        makeAttestation("secbot", reviewerFp, {
          verdict: "reject",
          date: "2026-02-10",
          statement: "Critical vulnerability in dependency chain",
        }),
      ];

      const result = evaluatePolicy(store, trust, true, attestations);

      expect(result.scenario).toBe("trusted_reviewer_destatement");
      expect(result.destatement).toBeDefined();
      expect(result.destatement!.reviewer).toBe("secbot");
      expect(result.destatement!.date).toBe("2026-02-10");
      expect(result.destatement!.reason).toBe("Critical vulnerability in dependency chain");
    });
  });

  // -----------------------------------------------------------------------
  // Unknown author scenarios
  // -----------------------------------------------------------------------

  describe("unknown author scenarios", () => {
    const unknownFp = "FFFF9999FFFF9999FFFF9999FFFF9999FFFF9999";
    const reviewerFp = "RRRR4444RRRR4444RRRR4444RRRR4444RRRR4444";

    test("unknown author with no attestations returns unknown_author, prompt", () => {
      const store = makeStore();
      const trust = makeTrust("stranger", unknownFp);

      const result = evaluatePolicy(store, trust, true);

      expect(result.scenario).toBe("unknown_author");
      expect(result.action).toBe("prompt");
    });

    test("unknown author with trusted reviewer current attestation returns trusted_reviewer_attested, allow", () => {
      const store = makeStore({
        trusted_reviewers: { reviewer1: makeEntity(reviewerFp, "reviewer") },
      });
      const trust = makeTrust("stranger", unknownFp);
      const attestations = [
        makeAttestation("reviewer1", reviewerFp, { stale: false }),
      ];

      const result = evaluatePolicy(store, trust, true, attestations);

      expect(result.scenario).toBe("trusted_reviewer_attested");
      expect(result.action).toBe("allow");
    });

    test("unknown author with trusted reviewer stale attestation returns known_author_stale_attestations, prompt", () => {
      const store = makeStore({
        trusted_reviewers: { reviewer1: makeEntity(reviewerFp, "reviewer") },
      });
      const trust = makeTrust("stranger", unknownFp);
      const attestations = [
        makeAttestation("reviewer1", reviewerFp, { stale: true }),
      ];

      const result = evaluatePolicy(store, trust, true, attestations);

      expect(result.scenario).toBe("known_author_stale_attestations");
      expect(result.action).toBe("prompt");
    });

    test("unknown author with untrusted reviewer attestation returns unknown_author, prompt", () => {
      const untrustedReviewerFp = "UUUU8888UUUU8888UUUU8888UUUU8888UUUU8888";
      const store = makeStore();
      // No trusted reviewers in store
      const trust = makeTrust("stranger", unknownFp);
      const attestations = [
        makeAttestation("untrusted-reviewer", untrustedReviewerFp),
      ];

      const result = evaluatePolicy(store, trust, true, attestations);

      expect(result.scenario).toBe("unknown_author");
      expect(result.action).toBe("prompt");
    });
  });

  // -----------------------------------------------------------------------
  // Known author scenarios
  // -----------------------------------------------------------------------

  describe("known author scenarios", () => {
    const authorFp = "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111";
    const reviewerFp = "RRRR4444RRRR4444RRRR4444RRRR4444RRRR4444";

    test("known author with no attestations returns known_author_no_attestations, allow", () => {
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
      });
      const trust = makeTrust("alice", authorFp);

      const result = evaluatePolicy(store, trust, true);

      expect(result.scenario).toBe("known_author_no_attestations");
      expect(result.action).toBe("allow");
    });

    test("known author with no verified attestations array (undefined) returns known_author_no_attestations, allow", () => {
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
      });
      const trust = makeTrust("alice", authorFp);

      const result = evaluatePolicy(store, trust, true, undefined);

      expect(result.scenario).toBe("known_author_no_attestations");
      expect(result.action).toBe("allow");
    });

    test("known author with trusted reviewer current attestation returns trusted_reviewer_attested, allow", () => {
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
        trusted_reviewers: { reviewer1: makeEntity(reviewerFp, "reviewer") },
      });
      const trust = makeTrust("alice", authorFp);
      const attestations = [
        makeAttestation("reviewer1", reviewerFp, { stale: false }),
      ];

      const result = evaluatePolicy(store, trust, true, attestations);

      expect(result.scenario).toBe("trusted_reviewer_attested");
      expect(result.action).toBe("allow");
    });

    test("known author with trusted reviewer stale attestation returns known_author_stale_attestations, prompt", () => {
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
        trusted_reviewers: { reviewer1: makeEntity(reviewerFp, "reviewer") },
      });
      const trust = makeTrust("alice", authorFp);
      const attestations = [
        makeAttestation("reviewer1", reviewerFp, { stale: true }),
      ];

      const result = evaluatePolicy(store, trust, true, attestations);

      expect(result.scenario).toBe("known_author_stale_attestations");
      expect(result.action).toBe("prompt");
    });

    test("known author with untrusted reviewer attestation returns known_author_with_attestations, allow", () => {
      const untrustedReviewerFp = "UUUU8888UUUU8888UUUU8888UUUU8888UUUU8888";
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
        // No trusted reviewers
      });
      const trust = makeTrust("alice", authorFp);
      const attestations = [
        makeAttestation("untrusted-reviewer", untrustedReviewerFp),
      ];

      const result = evaluatePolicy(store, trust, true, attestations);

      expect(result.scenario).toBe("known_author_with_attestations");
      expect(result.action).toBe("allow");
    });

    test("known author with only reject attestations (all filtered) returns known_author_no_attestations, allow", () => {
      const untrustedReviewerFp = "UUUU8888UUUU8888UUUU8888UUUU8888UUUU8888";
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
        // reviewer is not trusted so destatement is ignored
      });
      const trust = makeTrust("alice", authorFp);
      const attestations = [
        makeAttestation("untrusted-reviewer", untrustedReviewerFp, { verdict: "reject" }),
      ];

      const result = evaluatePolicy(store, trust, true, attestations);

      // All attestations are reject (filtered from validApprovals), so zero valid approvals
      expect(result.scenario).toBe("known_author_no_attestations");
      expect(result.action).toBe("allow");
    });

    test("known author with TRUST.json attestations (legacy) from trusted reviewer returns trusted_reviewer_attested, allow", () => {
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
        trusted_reviewers: { reviewer1: makeEntity(reviewerFp, "reviewer") },
      });
      const trust: TrustJson = {
        schema_version: "0.2.0",
        author: {
          name: "Alice Author",
          github: "alice",
          keys: [{ type: "gpg", fingerprint: authorFp, key_url: "https://github.com/alice.gpg" }],
        },
        attestations: [
          {
            reviewer: "Reviewer One",
            github: "reviewer1",
            fingerprint: reviewerFp,
            date: "2026-01-10",
            scope: "full",
          },
        ],
      };

      // No verifiedAttestations passed — falls through to TRUST.json attestations path
      const result = evaluatePolicy(store, trust, true);

      expect(result.scenario).toBe("trusted_reviewer_attested");
      expect(result.action).toBe("allow");
    });

    test("known author with TRUST.json attestations (legacy) from untrusted reviewer returns known_author_with_attestations, allow", () => {
      const untrustedReviewerFp = "UUUU8888UUUU8888UUUU8888UUUU8888UUUU8888";
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
        // No trusted reviewers
      });
      const trust: TrustJson = {
        schema_version: "0.2.0",
        author: {
          name: "Alice Author",
          github: "alice",
          keys: [{ type: "gpg", fingerprint: authorFp, key_url: "https://github.com/alice.gpg" }],
        },
        attestations: [
          {
            reviewer: "Untrusted Reviewer",
            github: "untrusted-reviewer",
            fingerprint: untrustedReviewerFp,
            date: "2026-01-10",
            scope: "full",
          },
        ],
      };

      const result = evaluatePolicy(store, trust, true);

      expect(result.scenario).toBe("known_author_with_attestations");
      expect(result.action).toBe("allow");
    });

    test("known author with empty TRUST.json attestations returns known_author_no_attestations, allow", () => {
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
      });
      const trust: TrustJson = {
        schema_version: "0.2.0",
        author: {
          name: "Alice Author",
          github: "alice",
          keys: [{ type: "gpg", fingerprint: authorFp, key_url: "https://github.com/alice.gpg" }],
        },
        attestations: [],
      };

      // No verifiedAttestations — falls through to TRUST.json attestations which is empty
      const result = evaluatePolicy(store, trust, true);

      expect(result.scenario).toBe("known_author_no_attestations");
      expect(result.action).toBe("allow");
    });
  });

  // -----------------------------------------------------------------------
  // Custom policy scenarios
  // -----------------------------------------------------------------------

  describe("custom policy scenarios", () => {
    test("custom policy: unknown_author set to allow returns unknown_author, allow", () => {
      const store = makeStore({
        policies: {
          unsigned: "refuse",
          signature_invalid: "refuse",
          unknown_author: "allow",
          known_author_no_attestations: "allow",
          known_author_with_attestations: "allow",
          known_author_stale_attestations: "prompt",
          trusted_reviewer_attested: "allow",
          trusted_reviewer_destatement: "refuse",
        },
      });
      const trust = makeTrust("stranger", "FFFF9999FFFF9999FFFF9999FFFF9999FFFF9999");

      const result = evaluatePolicy(store, trust, true);

      expect(result.scenario).toBe("unknown_author");
      expect(result.action).toBe("allow");
    });

    test("custom policy: known_author_no_attestations set to refuse returns known_author_no_attestations, refuse", () => {
      const authorFp = "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111";
      const store = makeStore({
        trusted_authors: { alice: makeEntity(authorFp) },
        policies: {
          unsigned: "refuse",
          signature_invalid: "refuse",
          unknown_author: "prompt",
          known_author_no_attestations: "refuse",
          known_author_with_attestations: "allow",
          known_author_stale_attestations: "prompt",
          trusted_reviewer_attested: "allow",
          trusted_reviewer_destatement: "refuse",
        },
      });
      const trust = makeTrust("alice", authorFp);

      const result = evaluatePolicy(store, trust, true);

      expect(result.scenario).toBe("known_author_no_attestations");
      expect(result.action).toBe("refuse");
    });
  });
});
