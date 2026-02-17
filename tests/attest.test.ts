// SkillSeal attestation parsing and validation tests
// Tests canonicalJsonStringify, parseAttestationBundle, and bundle validation

import { test, expect, describe } from "bun:test";
import { canonicalJsonStringify, parseAttestationBundle } from "../src/lib/attest";

// ---------------------------------------------------------------------------
// Helper: build a structurally valid attestation bundle object
// ---------------------------------------------------------------------------

interface DeepPartial<T> {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
}

function makeValidBundleObj(overrides?: DeepPartial<Record<string, unknown>>): Record<string, unknown> {
  const base: Record<string, unknown> = {
    schema_version: "0.2.0",
    format: "skillseal-attestation-bundle/v1",
    statement: {
      type: "https://skillseal.dev/attestation/review/v1",
      subject: {
        skill: "example-skill",
        version: "1.0.0",
        signed: true,
        repository: "github.com/test-org/test-skill",
        commit: "abc123def456",
        digests: {
          skill_md_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          manifest_sha256: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        },
      },
      reviewer: {
        name: "Test Reviewer",
        github: "test-reviewer",
        fingerprint: "ABCD1234EFGH5678",
      },
      attestation: {
        scope: "full-review",
        statement: "Reviewed and found no issues.",
        date: "2026-01-15T12:00:00.000Z",
      },
    },
    signatures: [
      { type: "gpg", value: "-----BEGIN PGP SIGNATURE-----\nfakesig\n-----END PGP SIGNATURE-----" },
    ],
  };

  if (overrides) {
    return deepMerge(base, overrides);
  }
  return base;
}

function deepMerge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    const srcVal = source[key];
    const tgtVal = result[key];
    if (
      srcVal !== null &&
      typeof srcVal === "object" &&
      !Array.isArray(srcVal) &&
      tgtVal !== null &&
      typeof tgtVal === "object" &&
      !Array.isArray(tgtVal)
    ) {
      result[key] = deepMerge(
        tgtVal as Record<string, unknown>,
        srcVal as Record<string, unknown>,
      );
    } else {
      result[key] = srcVal;
    }
  }
  return result;
}

/** Serialize a valid bundle to JSON string, with optional overrides applied first. */
function makeValidBundle(overrides?: DeepPartial<Record<string, unknown>>): string {
  return JSON.stringify(makeValidBundleObj(overrides), null, 2);
}

/**
 * Build a bundle JSON string, then delete a nested key path from the parsed object
 * before re-serializing. Useful for "missing field" negative tests.
 */
function makeBundleWithout(...keyPath: string[]): string {
  const obj = makeValidBundleObj();
  let cursor: Record<string, unknown> = obj;
  for (let i = 0; i < keyPath.length - 1; i++) {
    cursor = cursor[keyPath[i]] as Record<string, unknown>;
  }
  delete cursor[keyPath[keyPath.length - 1]];
  return JSON.stringify(obj, null, 2);
}

/**
 * Build a bundle JSON string, then set a nested key path to a specific value.
 * Useful for "wrong value" negative tests.
 */
function makeBundleWith(keyPath: string[], value: unknown): string {
  const obj = makeValidBundleObj();
  let cursor: Record<string, unknown> = obj;
  for (let i = 0; i < keyPath.length - 1; i++) {
    cursor = cursor[keyPath[i]] as Record<string, unknown>;
  }
  cursor[keyPath[keyPath.length - 1]] = value;
  return JSON.stringify(obj, null, 2);
}

// ===========================================================================
// canonicalJsonStringify
// ===========================================================================

describe("canonicalJsonStringify", () => {
  test("sorts object keys alphabetically", () => {
    const input = { zebra: 1, apple: 2, mango: 3 };
    const result = canonicalJsonStringify(input);
    const parsed = JSON.parse(result);
    const keys = Object.keys(parsed);
    expect(keys).toEqual(["apple", "mango", "zebra"]);
  });

  test("sorts nested object keys recursively", () => {
    const input = {
      outer: {
        zz: 1,
        aa: 2,
        inner: {
          cc: 3,
          bb: 4,
        },
      },
      first: "value",
    };
    const result = canonicalJsonStringify(input);
    // Verify structure ordering by checking substring positions
    const firstIdx = result.indexOf('"first"');
    const outerIdx = result.indexOf('"outer"');
    expect(firstIdx).toBeLessThan(outerIdx);

    const aaIdx = result.indexOf('"aa"');
    const zzIdx = result.indexOf('"zz"');
    expect(aaIdx).toBeLessThan(zzIdx);

    const bbIdx = result.indexOf('"bb"');
    const ccIdx = result.indexOf('"cc"');
    expect(bbIdx).toBeLessThan(ccIdx);
  });

  test("preserves array order (arrays are NOT sorted)", () => {
    const input = { items: [3, 1, 2], names: ["charlie", "alice", "bob"] };
    const result = canonicalJsonStringify(input);
    const parsed = JSON.parse(result);
    expect(parsed.items).toEqual([3, 1, 2]);
    expect(parsed.names).toEqual(["charlie", "alice", "bob"]);
  });

  test("uses 2-space indentation", () => {
    const input = { a: { b: 1 } };
    const result = canonicalJsonStringify(input);
    const lines = result.split("\n");
    // Line 0: {
    // Line 1:   "a": {          <- 2 spaces
    // Line 2:     "b": 1        <- 4 spaces
    // Line 3:   }               <- 2 spaces
    // Line 4: }
    expect(lines[1]).toMatch(/^ {2}"/);
    expect(lines[2]).toMatch(/^ {4}"/);
  });

  test("appends trailing newline", () => {
    const input = { key: "value" };
    const result = canonicalJsonStringify(input);
    expect(result.endsWith("\n")).toBe(true);
    // Ensure it's exactly one trailing newline, not two
    expect(result.endsWith("\n\n")).toBe(false);
  });

  test("produces deterministic output for same input regardless of key insertion order", () => {
    const obj1: Record<string, unknown> = {};
    obj1.z = 1;
    obj1.a = 2;
    obj1.m = 3;

    const obj2: Record<string, unknown> = {};
    obj2.a = 2;
    obj2.m = 3;
    obj2.z = 1;

    const obj3: Record<string, unknown> = {};
    obj3.m = 3;
    obj3.z = 1;
    obj3.a = 2;

    const r1 = canonicalJsonStringify(obj1);
    const r2 = canonicalJsonStringify(obj2);
    const r3 = canonicalJsonStringify(obj3);

    expect(r1).toBe(r2);
    expect(r2).toBe(r3);
  });

  test("handles null values correctly", () => {
    const input = { a: null, b: 1, c: null };
    const result = canonicalJsonStringify(input);
    const parsed = JSON.parse(result);
    expect(parsed.a).toBeNull();
    expect(parsed.c).toBeNull();
    // Keys should still be sorted
    const keys = Object.keys(parsed);
    expect(keys).toEqual(["a", "b", "c"]);
  });

  test("handles empty objects", () => {
    const result = canonicalJsonStringify({});
    expect(result).toBe("{}\n");
  });

  test("handles deeply nested structures", () => {
    const input = {
      level1: {
        z: {
          level3: {
            b: "deep",
            a: "value",
          },
        },
        a: {
          level3: {
            y: [1, 2, 3],
            x: "leaf",
          },
        },
      },
    };
    const result = canonicalJsonStringify(input);
    const parsed = JSON.parse(result);

    // Verify nested key ordering
    const level1Keys = Object.keys(parsed.level1);
    expect(level1Keys).toEqual(["a", "z"]);

    const innerAKeys = Object.keys(parsed.level1.a.level3);
    expect(innerAKeys).toEqual(["x", "y"]);

    const innerZKeys = Object.keys(parsed.level1.z.level3);
    expect(innerZKeys).toEqual(["a", "b"]);

    // Array preserved
    expect(parsed.level1.a.level3.y).toEqual([1, 2, 3]);
  });
});

// ===========================================================================
// parseAttestationBundle — valid bundles
// ===========================================================================

describe("parseAttestationBundle", () => {
  describe("valid bundles", () => {
    test("parses a valid attestation bundle with all fields", () => {
      const json = makeValidBundle();
      const bundle = parseAttestationBundle(json);

      expect(bundle.schema_version).toBe("0.2.0");
      expect(bundle.format).toBe("skillseal-attestation-bundle/v1");
      expect(bundle.statement.type).toBe("https://skillseal.dev/attestation/review/v1");
      expect(bundle.statement.subject.skill).toBe("example-skill");
      expect(bundle.statement.subject.version).toBe("1.0.0");
      expect(bundle.statement.subject.signed).toBe(true);
      expect(bundle.statement.subject.repository).toBe("github.com/test-org/test-skill");
      expect(bundle.statement.subject.commit).toBe("abc123def456");
      expect(bundle.statement.subject.digests.skill_md_sha256).toBe(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      );
      expect(bundle.statement.subject.digests.manifest_sha256).toBe(
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
      );
      expect(bundle.statement.reviewer.name).toBe("Test Reviewer");
      expect(bundle.statement.reviewer.github).toBe("test-reviewer");
      expect(bundle.statement.reviewer.fingerprint).toBe("ABCD1234EFGH5678");
      expect(bundle.statement.attestation.scope).toBe("full-review");
      expect(bundle.statement.attestation.statement).toBe("Reviewed and found no issues.");
      expect(bundle.statement.attestation.date).toBe("2026-01-15T12:00:00.000Z");
      expect(bundle.signatures).toHaveLength(1);
      expect(bundle.signatures[0].type).toBe("gpg");
    });

    test("parses a bundle with verdict: 'approve'", () => {
      const json = makeBundleWith(["statement", "attestation", "verdict"], "approve");
      const bundle = parseAttestationBundle(json);
      expect(bundle.statement.attestation.verdict).toBe("approve");
    });

    test("parses a bundle with verdict: 'reject' (destatement)", () => {
      const json = makeBundleWith(["statement", "attestation", "verdict"], "reject");
      const bundle = parseAttestationBundle(json);
      expect(bundle.statement.attestation.verdict).toBe("reject");
    });

    test("parses a bundle without verdict field (backwards compatible)", () => {
      // Default makeValidBundle has no verdict
      const json = makeValidBundle();
      const bundle = parseAttestationBundle(json);
      expect(bundle.statement.attestation.verdict).toBeUndefined();
    });

    test("accepts schema version 0.2.0", () => {
      const json = makeBundleWith(["schema_version"], "0.2.0");
      const bundle = parseAttestationBundle(json);
      expect(bundle.schema_version).toBe("0.2.0");
    });

    test("accepts schema version 0.2.5", () => {
      const json = makeBundleWith(["schema_version"], "0.2.5");
      const bundle = parseAttestationBundle(json);
      // The parser casts to AttestationBundle; the version string is preserved as-is
      expect((bundle as Record<string, unknown>).schema_version).toBe("0.2.5");
    });

    test("accepts schema version 0.2.9 (any 0.2.x)", () => {
      const json = makeBundleWith(["schema_version"], "0.2.9");
      const bundle = parseAttestationBundle(json);
      expect((bundle as Record<string, unknown>).schema_version).toBe("0.2.9");
    });
  });

  // =========================================================================
  // parseAttestationBundle — invalid bundles: format errors
  // =========================================================================

  describe("invalid bundles — format errors", () => {
    test("throws on invalid JSON", () => {
      expect(() => parseAttestationBundle("{not valid json}")).toThrow(
        "Attestation bundle is not valid JSON",
      );
    });

    test("throws on wrong format string", () => {
      const json = makeBundleWith(["format"], "some-other-format/v2");
      expect(() => parseAttestationBundle(json)).toThrow("Unknown attestation format");
    });

    test("throws on schema version 0.1.0 (too old)", () => {
      const json = makeBundleWith(["schema_version"], "0.1.0");
      expect(() => parseAttestationBundle(json)).toThrow("Incompatible schema version");
    });

    test("throws on schema version 0.1.9 (too old)", () => {
      const json = makeBundleWith(["schema_version"], "0.1.9");
      expect(() => parseAttestationBundle(json)).toThrow("Incompatible schema version");
    });

    test("throws on missing statement", () => {
      const json = makeBundleWithout("statement");
      expect(() => parseAttestationBundle(json)).toThrow("Missing statement");
    });

    test("throws on wrong attestation type", () => {
      const json = makeBundleWith(
        ["statement", "type"],
        "https://example.com/wrong-type/v1",
      );
      expect(() => parseAttestationBundle(json)).toThrow("Unknown attestation type");
    });

    test("throws on missing subject", () => {
      const json = makeBundleWith(["statement", "subject"], undefined);
      // When subject is undefined, the subject check triggers
      // We need to actually remove it
      const obj = makeValidBundleObj();
      delete (obj.statement as Record<string, unknown>).subject;
      const raw = JSON.stringify(obj, null, 2);
      expect(() => parseAttestationBundle(raw)).toThrow("Missing required subject fields");
    });

    test("throws on missing subject.skill", () => {
      const obj = makeValidBundleObj();
      const subject = (obj.statement as Record<string, unknown>).subject as Record<string, unknown>;
      delete subject.skill;
      const json = JSON.stringify(obj, null, 2);
      expect(() => parseAttestationBundle(json)).toThrow("Missing required subject fields");
    });

    test("throws on missing subject.digests", () => {
      const obj = makeValidBundleObj();
      const subject = (obj.statement as Record<string, unknown>).subject as Record<string, unknown>;
      delete subject.digests;
      const json = JSON.stringify(obj, null, 2);
      expect(() => parseAttestationBundle(json)).toThrow("Missing required subject fields");
    });

    test("throws on missing digests.skill_md_sha256", () => {
      const obj = makeValidBundleObj();
      const subject = (obj.statement as Record<string, unknown>).subject as Record<string, unknown>;
      const digests = subject.digests as Record<string, unknown>;
      delete digests.skill_md_sha256;
      const json = JSON.stringify(obj, null, 2);
      expect(() => parseAttestationBundle(json)).toThrow("Missing required digest field: skill_md_sha256");
    });

    test("throws on missing reviewer", () => {
      const obj = makeValidBundleObj();
      delete (obj.statement as Record<string, unknown>).reviewer;
      const json = JSON.stringify(obj, null, 2);
      expect(() => parseAttestationBundle(json)).toThrow("Missing required reviewer fields");
    });

    test("throws on missing reviewer.github", () => {
      const obj = makeValidBundleObj();
      const reviewer = ((obj.statement as Record<string, unknown>).reviewer) as Record<string, unknown>;
      delete reviewer.github;
      const json = JSON.stringify(obj, null, 2);
      expect(() => parseAttestationBundle(json)).toThrow("Missing required reviewer fields");
    });

    test("throws on missing reviewer.fingerprint", () => {
      const obj = makeValidBundleObj();
      const reviewer = ((obj.statement as Record<string, unknown>).reviewer) as Record<string, unknown>;
      delete reviewer.fingerprint;
      const json = JSON.stringify(obj, null, 2);
      expect(() => parseAttestationBundle(json)).toThrow("Missing required reviewer fields");
    });

    test("throws on missing attestation object", () => {
      const obj = makeValidBundleObj();
      delete (obj.statement as Record<string, unknown>).attestation;
      const json = JSON.stringify(obj, null, 2);
      expect(() => parseAttestationBundle(json)).toThrow("Missing required attestation fields");
    });

    test("throws on missing attestation.scope", () => {
      const obj = makeValidBundleObj();
      const attestation = ((obj.statement as Record<string, unknown>).attestation) as Record<string, unknown>;
      delete attestation.scope;
      const json = JSON.stringify(obj, null, 2);
      expect(() => parseAttestationBundle(json)).toThrow("Missing required attestation fields");
    });

    test("throws on missing attestation.date", () => {
      const obj = makeValidBundleObj();
      const attestation = ((obj.statement as Record<string, unknown>).attestation) as Record<string, unknown>;
      delete attestation.date;
      const json = JSON.stringify(obj, null, 2);
      expect(() => parseAttestationBundle(json)).toThrow("Missing required attestation fields");
    });

    test("throws on invalid scope value", () => {
      const json = makeBundleWith(["statement", "attestation", "scope"], "casual-glance");
      expect(() => parseAttestationBundle(json)).toThrow("Invalid attestation scope");
    });

    test("throws on invalid verdict value (not 'approve' or 'reject')", () => {
      const json = makeBundleWith(["statement", "attestation", "verdict"], "maybe");
      expect(() => parseAttestationBundle(json)).toThrow("Invalid attestation verdict");
    });

    test("throws on empty signatures array", () => {
      const json = makeBundleWith(["signatures"], []);
      expect(() => parseAttestationBundle(json)).toThrow("Missing or empty signatures array");
    });

    test("throws on missing signatures array", () => {
      const json = makeBundleWithout("signatures");
      expect(() => parseAttestationBundle(json)).toThrow("Missing or empty signatures array");
    });

    test("throws on signature missing type", () => {
      const json = makeBundleWith(["signatures"], [{ value: "sig-data" }]);
      expect(() => parseAttestationBundle(json)).toThrow("Each signature must have a 'type' string field");
    });

    test("throws on signature missing value", () => {
      const json = makeBundleWith(["signatures"], [{ type: "gpg" }]);
      expect(() => parseAttestationBundle(json)).toThrow("Each signature must have a 'value' string field");
    });
  });
});
