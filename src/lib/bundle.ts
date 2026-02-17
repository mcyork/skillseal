// SkillSeal — trust bundle management
// Fetches, verifies, and applies community-curated trust bundles

import type { TrustStore, TrustedEntity } from "./trust";
import { getProvider } from "./providers";

export interface TrustBundleData {
  bundle: string;
  version: number;
  updated: string;
  trusted_authors: Record<string, TrustedEntity>;
  trusted_reviewers: Record<string, TrustedEntity>;
  revoked_fingerprints: string[];
}

const MAX_BUNDLE_SIZE = 256 * 1024;

export async function fetchBundle(
  source: string
): Promise<{ data: TrustBundleData; rawJson: string; signature: string }> {
  const baseUrl = `https://raw.githubusercontent.com/${source}/main`;
  const jsonUrl = `${baseUrl}/trust-bundle.json`;
  const sigUrl = `${baseUrl}/trust-bundle.json.sig`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);

  try {
    const [jsonResp, sigResp] = await Promise.all([
      fetch(jsonUrl, { signal: controller.signal }),
      fetch(sigUrl, { signal: controller.signal }),
    ]);

    if (!jsonResp.ok) {
      throw new Error(`Failed to fetch trust bundle from ${jsonUrl}: ${jsonResp.status}`);
    }
    if (!sigResp.ok) {
      throw new Error(`Failed to fetch bundle signature from ${sigUrl}: ${sigResp.status}`);
    }

    const rawJson = await jsonResp.text();
    if (rawJson.length > MAX_BUNDLE_SIZE) {
      throw new Error(`Bundle too large: ${rawJson.length} bytes (max ${MAX_BUNDLE_SIZE})`);
    }

    const signature = await sigResp.text();
    const data: TrustBundleData = JSON.parse(rawJson);

    return { data, rawJson, signature };
  } finally {
    clearTimeout(timeout);
  }
}

export async function verifyBundle(
  rawJson: string,
  signature: string,
  publisherGithub: string,
  store: TrustStore
): Promise<{ valid: boolean; errors: string[] }> {
  const errors: string[] = [];

  const publisherEntity =
    store.trusted_reviewers[publisherGithub] || store.trusted_authors[publisherGithub];

  if (!publisherEntity) {
    return {
      valid: false,
      errors: [`Bundle publisher "${publisherGithub}" is not in the local trust store`],
    };
  }

  for (const key of publisherEntity.keys) {
    const provider = getProvider(key.type);
    if (!provider) continue;

    try {
      const result = await provider.verifyContent(
        rawJson,
        signature,
        publisherGithub,
        key.fingerprint
      );
      if (result.valid) {
        return { valid: true, errors: [] };
      }
      for (const err of result.errors) {
        errors.push(err);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`${key.type} bundle verification: ${msg}`);
    }
  }

  return { valid: false, errors };
}

export function applyBundle(data: TrustBundleData, store: TrustStore): {
  addedAuthors: number;
  addedReviewers: number;
  revokedKeys: number;
} {
  let addedAuthors = 0;
  let addedReviewers = 0;
  let revokedKeys = 0;

  for (const [github, entity] of Object.entries(data.trusted_authors)) {
    if (!store.trusted_authors[github]) {
      store.trusted_authors[github] = entity;
      addedAuthors++;
    }
  }

  for (const [github, entity] of Object.entries(data.trusted_reviewers)) {
    if (!store.trusted_reviewers[github]) {
      store.trusted_reviewers[github] = entity;
      addedReviewers++;
    }
  }

  if (data.revoked_fingerprints && data.revoked_fingerprints.length > 0) {
    const revokedSet = new Set(
      data.revoked_fingerprints.map((fp) => fp.toUpperCase().replace(/\s/g, ""))
    );

    for (const entities of [store.trusted_authors, store.trusted_reviewers]) {
      for (const [github, entity] of Object.entries(entities)) {
        const beforeLen = entity.keys.length;
        entity.keys = entity.keys.filter(
          (k) => !revokedSet.has(k.fingerprint.toUpperCase().replace(/\s/g, ""))
        );
        revokedKeys += beforeLen - entity.keys.length;

        if (entity.keys.length === 0) {
          delete entities[github];
        }
      }
    }
  }

  return { addedAuthors, addedReviewers, revokedKeys };
}
