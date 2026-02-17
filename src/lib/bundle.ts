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

  // Persist revoked fingerprints in the store
  if (!store.revoked_fingerprints) store.revoked_fingerprints = [];
  if (data.revoked_fingerprints) {
    for (const fp of data.revoked_fingerprints) {
      const normalized = fp.toUpperCase().replace(/\s/g, "");
      if (!store.revoked_fingerprints.includes(normalized)) {
        store.revoked_fingerprints.push(normalized);
      }
    }
  }

  // Merge authors — add new keys, filter out revoked
  for (const [github, entity] of Object.entries(data.trusted_authors)) {
    // Filter out revoked keys before adding
    entity.keys = entity.keys.filter(
      (k) => !store.revoked_fingerprints!.includes(k.fingerprint.toUpperCase().replace(/\s/g, ""))
    );

    if (store.trusted_authors[github]) {
      // Merge: add any new keys not already present
      const existing = store.trusted_authors[github];
      for (const newKey of entity.keys) {
        const normalized = newKey.fingerprint.toUpperCase().replace(/\s/g, "");
        const exists = existing.keys.some(
          (k) => k.fingerprint.toUpperCase().replace(/\s/g, "") === normalized
        );
        if (!exists) {
          existing.keys.push(newKey);
        }
      }
    } else if (entity.keys.length > 0) {
      store.trusted_authors[github] = entity;
      addedAuthors++;
    }
  }

  // Merge reviewers — add new keys, filter out revoked
  for (const [github, entity] of Object.entries(data.trusted_reviewers)) {
    entity.keys = entity.keys.filter(
      (k) => !store.revoked_fingerprints!.includes(k.fingerprint.toUpperCase().replace(/\s/g, ""))
    );

    if (store.trusted_reviewers[github]) {
      const existing = store.trusted_reviewers[github];
      for (const newKey of entity.keys) {
        const normalized = newKey.fingerprint.toUpperCase().replace(/\s/g, "");
        const exists = existing.keys.some(
          (k) => k.fingerprint.toUpperCase().replace(/\s/g, "") === normalized
        );
        if (!exists) {
          existing.keys.push(newKey);
        }
      }
    } else if (entity.keys.length > 0) {
      store.trusted_reviewers[github] = entity;
      addedReviewers++;
    }
  }

  // Revoke keys from existing store entries
  if (store.revoked_fingerprints.length > 0) {
    const revokedSet = new Set(store.revoked_fingerprints);

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
