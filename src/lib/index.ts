// SkillSeal shared library — re-exports all modules

export { generateManifest, writeManifest, hashManifest, verifyManifest } from "./manifest";
export type { ManifestData } from "./manifest";

export { signSkill, getSigningFingerprint, getKeyUid, isCacheWarm, clearCache, signFile, verifyFileSignature } from "./sign";
export type { SignResult } from "./sign";

export { fetchGitHubKey, verifySkill } from "./verify";
export type { TrustJson, VerifyResult, VerifyOptions } from "./verify";

export {
  loadTrustStore,
  saveTrustStore,
  isAuthorTrusted,
  isReviewerTrusted,
  evaluatePolicy,
} from "./trust";
export type { TrustStore, TrustedEntity, PolicyAction, PolicyScenario } from "./trust";

export { loadConfig } from "./config";
export type { SkillSealConfig } from "./config";

export {
  canonicalJsonStringify,
  createAttestationStatement,
  signAttestation,
  packageAttestationBundle,
  parseAttestationBundle,
  verifyAttestationBundle,
  discoverLocalAttestations,
  fetchAttestationFromUrl,
  probeReviewerRepo,
  discoverAttestations,
} from "./attest";
export type {
  AttestationScope,
  AttestationSubject,
  AttestationReviewer,
  AttestationStatement,
  AttestationBundle,
  AttestationResult,
  DiscoverOptions,
} from "./attest";
