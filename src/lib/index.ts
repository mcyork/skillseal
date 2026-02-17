// SkillSeal shared library — re-exports all modules

export { generateManifest, writeManifest, hashManifest, verifyManifest, isPlugin } from "./manifest";
export type { ManifestData } from "./manifest";

export { signSkill, signPlugin, getKeyUid } from "./sign";
export type { SignResult } from "./sign";

export { verifySkill, verifyPlugin } from "./verify";
export type { TrustJson, TrustJsonKey, VerifyResult, VerifyOptions, PluginVerifyResult } from "./verify";

export {
  loadTrustStore,
  saveTrustStore,
  isAuthorTrusted,
  isReviewerTrusted,
  evaluatePolicy,
} from "./trust";
export type { TrustStore, TrustedEntity, TrustedEntityKey, TrustStoreOverride, BundleSubscription, PolicyAction, PolicyScenario, DestatementInfo } from "./trust";

export { readCache, writeCache } from "./cache";
export type { CacheKeyType } from "./cache";

export { loadConfig, getConfigKeys, getConfigKeysByType } from "./config";
export type { SkillSealConfig, KeyConfig } from "./config";

export {
  registerProvider,
  getProvider,
  getAllProviders,
  getProviderTypes,
  detectProvider,
  fetchGitHubSSHSigningKeys,
  fetchGitHubGPGKey,
  validateSSHKeyStrength,
} from "./providers";
export type { SigningProvider, GitHubSSHSigningKey, SSHKeyStrength } from "./providers";

export {
  canonicalJsonStringify,
  createAttestationStatement,
  signAttestationMulti,
  packageAttestationBundle,
  parseAttestationBundle,
  verifyAttestationBundle,
  discoverLocalAttestations,
  fetchAttestationFromUrl,
  probeReviewerRepo,
  probeAttestationLiveness,
  discoverAttestations,
} from "./attest";

export { fetchBundle, verifyBundle, applyBundle } from "./bundle";
export type { TrustBundleData } from "./bundle";

export type {
  AttestationScope,
  AttestationSubject,
  AttestationReviewer,
  AttestationStatement,
  AttestationSignature,
  AttestationBundle,
  AttestationResult,
  DiscoverOptions,
} from "./attest";
