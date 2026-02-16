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
export type { TrustStore, TrustedEntity, TrustedEntityKey, PolicyAction, PolicyScenario } from "./trust";

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
  discoverAttestations,
} from "./attest";
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
