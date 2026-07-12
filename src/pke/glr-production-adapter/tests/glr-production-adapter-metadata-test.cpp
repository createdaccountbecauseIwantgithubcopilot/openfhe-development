#include "openfhe/pke/glr-production-adapter.h"

#include <bit>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <numeric>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace {

void Require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

template <typename T>
concept HasResidentDftBank = requires(T value) { value.dftBank; };

template <typename T>
concept HasAuthorizationToken = requires(T value) { value.authorization; };

glscheme::SecurityReport MakeGl128CorridorReport(
    const glscheme::rns::GlrParams& params,
    std::uint32_t sparseHammingWeight,
    const std::string& supportCommitment) {
    glscheme::SecurityReport report;
    report.valid = true;
    report.production_safe = true;
    report.fallback_advisory = false;
    report.prime_congruence_ok = true;
    report.ring_dimension = std::uint64_t{2} * params.coeffs_R();
    report.target_security_bits = 128;
    report.estimated_security_bits = 137.64699816982164;
    report.error_sigma = 3.2;
    report.estimator_name = "lattice-estimator";
    report.estimator_commit =
        glscheme::production_security_estimator_commit();
    report.estimator_backend = "sage";
    report.secret_distribution =
        "sparse-ternary(h=" + std::to_string(sparseHammingWeight) + ")";
    report.security_model = "classical";
    report.estimator_transcript_sha256 =
        "98cba6bc908df1855ce2c00527035c6d4813bb5128a578e7c94f87b9cfcc3878";
    report.q_bits = 678;
    report.extended_q_bits = 1056;
    report.parameter_fingerprint =
        glscheme::rns::glr_parameter_fingerprint(params);
    report.estimator_input_parameter_fingerprint =
        report.parameter_fingerprint;
    report.bootstrap_profile_fingerprint =
        glscheme::rns::glr_bootstrap_profile_fingerprint(
            params, sparseHammingWeight, supportCommitment);
    report.estimator_input_bootstrap_profile_fingerprint =
        report.bootstrap_profile_fingerprint;
    for (std::size_t i = 0; i < 7; ++i) {
        report.sparse_exposure_q_primes.push_back(params.q_chain[i].q);
    }
    for (const auto& modulus : params.p_special) {
        report.sparse_exposure_q_primes.push_back(modulus.q);
    }
    for (const std::uint64_t prime : report.sparse_exposure_q_primes) {
        report.sparse_estimate_modulus_bits +=
            std::log2(static_cast<double>(prime));
    }
    return report;
}

lbcrypto::GLRProductionAdapter::
    NativeDirectVectorDensePrimarySecurityEvidence
MakeDensePrimarySecurityEvidence() {
    using Adapter = lbcrypto::GLRProductionAdapter;
    Adapter::NativeDirectVectorDensePrimarySecurityEvidence evidence;
    evidence.transcript_artifact =
        glscheme::rns::kGlrShipDirectVectorGl128DenseTranscriptArtifact;
    evidence.transcript_sha256 =
        glscheme::rns::kGlrShipDirectVectorGl128DenseTranscriptSha256;
    evidence.estimator_name = "malb/lattice-estimator";
    evidence.estimator_commit =
        glscheme::rns::kGlrShipDirectVectorGl128EstimatorCommit;
    evidence.estimator_backend = "sage";
    evidence.security_model = "classical";
    evidence.secret_distribution = "ternary";
    evidence.estimated_security_bits =
        glscheme::rns::kGlrShipDirectVectorGl128DensePrimarySecurityBits;
    evidence.ring_dimension = 65536;
    evidence.q_bits = 678;
    evidence.qp_bits = 1056;
    return evidence;
}

double ExpectedH2DirectOutputScale(
    const glscheme::rns::GlrContext& context) {
    double leafScale = context.params.delta * context.params.delta;
    for (std::uint32_t step = 0; step < 2; ++step) {
        leafScale /= static_cast<double>(
            context.modulus_at(context.active_q_primes(4 + step) - 1).q);
    }
    double outputScale = leafScale * leafScale;
    for (std::uint32_t step = 0; step < 2; ++step) {
        outputScale /= static_cast<double>(
            context.modulus_at(context.active_q_primes(6 + step) - 1).q);
    }
    return outputScale;
}

lbcrypto::GLRProductionAdapter::NativeDirectVectorEvidence
MakeH2DirectEvidence(const glscheme::rns::GlrContext& context) {
    using Evidence =
        lbcrypto::GLRProductionAdapter::NativeDirectVectorEvidence;
    Evidence evidence;
    evidence.insecure_toy_only = true;
    evidence.evaluator_secret_free = true;
    evidence.all_xw_coefficients_simultaneous = true;
    evidence.simultaneous_x_i_wrap_w_phi_table_covered = true;
    evidence.randomized_nonzero_a = true;
    evidence.logical_slots = 32768;
    evidence.scalar_center_refreshes = 0;
    evidence.selector_ciphertexts_visited = 8;
    evidence.selector_provider_leases = 8;
    evidence.selector_window_count = 2;
    evidence.unsigned_selector_candidates = 2;
    evidence.selector_manifest_authenticated = true;
    evidence.selector_provider_secret_free = true;
    evidence.plaintext_ciphertext_products = 8;
    evidence.leaf_rescales = 4;
    evidence.tree_product_nodes = 2;
    evidence.tree_relinearizations = 2;
    evidence.tree_relinearization_key_provider_leases = 2;
    evidence.tree_carry_level_alignments = 0;
    evidence.tree_rescales = 2;
    evidence.conjugation_key_switches = 2;
    evidence.multiplicative_depth = 2;
    evidence.selector_level = 4;
    evidence.rescale_stride = 2;
    evidence.physical_q_prime_drops = 4;
    evidence.output_level = 8;
    evidence.output_scale = ExpectedH2DirectOutputScale(context);
    return evidence;
}

// Allocation-light non-owning placeholder used only to prove that malformed
// execution material is rejected before the input ciphertext or any streamed
// pair is consumed.  It is intentionally not a valid gadget opening.
class MetadataOnlyGadgetProvider final
    : public glscheme::rns::GlrShipGadgetProvider {
public:
    const glscheme::rns::GlrShipGadgetManifest& manifest()
        const noexcept override {
        return manifest_;
    }

    glscheme::rns::GlrShipGadgetMaterialPolicy policy()
        const noexcept override {
        return glscheme::rns::GlrShipGadgetMaterialPolicy::
            owner_authored_immutable;
    }

    bool secret_material_accessed() const noexcept override { return false; }

    void visit_pair(
        std::size_t,
        const glscheme::rns::GlrShipGadgetPairVisitor&) const override {
        throw glscheme::rns::GlrError(
            "metadata-only gadget provider must never lease a pair");
    }

private:
    glscheme::rns::GlrShipGadgetManifest manifest_;
};

// Authenticated manifest-only DFT provider used to prove the OpenFHE seam
// accepts the new typed streamed endpoint without allocating the production
// plaintext payload.  Any attempted lease still fails closed.
class MetadataOnlyDftProvider final
    : public glscheme::rns::GlrDftPlaintextProvider {
public:
    explicit MetadataOnlyDftProvider(
        glscheme::rns::GlrDftPlaintextManifest manifest)
        : manifest_(std::move(manifest)) {}

    const glscheme::rns::GlrDftPlaintextManifest& manifest()
        const noexcept override {
        return manifest_;
    }

    glscheme::rns::GlrDftPlaintextMaterialPolicy policy()
        const noexcept override {
        return glscheme::rns::GlrDftPlaintextMaterialPolicy::
            owner_authored_immutable;
    }

    bool secret_material_accessed() const noexcept override { return false; }

    void visit_plaintext(
        glscheme::rns::GlrDftPlaintextKind,
        const glscheme::rns::GlrDftPlaintextVisitor&) const override {
        throw glscheme::rns::GlrError(
            "metadata-only DFT provider must never lease a plaintext");
    }

private:
    glscheme::rns::GlrDftPlaintextManifest manifest_;
};

glscheme::rns::GlrDftPlaintextManifest MakeMetadataDftManifest(
    const glscheme::rns::GlrContext& context,
    std::uint32_t level,
    double scale) {
    auto census = glscheme::rns::glr_model_dft_plaintext_streaming_bytes(
        context.params, level);
    glscheme::rns::GlrDftPlaintextManifest manifest;
    manifest.parameter_fingerprint =
        glscheme::rns::glr_parameter_fingerprint(context.params);
    manifest.entries.reserve(census.entries.size());
    for (std::size_t i = 0; i < census.entries.size(); ++i) {
        const auto& modeled = census.entries[i];
        glscheme::rns::GlrDftPlaintextManifestEntry entry;
        entry.kind = modeled.kind;
        entry.ring = modeled.ring;
        entry.domain = glscheme::rns::GlrDomain::Slot;
        entry.plaintext_level = level;
        entry.poly_level = level;
        entry.extended = false;
        entry.scale_bits = std::bit_cast<std::uint64_t>(scale);
        entry.residue_word_count = modeled.residue_word_count;
        entry.residue_bytes = modeled.residue_bytes;
        entry.plaintext_commitment =
            "sha256:" + std::string(64, static_cast<char>('a' + i));
        manifest.entries.push_back(std::move(entry));
    }
    manifest.manifest_commitment =
        glscheme::rns::glr_dft_plaintext_manifest_commitment(manifest);
    return manifest;
}

}  // namespace

int main() {
    using Adapter = lbcrypto::GLRProductionAdapter;
    using glscheme::production::LayoutKind;

    static_assert(std::is_same_v<Adapter::Context, glscheme::rns::GlrContext>);
    static_assert(
        std::is_same_v<Adapter::Ciphertext, glscheme::rns::GlrCiphertext>);
    static_assert(
        std::is_same_v<Adapter::PublicKey, glscheme::rns::GlrPublicKey>);
    static_assert(!std::is_copy_constructible_v<Adapter>);
    static_assert(!std::is_copy_constructible_v<Adapter::EvaluationKeys>);
    static_assert(std::is_trivially_copyable_v<
                  Adapter::FixedProfileBindingText>);
    static_assert(std::is_trivially_copyable_v<
                  Adapter::RefreshTraceKeyEntry>);
    static_assert(std::is_trivially_copyable_v<
                  Adapter::RefreshKeyLevelByteModel>);
    static_assert(std::is_trivially_copyable_v<
                  Adapter::NativeRefreshEndpointPreflight>);
    static_assert(std::is_trivially_copyable_v<
                  Adapter::OrdinaryRefreshPreflight>);
    static_assert(std::is_trivially_copyable_v<
                  Adapter::NativeRefreshAllYProductionReceipt>);
    static_assert(std::is_trivially_copyable_v<
                  Adapter::OrdinaryRefreshAuthorization>);
    static_assert(std::is_aggregate_v<
                  Adapter::OrdinaryRefreshExecutionMaterialView>);
    static_assert(std::is_trivially_copyable_v<
                  Adapter::OrdinaryRefreshExecutionMaterialView>);
    using ExecutionMaterial =
        Adapter::OrdinaryRefreshExecutionMaterialView;
    static_assert(!HasResidentDftBank<ExecutionMaterial>);
    static_assert(!HasAuthorizationToken<ExecutionMaterial>);
    static_assert(sizeof(ExecutionMaterial) == 9 * sizeof(const void*));
    static_assert(std::is_same_v<
                  decltype(std::declval<ExecutionMaterial>().keyProvider),
                  const Adapter::NativeKeyProvider*>);
    static_assert(std::is_same_v<
                  decltype(std::declval<ExecutionMaterial>().keyBinding),
                  const Adapter::NativeLeasedKeyBinding*>);
    static_assert(std::is_same_v<
                  decltype(std::declval<ExecutionMaterial>().dftProvider),
                  const Adapter::NativeRefreshDftPlaintextProvider*>);
    static_assert(std::is_same_v<
                  decltype(std::declval<ExecutionMaterial>().dftBinding),
                  const Adapter::NativeRefreshDftPlaintextBinding*>);
    static_assert(std::is_same_v<
                  decltype(std::declval<ExecutionMaterial>().gadgetProvider),
                  const Adapter::NativeRefreshGadgetProvider*>);
    static_assert(std::is_same_v<
                  decltype(std::declval<ExecutionMaterial>().securityReport),
                  const Adapter::SecurityReport*>);
    using AdapterRef = const Adapter&;
    using CiphertextRef = const Adapter::Ciphertext&;
    using PlaintextRef = const Adapter::Plaintext&;
    using KeysRef = const Adapter::EvaluationKeys&;
    using RefreshPreflightRef =
        const Adapter::OrdinaryRefreshPreflight&;
    using SecurityReportRef = const Adapter::SecurityReport&;
    using AuthorizationRef =
        const Adapter::OrdinaryRefreshAuthorization&;
    using ExecutionMaterialRef =
        const Adapter::OrdinaryRefreshExecutionMaterialView&;
    using DirectAllYRef =
        const Adapter::DirectVectorAllYReturnPreflight&;
    using DirectAuthorizationRef =
        const Adapter::DirectVectorPrimaryAuthorization&;
    using DirectOwnerKeyLineageRef =
        const Adapter::DirectVectorOwnerKeyLineage&;
    using DirectStorageAuthorizationRef =
        const Adapter::DirectVectorPrimarySelectorStorageAuthorization&;
    using DirectRecordPreflightRef =
        const Adapter::DirectVectorSelectorRecordPreflight&;
    using DensePrimaryRef = const Adapter::
        NativeDirectVectorDensePrimarySecurityEvidence&;
    using DirectSmokeEvidenceRef =
        const Adapter::NativeDirectVectorEvidence&;
    using DirectSmokeReceiptRef =
        const Adapter::DirectVectorH2Stride2SmokeReceipt&;
    using NativeKeyProviderRef = const Adapter::NativeKeyProvider&;
    using NativeSchemeWorkloadRef =
        const Adapter::NativeGL128SchemeWorkload&;
    using NativePlainProductOptionsRef =
        const Adapter::NativeGL128PlainProductOptions&;
    using SparseKeyRef = const glscheme::rns::GlrSparseSecretKey&;
    using SecretKeyRef = const Adapter::SecretKey&;
    using SelectorGenerationSeedRef = const Adapter::
        NativeDirectVectorProductionSelectorGenerationSeed&;
    using SelectorCheckpointRef = const Adapter::
        NativeDirectVectorProductionSelectorManifestCheckpoint&;
    using SelectorRecordRef = const Adapter::
        NativeDirectVectorSelectorRecordGenerationResult&;
    using SelectorOpeningRef = const Adapter::
        NativeDirectVectorProductionSelectorProviderOpeningResult&;
    using DftSessionRef = const Adapter::
        NativeValidatedDftPlaintextProviderSession&;
    using BootstrapAuthorizationRef = const Adapter::
        NativeGL128DirectBootstrapAuthorizationBundle&;
    using PersistedSelectorBankRef = const Adapter::
        NativeGL128PersistedSelectorBankResult&;
    using CtsStcConfigRef = const Adapter::NativeCtsStcConfig&;
    using DftProviderRef = const Adapter::NativeRefreshDftPlaintextProvider&;
    using DftBindingRef = const Adapter::NativeRefreshDftPlaintextBinding&;
    using DirectBootstrapKeysRef =
        const Adapter::CompactDirectBootstrapKeys&;
    using DirectBootstrapPlanRef =
        const Adapter::NativeGL128DirectBootstrapKeyPlan&;
    using CompactKskSinkRef = const Adapter::NativeCompactKskSetSink&;
    static_assert(std::is_same_v<
                  Adapter::NativeGL128ProfileReceipt,
                  glscheme::rns::Gl128ProfileReceipt>);
    static_assert(std::is_same_v<
                  Adapter::NativeGL128EvaluationResult,
                  glscheme::rns::Gl128EvaluationResult>);
    static_assert(glscheme::rns::kGl128BootstrapDftScale == 0x1p46);
    static_assert(!std::is_copy_constructible_v<
                  Adapter::CompactEvaluationKeys>);
    static_assert(!std::is_copy_constructible_v<
                  Adapter::CompactDirectBootstrapKeys>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .GetCanonicalProfileReceipt()),
                  Adapter::NativeGL128ProfileReceipt>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .PlanCanonicalSchemeKeys(
                                   std::declval<NativeSchemeWorkloadRef>())),
                  Adapter::NativeGL128SchemeKeyPlan>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .PlanCanonicalDirectBootstrapKeys()),
                  Adapter::NativeGL128DirectBootstrapKeyPlan>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .GenerateCompactDirectBootstrapKeys(
                                   std::declval<SecretKeyRef>(),
                                   std::declval<SparseKeyRef>(),
                                   std::declval<DirectBootstrapPlanRef>(),
                                   std::declval<std::string>(),
                                   std::declval<CompactKskSinkRef>(), 1)),
                  Adapter::
                      NativeGL128DirectBootstrapKeyGenerationResult>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .OpenDftPlaintextSession(
                                   std::declval<DftProviderRef>(),
                                   std::declval<DftBindingRef>())),
                  Adapter::NativeValidatedDftPlaintextProviderSession>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().EvaluateAdd(
                      std::declval<CiphertextRef>(),
                      std::declval<CiphertextRef>())),
                  Adapter::NativeGL128EvaluationResult>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().EvaluateMatMul(
                      std::declval<CiphertextRef>(),
                      std::declval<PlaintextRef>(),
                      std::declval<NativePlainProductOptionsRef>())),
                  Adapter::NativeGL128EvaluationResult>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().EvaluateMatMul(
                      std::declval<CiphertextRef>(),
                      std::declval<CiphertextRef>(),
                      std::declval<NativeKeyProviderRef>())),
                  Adapter::NativeGL128EvaluationResult>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .CreateDirectVectorPrimarySelectorGenerator(
                                   std::declval<SecretKeyRef>(),
                                   std::declval<SparseKeyRef>(),
                                   std::declval<DirectAuthorizationRef>(),
                                   std::declval<DirectStorageAuthorizationRef>(),
                                   std::declval<SelectorGenerationSeedRef>())),
                  std::unique_ptr<Adapter::
                      NativeDirectVectorProductionSelectorGenerator>>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .BeginDirectVectorPrimarySelectorManifest(
                                   std::declval<DirectAuthorizationRef>(),
                                   std::declval<DirectStorageAuthorizationRef>())),
                  Adapter::
                      NativeDirectVectorProductionSelectorManifestCheckpoint>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .AppendDirectVectorPrimarySelectorRecord(
                                   std::declval<DirectAuthorizationRef>(),
                                   std::declval<DirectStorageAuthorizationRef>(),
                                   std::declval<SelectorCheckpointRef>(),
                                   std::declval<SelectorRecordRef>())),
                  Adapter::
                      NativeDirectVectorProductionSelectorManifestCheckpoint>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .ExecuteDirectVectorAllYProduction(
                                   std::declval<CiphertextRef>(),
                                   std::declval<DirectAuthorizationRef>(),
                                   std::declval<SelectorOpeningRef>(),
                                   std::declval<DirectBootstrapKeysRef>(),
                                   std::declval<DftSessionRef>())),
                  Adapter::DirectVectorProductionAllYResult>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().PrepareDirectShipInput(
                      std::declval<CiphertextRef>(),
                      std::declval<BootstrapAuthorizationRef>(),
                      std::declval<DftSessionRef>(),
                      std::declval<DirectBootstrapKeysRef>(),
                      std::declval<CtsStcConfigRef>(), 1.0e-12)),
                  Adapter::NativeGL128DirectInputPreparationResult>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().BootstrapDirect(
                      std::declval<CiphertextRef>(),
                      std::declval<BootstrapAuthorizationRef>(),
                      std::declval<SelectorOpeningRef>(),
                      std::declval<DftSessionRef>(),
                      std::declval<DirectBootstrapKeysRef>(),
                      std::declval<CtsStcConfigRef>(), 1.0e-12)),
                  Adapter::NativeGL128BootstrapResult>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .OpenPersistedDirectSelectorBank(
                                   std::declval<BootstrapAuthorizationRef>(),
                                   std::declval<PersistedSelectorBankRef>(),
                                   std::declval<DirectBootstrapKeysRef>(),
                                   std::declval<Adapter::
                                       NativeDirectVectorProductionSelectorBlobLeaseCallbacks>())),
                  Adapter::
                      NativeDirectVectorProductionSelectorProviderOpeningResult>);
    static_assert(std::is_trivially_copyable_v<
                  Adapter::DirectVectorAllYReturnPreflight>);
    static_assert(!std::is_trivially_copyable_v<
                  Adapter::DirectVectorH2Stride2SmokeReceipt>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .PreflightDirectVectorPrimaryAllYReturn()),
                  Adapter::DirectVectorAllYReturnPreflight>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .ValidateDirectVectorPrimaryAllYReturnPreflight(
                                   std::declval<DirectAllYRef>())),
                  void>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .AuthorizeDirectVectorPrimaryCandidate(
                                   std::declval<const std::string&>(),
                                   std::declval<SecurityReportRef>(),
                                   std::declval<DensePrimaryRef>(),
                                   std::declval<DirectOwnerKeyLineageRef>())),
                  Adapter::DirectVectorPrimaryAuthorization>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .ValidateDirectVectorPrimaryAuthorization(
                                   std::declval<DirectAuthorizationRef>(),
                                   std::declval<const std::string&>(),
                                   std::declval<SecurityReportRef>(),
                                   std::declval<DensePrimaryRef>(),
                                   std::declval<DirectOwnerKeyLineageRef>())),
                  void>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .AuthorizeDirectVectorPrimarySelectorStorage(
                                   std::declval<DirectAuthorizationRef>())),
                  Adapter::
                      DirectVectorPrimarySelectorStorageAuthorization>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .ValidateDirectVectorPrimarySelectorStorageAuthorization(
                                   std::declval<DirectStorageAuthorizationRef>(),
                                   std::declval<DirectAuthorizationRef>())),
                  void>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .PreflightDirectVectorPrimarySelectorRecord(
                                   std::declval<DirectStorageAuthorizationRef>(),
                                   std::declval<DirectAuthorizationRef>())),
                  Adapter::DirectVectorSelectorRecordPreflight>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .ValidateDirectVectorPrimarySelectorRecordPreflight(
                                   std::declval<DirectRecordPreflightRef>(),
                                   std::declval<DirectStorageAuthorizationRef>(),
                                   std::declval<DirectAuthorizationRef>())),
                  void>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .BindInsecureDirectVectorH2Stride2Smoke(
                                   std::declval<DirectSmokeEvidenceRef>(),
                                   32768, 1.0e-8, 1.0,
                                   UINT64_C(64) << 20, 1, 1)),
                  Adapter::DirectVectorH2Stride2SmokeReceipt>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .ValidateInsecureDirectVectorH2Stride2SmokeReceipt(
                                   std::declval<DirectSmokeReceiptRef>())),
                  void>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .PreflightOrdinaryRefresh()),
                  Adapter::OrdinaryRefreshPreflight>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .ValidateOrdinaryRefreshPreflight(
                                   std::declval<RefreshPreflightRef>())),
                  void>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .AuthorizeOrdinaryRefreshProduction(
                                   std::declval<const std::string&>(),
                                   std::declval<SecurityReportRef>(), 40,
                                   true)),
                  Adapter::OrdinaryRefreshAuthorization>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .ValidateOrdinaryRefreshAuthorization(
                                   std::declval<AuthorizationRef>(),
                                   std::declval<const std::string&>(),
                                   std::declval<SecurityReportRef>(), 40,
                                   true)),
                  void>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>()
                               .ExecuteOrdinaryRefresh(
                                   std::declval<CiphertextRef>(),
                                   std::declval<ExecutionMaterialRef>())),
                  Adapter::OrdinaryRefreshExecutionResult>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().Sub(
                      std::declval<CiphertextRef>(),
                      std::declval<CiphertextRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().Negate(
                      std::declval<CiphertextRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().Rescale(
                      std::declval<CiphertextRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().MatMul(
                      std::declval<CiphertextRef>(),
                      std::declval<PlaintextRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().Hadamard(
                      std::declval<CiphertextRef>(),
                      std::declval<PlaintextRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().RotateRows(
                      std::declval<CiphertextRef>(), 1,
                      std::declval<KeysRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().RotateColumns(
                      std::declval<CiphertextRef>(), 1)),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().RotateMatrices(
                      std::declval<CiphertextRef>(), 1,
                      std::declval<KeysRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().Transpose(
                      std::declval<CiphertextRef>(),
                      std::declval<KeysRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().Conjugate(
                      std::declval<CiphertextRef>(),
                      std::declval<KeysRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().HermitianTranspose(
                      std::declval<CiphertextRef>(),
                      std::declval<KeysRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().MatMul(
                      std::declval<CiphertextRef>(),
                      std::declval<CiphertextRef>(),
                      std::declval<KeysRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().Hadamard(
                      std::declval<CiphertextRef>(),
                      std::declval<CiphertextRef>(),
                      std::declval<KeysRef>())),
                  Adapter::Ciphertext>);

    const Adapter::Profile profile = Adapter::CanonicalProfile();
    Require(profile.layout == LayoutKind::gl128_257_n32_tensor,
            "wrong typed layout");
    Require(profile.canonical_name ==
                "GL-128-257-N32/physical-256x128x128",
            "wrong canonical name");
    Require(profile.n == 128 && profile.p == 257 && profile.phi == 256,
            "wrong GL algebra shape");
    Require(profile.has_w_axis && profile.matrix_count == 256,
            "production profile lost its W axis");
    Require(profile.physical.planes == 256 && profile.physical.rows == 128 &&
                profile.physical.columns == 128,
            "wrong physical tensor shape");
    Require(profile.payload_complex_values == 4194304ULL,
            "wrong production payload size");
    Require(profile.rlwe_ring_dimension == 65536ULL,
            "wrong RLWE dimension");

    // Context construction and primary key generation are small enough for a
    // fast smoke test.  A full R' plaintext/ciphertext allocates gigabytes at
    // this canonical geometry, so encode/encrypt/decrypt/add are compile/link
    // provider checks here and belong in the resource-qualified acceptance run.
    Adapter adapter = Adapter::Create();
    const auto& context = adapter.GetContext();
    Require(context.params.name == "GL-128-257-N32", "wrong context profile");
    Require(context.n() == 128 && context.p_() == 257 && context.phi() == 256,
            "wrong context geometry");
    Require(context.params.coeffs_Rp() == 4194304ULL,
            "context is not the production R' tensor");
    const auto profileReceipt = adapter.GetCanonicalProfileReceipt();
    Require(profileReceipt.schema == "glscheme.gl128_profile_receipt.v1" &&
                profileReceipt.profile_name == "GL-128-257-N32" &&
                profileReceipt.parameter_fingerprint ==
                    glscheme::rns::glr_parameter_fingerprint(context.params) &&
                profileReceipt.matrix_order == 128 &&
                profileReceipt.matrix_count == 256 &&
                profileReceipt.complex_slot_count == 4194304ULL &&
                profileReceipt.secret_ring_dimension == 65536ULL &&
                profileReceipt.q_prime_count == 25 &&
                profileReceipt.special_prime_count == 14 &&
                profileReceipt.rescale_stride == 2 &&
                profileReceipt.sparse_hamming_weight == 40 &&
                profileReceipt.exact_profile &&
                profileReceipt.canonical_ship_geometry &&
                !profileReceipt.sparse_security_admitted,
            "core GL128 profile receipt lost its exact production binding");

    const auto schemeKeyPlan = adapter.PlanCanonicalSchemeKeys();
    Require(schemeKeyPlan.schema == "glscheme.gl128_scheme_key_plan.v1" &&
                schemeKeyPlan.parameter_fingerprint ==
                    profileReceipt.parameter_fingerprint &&
                schemeKeyPlan.key_level == 0 &&
                schemeKeyPlan.ids.size() == 5 &&
                schemeKeyPlan.small_switch_key_count == 2 &&
                schemeKeyPlan.big_switch_key_count == 3 &&
                schemeKeyPlan.matrix_product_relinearization_complete &&
                schemeKeyPlan.hadamard_relinearization_complete &&
                schemeKeyPlan.automorphism_keys_complete &&
                schemeKeyPlan.seeded_public_a_compaction_planned &&
                schemeKeyPlan.compact_persistent_bytes <
                    schemeKeyPlan.full_materialized_bytes &&
                schemeKeyPlan.compact_bytes_saved ==
                    schemeKeyPlan.full_materialized_bytes -
                        schemeKeyPlan.compact_persistent_bytes,
            "complete core GL128 scheme-key plan is malformed");

    const auto directKeyPlan =
        adapter.PlanCanonicalDirectBootstrapKeys();
    Require(directKeyPlan.schema ==
                    "glscheme.gl128_direct_bootstrap_key_plan.v2" &&
                directKeyPlan.parameter_fingerprint ==
                    profileReceipt.parameter_fingerprint &&
                directKeyPlan.requirements.size() == 5 &&
                directKeyPlan.selector_level == 0 &&
                directKeyPlan.first_relinearization_level == 2 &&
                directKeyPlan.output_level == 14 &&
                directKeyPlan.forward_return_level == 18 &&
                directKeyPlan.requirements[0].key_level == 2 &&
                directKeyPlan.requirements[1].key_level == 14 &&
                directKeyPlan.requirements[2].key_level == 24 &&
                directKeyPlan.requirements[3].key_level == 14 &&
                directKeyPlan.requirements[4].key_level == 14 &&
                directKeyPlan.requirements[0].special_prime_count == 0 &&
                directKeyPlan.requirements[1].special_prime_count == 0 &&
                directKeyPlan.requirements[2].special_prime_count == 1 &&
                directKeyPlan.requirements[3].special_prime_count == 0 &&
                directKeyPlan.requirements[4].special_prime_count == 0 &&
                directKeyPlan.exact_h40_corridor &&
                directKeyPlan.seeded_public_a_compaction_planned &&
                directKeyPlan.compact_persistent_bytes <
                    directKeyPlan.full_materialized_bytes &&
                directKeyPlan.compact_bytes_saved ==
                    directKeyPlan.full_materialized_bytes -
                        directKeyPlan.compact_persistent_bytes,
            "complete core GL128 direct-bootstrap key plan is malformed");
    const auto directDftConfig =
        adapter.GetCanonicalDirectDftGenerationConfig();
    Require(directDftConfig.profile ==
                    Adapter::NativeDftPlaintextGenerationConfig::Profile::
                        forward_only_two_record_v2 &&
                directDftConfig.forward_level == 13 &&
                directDftConfig.inverse_level == 17 &&
                directDftConfig.forward_scale ==
                    glscheme::rns::kGl128BootstrapForwardDftScale &&
                directDftConfig.inverse_scale ==
                    glscheme::rns::kGl128BootstrapDftScale &&
                Adapter::kForwardDftPlaintextEntryCount == 2 &&
                Adapter::kLegacyDftPlaintextEntryCount == 4,
            "directional direct-bootstrap DFT schedule drifted");
    const std::uint64_t expectedPublicKeyBytes =
        std::uint64_t{context.active_q_primes(0)} * 2 *
        context.params.coeffs_R() * 2 * sizeof(std::uint64_t);
    Require(adapter.PublicKeyResidentBytes() == expectedPublicKeyBytes &&
                expectedPublicKeyBytes == 25ULL * 1024 * 1024,
            "compact production public-key byte model is wrong");

    // The execution API is link-visible, but an empty non-owning view must
    // fail before inspecting the deliberately empty ciphertext.  Merely
    // constructing a result cannot assert successful execution either.
    Adapter::OrdinaryRefreshExecutionResult unopenedExecution;
    Require(!unopenedExecution.productionExecutionExposed,
            "default execution result overstates production execution");
    std::string nullExecutionMaterialError;
    try {
        (void)adapter.ExecuteOrdinaryRefresh(
            Adapter::Ciphertext{},
            Adapter::OrdinaryRefreshExecutionMaterialView{});
    }
    catch (const glscheme::rns::GlrError& error) {
        nullExecutionMaterialError = error.what();
    }
    Require(nullExecutionMaterialError.find(
                "non-null authenticated leased KSK provider/binding") !=
                std::string::npos,
            "null ordinary-refresh execution material did not fail closed");

    // The direct-vector lane exposes the genuine bounded all-Y row pack and
    // full StC-return boundary as an expected shape.  This remains a
    // preflight: h40 ciphertext execution and owner value/noise acceptance
    // are both explicitly false.
    const Adapter::DirectVectorAllYReturnPreflight directAllY =
        adapter.PreflightDirectVectorPrimaryAllYReturn();
    adapter.ValidateDirectVectorPrimaryAllYReturnPreflight(directAllY);
    Require(directAllY.yRows == 128 &&
                directAllY.selectorLevel == 0 &&
                directAllY.activeSelectorQPrimes == 25 &&
                directAllY.directOutputLevel == 14 &&
                directAllY.directMultiplicativeDepth == 7 &&
                directAllY.rescaleStride == 2 &&
                directAllY.physicalQPrimeDropsPerRow == 14 &&
                directAllY.logicalXwSlotsPerRow == 32768ULL &&
                directAllY.totalXwSlots == 4194304ULL &&
                directAllY.selectorCiphertextsVisited == 163840ULL &&
                directAllY.selectorProviderLeases == 163840ULL &&
                directAllY.plaintextCiphertextProducts == 163840ULL &&
                directAllY.leafRescales == 10240ULL &&
                directAllY.treeProductNodes == 9984ULL &&
                directAllY.treeRelinearizations == 9984ULL &&
                directAllY.treeRelinearizationKeyProviderLeases == 256ULL &&
                directAllY.treeCarryLevelAlignments == 512ULL &&
                directAllY.treeRescales == 9984ULL &&
                directAllY.conjugationKeySwitches == 256ULL &&
                directAllY.expectedMaxLiveYRows == 1 &&
                directAllY.representationScaleFactor == 32768ULL &&
                directAllY.packedInputLevel == 14 &&
                directAllY.transformMaterialLevel == 13 &&
                directAllY.transformKeyLevel == 14 &&
                directAllY.outputLevel == 18 &&
                directAllY.forwardPhysicalQPrimeDrops == 4 &&
                directAllY.expectedDftPlaintextVisits == 2 &&
                directAllY.strictYOrderRequired &&
                directAllY.fullYCoverageRequired &&
                directAllY.primaryRingRSlotRowsRequired &&
                directAllY.slotToCoeffPerRowRequired &&
                directAllY.traceRepresentationScaleRestored &&
                directAllY.boundedRowPackBoundaryImplemented &&
                directAllY.fullReturnBoundaryImplemented &&
                !directAllY.canonicalH40CiphertextValueExecutionPerformed &&
                !directAllY
                     .canonicalH40DecryptedValueNoiseAcceptanceRecorded,
            "direct-vector all-Y/full-return preflight lost its exact "
            "L0/Q25 -> L14 -> L18 counter/level shape");
    {
        auto forged = directAllY;
        forged.outputLevel = 21;
        bool rejected = false;
        try {
            adapter.ValidateDirectVectorPrimaryAllYReturnPreflight(forged);
        }
        catch (const glscheme::rns::GlrError&) {
            rejected = true;
        }
        Require(rejected,
                "forged direct-vector full-return level was accepted");
    }
    {
        auto forged = directAllY;
        forged.canonicalH40CiphertextValueExecutionPerformed = true;
        bool rejected = false;
        try {
            adapter.ValidateDirectVectorPrimaryAllYReturnPreflight(forged);
        }
        catch (const glscheme::rns::GlrError&) {
            rejected = true;
        }
        Require(rejected,
                "forged direct-vector h40 execution claim was accepted");
    }

    // Bind the exact checked-in sparse Q7+P14 report and the independent
    // dense-primary full-QP transcript to GLScheme's metadata-only candidate
    // authorizer.  OpenFHE supplies no alternate level/window/key-domain
    // knobs, so copied authorization cannot silently widen the transcript.
    const auto directWindows = glscheme::rns::glr_ship_make_windows(
        128, 256, 40, 0, 2, 2, 2);
    const std::string directSupportCommitment =
        glscheme::rns::glr_ship_support_commitment(
            128, 256, directWindows);
    Require(directSupportCommitment ==
                "glr-ship-support-v1:n=128:phi=256:count=40:"
                "fnv64=626576712384570758",
            "canonical direct-vector support commitment drifted");
    const Adapter::SecurityReport directSparseReport =
        MakeGl128CorridorReport(
            context.params, 40, directSupportCommitment);
    const auto directDenseEvidence = MakeDensePrimarySecurityEvidence();
    const Adapter::DirectVectorOwnerKeyLineage directOwnerKeyLineage{
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "sha256:3333333333333333333333333333333333333333333333333333333333333333"};
    static_assert(!Adapter::kStructuredH40ProductionAuthorizationAvailable);
    static_assert(!Adapter::NativeDirectVectorProductionAuthorizationEvidence::
                       structured_h40_distribution_report_bound);
    std::string revokedH40AuthorizationError;
    try {
        (void)adapter.AuthorizeDirectVectorPrimaryCandidate(
            directSupportCommitment, directSparseReport,
            directDenseEvidence, directOwnerKeyLineage);
    }
    catch (const glscheme::rns::GlrError& error) {
        revokedH40AuthorizationError = error.what();
    }
    Require(revokedH40AuthorizationError.find(
                "structured public-window one-signed-monomial-per-window") !=
                std::string::npos,
            "free-support h40 proxy unexpectedly authorized the structured "
            "GL128 secret");
    Adapter::NativeDirectVectorProductionAuthorizationEvidence
        revokedNativeH40Authorization;
    Require(revokedNativeH40Authorization.schema ==
                    glscheme::rns::
                        kGlrShipDirectVectorGl128PrimaryAuthorizationSchema &&
                !revokedNativeH40Authorization
                     .production_candidate_metadata_authorized &&
                !revokedNativeH40Authorization
                     .structured_h40_distribution_report_bound &&
                !revokedNativeH40Authorization.selector_storage_admitted &&
                !revokedNativeH40Authorization.selector_material_generated &&
                !revokedNativeH40Authorization.value_execution,
            "default schema-v3 h40 receipt does not remain revoked");
    std::string revokedH40StorageError;
    try {
        (void)glscheme::rns::
            glr_authorize_ship_direct_vector_gl128_selector_storage(
                revokedNativeH40Authorization);
    }
    catch (const glscheme::rns::GlrError& error) {
        revokedH40StorageError = error.what();
    }
    Require(revokedH40StorageError.find(
                "canonical production metadata authorization is absent") !=
                std::string::npos,
            "revoked h40 receipt unexpectedly admitted selector storage");

    // Retain compile coverage for the historical wrapper shape, but keep it
    // unreachable while core's immutable structured-distribution posture is
    // false.  The static assertions above make accidental re-enablement a
    // build failure rather than a silently activated metadata path.
    if constexpr (Adapter::kStructuredH40ProductionAuthorizationAvailable) {
    const Adapter::DirectVectorPrimaryAuthorization directAuthorization =
        adapter.AuthorizeDirectVectorPrimaryCandidate(
            directSupportCommitment, directSparseReport,
            directDenseEvidence, directOwnerKeyLineage);
    adapter.ValidateDirectVectorPrimaryAuthorization(
        directAuthorization, directSupportCommitment, directSparseReport,
        directDenseEvidence, directOwnerKeyLineage);
    const auto& directNative = directAuthorization.native;
    Require(directNative.schema ==
                    glscheme::rns::
                        kGlrShipDirectVectorGl128PrimaryAuthorizationSchema &&
                directNative.production_candidate_metadata_authorized &&
                directNative.sparse_h40_q7_p14_report_bound &&
                directNative.dense_primary_full_qp_report_bound &&
                directNative.q0_only_sparse_public_input &&
                directNative.sparse_public_input_level == 24 &&
                directNative.sparse_public_input_active_q_primes == 1 &&
                directNative.primary_selector_ciphertexts &&
                directNative.plan.selector_level == 0 &&
                directNative.plan.active_q_primes == 25 &&
                directNative.relinearization_first_frontier_level == 2 &&
                directNative.conjugation_level == 14 &&
                directNative.plan.multiplicative_depth == 7 &&
                directNative.plan.physical_q_prime_drops == 14 &&
                directNative.plan.output_level == 14 &&
                directNative.plan.unsigned_candidate_count == 320 &&
                directNative.plan.signed_selector_count == 640 &&
                directNative.plan.plaintext_ciphertext_products == 1280 &&
                directNative.plan.tree_product_nodes == 78 &&
                directNative.plan
                        .bytes_per_encoded_compact_selector_record ==
                    6553826ULL &&
                directNative.plan.exact_encoded_compact_selector_bytes ==
                    4194448640ULL &&
                directNative.plan.compact_streamed_peak_selector_bytes ==
                    32768032ULL &&
                directNative.reserved_transform_material_level == 13 &&
                directNative.reserved_xw_forward_return_output_level == 18 &&
                directNative.owner_key_seed_commitment ==
                    directOwnerKeyLineage.ownerKskSeedCommitment &&
                directNative.primary_secret_lineage_commitment ==
                    directOwnerKeyLineage.primarySecretLineageCommitment &&
                directNative.sparse_secret_lineage_commitment ==
                    directOwnerKeyLineage.sparseSecretLineageCommitment &&
                !directNative.xw_forward_return_composition_implemented &&
                !directNative.y_coefficient_pack_implemented &&
                !directNative.context_ciphertext_or_key_allocation_required &&
                !directNative.selector_storage_admitted &&
                !directNative.selector_material_generated &&
                !directNative.value_execution &&
                directAuthorization.metadataAuthorizationOnly &&
                directAuthorization.ownerKeyLineageBound &&
                !directAuthorization
                     .productionH40CiphertextValueExecutionPerformed &&
                !directAuthorization
                     .productionH40DecryptedValueNoiseAcceptanceRecorded &&
                directAuthorization.allYReturn.fullReturnBoundaryImplemented,
            "direct-vector dual-certificate authorization lost its exact "
            "metadata-only L0/Q25 -> L14 binding");
    {
        auto forged = directAuthorization;
        forged.native.value_execution = true;
        bool rejected = false;
        try {
            adapter.ValidateDirectVectorPrimaryAuthorization(
                forged, directSupportCommitment, directSparseReport,
                directDenseEvidence, directOwnerKeyLineage);
        }
        catch (const glscheme::rns::GlrError&) {
            rejected = true;
        }
        Require(rejected,
                "forged direct-vector h40 value execution was accepted");
    }
    {
        auto forged = directAuthorization;
        --forged.allYReturn.treeRelinearizationKeyProviderLeases;
        bool rejected = false;
        try {
            adapter.ValidateDirectVectorPrimaryAuthorization(
                forged, directSupportCommitment, directSparseReport,
                directDenseEvidence, directOwnerKeyLineage);
        }
        catch (const glscheme::rns::GlrError&) {
            rejected = true;
        }
        Require(rejected,
                "forged direct-vector all-Y counter was accepted");
    }
    {
        auto forgedDense = directDenseEvidence;
        forgedDense.transcript_sha256[0] ^= 1;
        bool rejected = false;
        try {
            (void)adapter.AuthorizeDirectVectorPrimaryCandidate(
                directSupportCommitment, directSparseReport, forgedDense,
                directOwnerKeyLineage);
        }
        catch (const glscheme::rns::GlrError&) {
            rejected = true;
        }
        Require(rejected,
                "cross-transcript dense-primary authorization was accepted");
    }
    {
        auto forged = directAuthorization;
        forged.native.primary_secret_lineage_commitment[7] = 'f';
        bool rejected = false;
        try {
            adapter.ValidateDirectVectorPrimaryAuthorization(
                forged, directSupportCommitment, directSparseReport,
                directDenseEvidence, directOwnerKeyLineage);
        }
        catch (const glscheme::rns::GlrError&) {
            rejected = true;
        }
        Require(rejected,
                "cross-lineage direct-vector authorization was accepted");
    }
    {
        auto forgedLineage = directOwnerKeyLineage;
        forgedLineage.primarySecretLineageCommitment =
            forgedLineage.sparseSecretLineageCommitment;
        bool rejected = false;
        try {
            (void)adapter.AuthorizeDirectVectorPrimaryCandidate(
                directSupportCommitment, directSparseReport,
                directDenseEvidence, forgedLineage);
        }
        catch (const glscheme::rns::GlrError&) {
            rejected = true;
        }
        Require(rejected,
                "duplicate owner key-lineage roots were accepted");
    }

    // Production selector storage has a separate core capability: the exact
    // canonical encoded bank exceeds the generic 512-MiB p257 total cap, but
    // its one-record-plus-expanded-ciphertext streaming peak stays bounded.
    // The generic admission must continue to reject the same plan.
    bool genericSelectorCapRejected = false;
    try {
        (void)glscheme::rns::glr_admit_ship_direct_selector_material(
            directNative.plan,
            glscheme::rns::GlrShipDirectSelectorAdmissionKind::
                compact_authenticated_streamed);
    }
    catch (const glscheme::rns::GlrError& error) {
        genericSelectorCapRejected =
            std::string(error.what()).find("512 MiB") != std::string::npos;
    }
    Require(genericSelectorCapRejected,
            "canonical selector admission widened the generic 512-MiB cap");

    const Adapter::DirectVectorPrimarySelectorStorageAuthorization
        selectorStorage =
            adapter.AuthorizeDirectVectorPrimarySelectorStorage(
                directAuthorization);
    adapter.ValidateDirectVectorPrimarySelectorStorageAuthorization(
        selectorStorage, directAuthorization);
    const auto& nativeStorage = selectorStorage.native;
    Require(nativeStorage.schema ==
                    glscheme::rns::
                        kGlrShipDirectVectorGl128SelectorStorageAdmissionSchema &&
                nativeStorage.production_authorization_schema ==
                    directNative.schema &&
                nativeStorage.parameter_fingerprint ==
                    directNative.parameter_fingerprint &&
                nativeStorage.support_commitment ==
                    directNative.support_commitment &&
                nativeStorage.owner_key_seed_commitment ==
                    directOwnerKeyLineage.ownerKskSeedCommitment &&
                nativeStorage.primary_secret_lineage_commitment ==
                    directOwnerKeyLineage.primarySecretLineageCommitment &&
                nativeStorage.sparse_secret_lineage_commitment ==
                    directOwnerKeyLineage.sparseSecretLineageCommitment &&
                nativeStorage.sparse_security_transcript_sha256 ==
                    directNative.sparse_h40_security
                        .estimator_transcript_sha256 &&
                nativeStorage.dense_security_transcript_sha256 ==
                    directNative.dense_primary_security.transcript_sha256 &&
                nativeStorage.selector_level == 0 &&
                nativeStorage.active_q_primes == 25 &&
                nativeStorage.signed_selector_count == 640 &&
                nativeStorage.selector_admission.kind ==
                    glscheme::rns::GlrShipDirectSelectorAdmissionKind::
                        compact_authenticated_production_streamed &&
                nativeStorage.selector_admission.full_selector_payload_bytes ==
                    directNative.plan.exact_resident_selector_bytes &&
                nativeStorage.selector_admission.stored_selector_payload_bytes ==
                    4194448640ULL &&
                nativeStorage.selector_admission.streamed_peak_selector_bytes ==
                    32768032ULL &&
                nativeStorage.production_metadata_authorization_bound &&
                nativeStorage.compact_authenticated_streaming_admitted &&
                !nativeStorage.generic_512_mib_cap_widened &&
                nativeStorage.production_generator_enabled &&
                !nativeStorage.manifest_or_payload_generated &&
                selectorStorage.metadataAuthorizationOnly &&
                selectorStorage.canonicalPlanBound &&
                selectorStorage.bothSecurityRootsBound &&
                selectorStorage.ownerKeyLineageBound &&
                selectorStorage.selectorGenerationEnabled &&
                !selectorStorage.selectorManifestOrPayloadGenerated &&
                !selectorStorage.selectorMaterialReady &&
                !selectorStorage.valueExecution &&
                selectorStorage.canonicalPlan.selector_level == 0 &&
                selectorStorage.canonicalPlan.active_q_primes == 25 &&
                selectorStorage.canonicalPlan
                        .exact_encoded_compact_selector_bytes ==
                    4194448640ULL &&
                selectorStorage.canonicalPlan
                        .compact_streamed_peak_selector_bytes ==
                    32768032ULL,
            "selector-storage receipt lost its canonical plan/security-root/"
            "bounded-storage binding");

    const auto rejectedStorageReceipt = [&](auto mutate) {
        auto forged = selectorStorage;
        mutate(forged);
        try {
            adapter.ValidateDirectVectorPrimarySelectorStorageAuthorization(
                forged, directAuthorization);
        }
        catch (const glscheme::rns::GlrError&) {
            return true;
        }
        return false;
    };
    Require(rejectedStorageReceipt([](auto& forged) {
                --forged.native.selector_admission
                      .stored_selector_payload_bytes;
            }),
            "forged selector encoded-byte total was accepted");
    Require(rejectedStorageReceipt([](auto& forged) {
                forged.native.sparse_security_transcript_sha256[0] ^= 1;
            }),
            "cross-root selector-storage receipt was accepted");
    Require(rejectedStorageReceipt([](auto& forged) {
                forged.native.primary_secret_lineage_commitment[7] ^= 1;
            }),
            "cross-lineage selector-storage receipt was accepted");
    Require(rejectedStorageReceipt([](auto& forged) {
                ++forged.canonicalPlan.signed_selector_count;
            }),
            "cross-plan selector-storage receipt was accepted");
    Require(rejectedStorageReceipt([](auto& forged) {
                forged.selectorMaterialReady = true;
            }),
            "metadata-only selector receipt was promoted to material ready");
    Require(rejectedStorageReceipt([](auto& forged) {
                forged.native.production_generator_enabled = false;
            }),
            "selector-storage receipt hid native generator availability");
    Require(rejectedStorageReceipt([](auto& forged) {
                forged.selectorGenerationEnabled = false;
            }),
            "selector-storage wrapper hid generator availability");
    Require(rejectedStorageReceipt([](auto& forged) {
                forged.native.manifest_or_payload_generated = true;
            }),
            "native selector storage was forged as payload generated");
    Require(rejectedStorageReceipt([](auto& forged) {
                forged.selectorManifestOrPayloadGenerated = true;
            }),
            "selector-storage wrapper was forged as payload generated");
    Require(rejectedStorageReceipt([](auto& forged) {
                forged.valueExecution = true;
            }),
            "metadata-only selector receipt was promoted to value execution");
    {
        auto forgedSource = directAuthorization;
        ++forgedSource.native.plan.signed_selector_count;
        bool rejected = false;
        try {
            (void)adapter.AuthorizeDirectVectorPrimarySelectorStorage(
                forgedSource);
        }
        catch (const glscheme::rns::GlrError&) {
            rejected = true;
        }
        Require(rejected,
                "selector storage accepted a forged source plan");
    }

    // OpenFHE exposes only the exact allocation-free shape of the native
    // random-access record boundary.  The core acceptance test already runs
    // and decrypts a real N128 record; this adapter test must not repeat that
    // owner-side allocation or imply that any record/material now exists.
    const Adapter::DirectVectorSelectorRecordPreflight recordPreflight =
        adapter.PreflightDirectVectorPrimarySelectorRecord(
            selectorStorage, directAuthorization);
    adapter.ValidateDirectVectorPrimarySelectorRecordPreflight(
        recordPreflight, selectorStorage, directAuthorization);
    Require(recordPreflight.schema ==
                    glscheme::rns::
                        kGlrShipDirectVectorGl128SelectorRecordGenerationSchema &&
                recordPreflight.ownerKeyLineage.ownerKskSeedCommitment ==
                    directOwnerKeyLineage.ownerKskSeedCommitment &&
                recordPreflight.ownerKeyLineage
                        .primarySecretLineageCommitment ==
                    directOwnerKeyLineage.primarySecretLineageCommitment &&
                recordPreflight.ownerKeyLineage
                        .sparseSecretLineageCommitment ==
                    directOwnerKeyLineage.sparseSecretLineageCommitment &&
                recordPreflight.totalRecordCount == 640 &&
                recordPreflight.selectorLevel == 0 &&
                recordPreflight.activeQPrimes == 25 &&
                recordPreflight.encodedRecordBytes == 6553826ULL &&
                recordPreflight.expectedReturnedRecordAndEncodingBytes ==
                    13107458ULL &&
                recordPreflight.authorizedStreamingPeakBytes == 32768032ULL &&
                recordPreflight.productionAuthorizationBound &&
                recordPreflight.storageAdmissionBound &&
                recordPreflight.ownerKeyLineageBound &&
                recordPreflight.deterministicRandomAccessGeneratorAvailable &&
                !recordPreflight.recordGenerated &&
                !recordPreflight.manifestOrPayloadGenerated &&
                !recordPreflight.selectorMaterialReady &&
                !recordPreflight.valueExecution,
            "random-access selector preflight overstated generation or lost "
            "its exact lineage/record/peak shape");
    const auto rejectedRecordPreflight = [&](auto mutate) {
        auto forged = recordPreflight;
        mutate(forged);
        try {
            adapter.ValidateDirectVectorPrimarySelectorRecordPreflight(
                forged, selectorStorage, directAuthorization);
        }
        catch (const glscheme::rns::GlrError&) {
            return true;
        }
        return false;
    };
    Require(rejectedRecordPreflight([](auto& forged) {
                --forged.encodedRecordBytes;
            }),
            "forged random-access encoded-record bytes were accepted");
    Require(rejectedRecordPreflight([](auto& forged) {
                forged.ownerKeyLineage.sparseSecretLineageCommitment[7] ^= 1;
            }),
            "cross-lineage random-access preflight was accepted");
    Require(rejectedRecordPreflight([](auto& forged) {
                forged.recordGenerated = true;
            }),
            "random-access preflight was promoted to a generated record");
    Require(rejectedRecordPreflight([](auto& forged) {
                forged.manifestOrPayloadGenerated = true;
            }),
            "random-access preflight was promoted to generated payload");
    Require(rejectedRecordPreflight([](auto& forged) {
                forged.deterministicRandomAccessGeneratorAvailable = false;
            }),
            "random-access preflight hid native generator availability");
    }

    // The n128/p257 h=2 rung is an explicitly insecure value smoke.  Bind its
    // exact native L4 -> L8 counter receipt plus owner-observed thresholds,
    // while proving neither adapter execution nor h40 security/value claims
    // can be forged into the copied receipt.
    const Adapter::NativeDirectVectorEvidence directH2Evidence =
        MakeH2DirectEvidence(context);
    const Adapter::DirectVectorH2Stride2SmokeReceipt directH2 =
        adapter.BindInsecureDirectVectorH2Stride2Smoke(
            directH2Evidence, 32768, 5.0e-8, 30.0,
            UINT64_C(256) << 20, 1, 1);
    adapter.ValidateInsecureDirectVectorH2Stride2SmokeReceipt(directH2);
    Require(directH2.native.selector_level == 4 &&
                directH2.native.output_level == 8 &&
                directH2.native.rescale_stride == 2 &&
                directH2.native.physical_q_prime_drops == 4 &&
                directH2.native.selector_provider_leases == 8 &&
                directH2.native.plaintext_ciphertext_products == 8 &&
                directH2.native.leaf_rescales == 4 &&
                directH2.native.tree_product_nodes == 2 &&
                directH2.native.tree_relinearizations == 2 &&
                directH2.native
                        .tree_relinearization_key_provider_leases == 2 &&
                directH2.native.conjugation_key_switches == 2 &&
                directH2.ownerCheckedSlots == 32768 &&
                directH2.compactSelectorMaxLive == 1 &&
                directH2.evaluationKeyMaxLive == 1 &&
                directH2.targetGl128GeometryAndStrideBound &&
                directH2.ownerValueObservationBound &&
                directH2.explicitlyInsecure &&
                !directH2.adapterExecutedSmoke &&
                !directH2.productionH40AuthorizationAdmitted &&
                !directH2.productionH40ValueExecutionClaimed &&
                !directH2.productionH40ValueNoiseAcceptanceClaimed,
            "insecure target h2 receipt lost its exact counter/claim shape");
    {
        auto forged = directH2;
        --forged.native.selector_provider_leases;
        bool rejected = false;
        try {
            adapter.ValidateInsecureDirectVectorH2Stride2SmokeReceipt(forged);
        }
        catch (const glscheme::rns::GlrError&) {
            rejected = true;
        }
        Require(rejected, "forged h2 selector census was accepted");
    }
    {
        auto forged = directH2;
        forged.productionH40AuthorizationAdmitted = true;
        bool rejected = false;
        try {
            adapter.ValidateInsecureDirectVectorH2Stride2SmokeReceipt(forged);
        }
        catch (const glscheme::rns::GlrError&) {
            rejected = true;
        }
        Require(rejected,
                "insecure h2 receipt was promoted to h40 authorization");
    }

    // The production ordinary-refresh preflight remains a fixed-size planning
    // object, independent of the separately typed execution API.  It consumes
    // the native prime-p census and exposes the exact logarithmic trace key
    // list without owning material or claiming that execution occurred.
    const Adapter::OrdinaryRefreshPreflight refresh =
        adapter.PreflightOrdinaryRefresh();
    adapter.ValidateOrdinaryRefreshPreflight(refresh);
    Require(refresh.canonicalProfile.View() == profile.canonical_name &&
                refresh.parameterFingerprint.View() ==
                    profile.binding_fingerprint &&
                refresh.layout == LayoutKind::gl128_257_n32_tensor &&
                refresh.canonicalProfileBound,
            "ordinary-refresh preflight lost its canonical profile binding");
    Require(refresh.native.n == 128 && refresh.native.p == 257 &&
                refresh.native.phi == 256 &&
                refresh.native.centered_refreshes == 32768ULL &&
                refresh.native.coefficients_packed == 4194304ULL &&
                refresh.native.x_trace_unique_keys == 7 &&
                refresh.native.w_trace_unique_keys == 8 &&
                refresh.native.x_trace_rotations_per_readout == 7 &&
                refresh.native.w_trace_rotations_per_readout == 8 &&
                refresh.native.trace_key_switches == 491520ULL &&
                refresh.native.exact_prime_w_dual &&
                !refresh.native.heap_allocation_required,
            "canonical prime-p refresh census is wrong");

    // The native endpoint arithmetic is fixed to the reviewed Q7+P14
    // corridor: gamma=64, canonical input delta, DFT scale 2^46, refreshed
    // fold/key level 18, and level-17 transform material.  Feasible arithmetic
    // remains preflight-only; execution separately requires a complete
    // caller-owned material view and a successful native endpoint call.
    const auto& endpoint = refresh.endpoint;
    Require(endpoint.total_q_primes == 25 &&
                endpoint.rescale_stride == 2 &&
                endpoint.required_input_live_q_primes == 7 &&
                endpoint.input_level == 18 &&
                endpoint.cts_output_level == 22 &&
                endpoint.normalized_level == 24 &&
                endpoint.packed_level == 18 &&
                endpoint.output_level == 22 &&
                endpoint.cts_rescale_count == 4 &&
                endpoint.normalization_rescale_count == 2 &&
                endpoint.stc_rescale_count == 4,
            "canonical endpoint level/rescale ledger is not "
            "18->22->24->fold18->22");
    Require(endpoint.normalization_multiplier == 1154461932539ULL &&
                refresh.refreshGamma == 64.0 &&
                endpoint.input_scale == context.params.delta &&
                endpoint.dft_scale == std::ldexp(1.0, 46) &&
                refresh.normalizationRelativeTolerance == 1.0e-12 &&
                endpoint.normalization_relative_error <=
                    refresh.normalizationRelativeTolerance &&
                endpoint.integer_multiplier_exactly_representable &&
                endpoint.strict_normalization_feasible &&
                !endpoint.would_require_scale_snapping &&
                !endpoint.scale_snapping_enabled,
            "canonical endpoint strict integer normalization is wrong");
    Require(endpoint.canonical_gl128_257_n32 &&
                !endpoint.context_or_key_allocation_required &&
                endpoint.arithmetic_preflight_only &&
                endpoint.requires_h40_corridor &&
                endpoint.security_binding_required &&
                !endpoint.production_execution_admitted &&
                endpoint.fold_level == 18 &&
                endpoint.transform_material_level == 17 &&
                endpoint.transform_material_alignment_safe &&
                endpoint.stc_headroom_valid,
            "canonical endpoint preflight confused arithmetic with "
            "production authorization");
    Require(refresh.traceKeyLevel == 18 &&
                refresh.nonTraceKeyLevel == 18 &&
                refresh.corridorQPrimeCount == 7 &&
                refresh.corridorSpecialPrimeCount == 14 &&
                refresh.requiredSparseHammingWeight == 40 &&
                refresh.reducedExposureCorridorRequired &&
                refresh.securityAuthorizationRequired,
            "canonical refresh key/corridor requirements are wrong");
    constexpr std::uint64_t MiB = 1024ULL * 1024ULL;
    constexpr std::uint64_t GiB = 1024ULL * MiB;
    Require(refresh.keyLevelModelCount ==
                Adapter::kCanonicalRefreshKeyLevelModelCount &&
                refresh.keyLevelModels.size() == 2,
            "canonical Q7/Q8 key-size census count is wrong");
    const auto& q7Keys = refresh.keyLevelModels[0];
    const auto& q8Keys = refresh.keyLevelModels[1];
    Require(q7Keys.keyLevel == 18 &&
                q7Keys.ringRPerKeyBytes == 21ULL * MiB &&
                q7Keys.ringRpPerKeyBytes == 2ULL * GiB + 640ULL * MiB &&
                q7Keys.ringRauxPerKeyBytes == 5ULL * GiB + 256ULL * MiB,
            "level-18 Q7 one-digit key byte model is wrong");
    Require(q8Keys.keyLevel == 17 &&
                q8Keys.ringRPerKeyBytes == 22ULL * MiB &&
                q8Keys.ringRpPerKeyBytes == 2ULL * GiB + 768ULL * MiB &&
                q8Keys.ringRauxPerKeyBytes == 5ULL * GiB + 512ULL * MiB,
            "level-17 Q8 one-digit key byte model is wrong");
    Require(refresh.traceRotationKeyResidentBytes == 15ULL * 21ULL * MiB,
            "listed level-18 trace-key byte total is wrong");
    Require(refresh.listedNonTraceKeyDebtResidentBytes ==
                3ULL * 21ULL * MiB + (2ULL * GiB + 640ULL * MiB) +
                    (5ULL * GiB + 256ULL * MiB),
            "listed level-18 non-trace key-debt byte total is wrong");
    Require(refresh.traceKeyCount ==
                Adapter::kCanonicalRefreshTraceKeyCount &&
                refresh.traceKeys.size() == 15,
            "canonical refresh trace-key count is not exactly 15");
    std::size_t traceIndex = 0;
    for (std::int32_t amount = 1; amount < 128; amount *= 2) {
        const auto& entry = refresh.traceKeys[traceIndex++];
        Require(entry.id.direction ==
                    glscheme::rns::GlrKsDirection::row_rotation &&
                    entry.id.amount == amount &&
                    entry.applications == 32768ULL,
                "row trace-key direction/amount/application count is wrong");
    }
    for (std::int32_t amount = 1; amount < 256; amount *= 2) {
        const auto& entry = refresh.traceKeys[traceIndex++];
        Require(entry.id.direction ==
                    glscheme::rns::GlrKsDirection::w_rotation &&
                    entry.id.amount == amount &&
                    entry.applications == 32768ULL,
                "W trace-key direction/amount/application count is wrong");
    }
    Require(traceIndex == refresh.traceKeys.size(),
            "refresh trace-key list has an unverified tail");
    const std::uint64_t traceApplications = std::accumulate(
        refresh.traceKeys.begin(), refresh.traceKeys.end(), std::uint64_t{0},
        [](std::uint64_t sum,
           const Adapter::RefreshTraceKeyEntry& entry) {
            return sum + entry.applications;
        });
    Require(traceApplications == refresh.native.trace_key_switches,
            "exact trace-key list does not sum to 491,520 switches");

    using Direction = glscheme::rns::GlrKsDirection;
    const std::array<Direction, 5> expectedEndpointDebts{
        Direction::primary_to_sparse,
        Direction::sparse_to_primary,
        Direction::conjugation_to_sparse,
        Direction::primary_conjtranspose_to_primary,
        Direction::aux_conjtranspose_to_primary,
    };
    Require(refresh.endpointKeyDebtCount ==
                Adapter::kCanonicalRefreshEndpointKeyDebtCount,
            "full endpoint non-trace key debt count is wrong");
    for (std::size_t i = 0; i < expectedEndpointDebts.size(); ++i) {
        Require(refresh.endpointKeyDebts[i].direction ==
                    expectedEndpointDebts[i] &&
                    refresh.endpointKeyDebts[i].amount == 0,
                "full endpoint non-trace key debt list is wrong");
    }
    Require(refresh.availability ==
                Adapter::OrdinaryRefreshAvailability::preflight_only &&
                refresh.reducedExposureCorridorRequired &&
                refresh.securityAuthorizationRequired &&
                refresh.sparseKeyRequired &&
                !refresh.encryptedSelectorBankRequired &&
                !refresh.encryptedGadgetBankRequired &&
                !refresh.dftBankRequired &&
                !refresh.productionExecutionExposed &&
                refresh.compactSelectorBindingRequired &&
                refresh.authenticatedLeasedKskRequired &&
                refresh.streamedGadgetProviderRequired &&
                refresh.streamedDftProviderRequired,
            "refresh preflight overstates production execution readiness");

    const auto rejectedRefreshForgery = [&](auto mutate) {
        Adapter::OrdinaryRefreshPreflight forged = refresh;
        mutate(forged);
        try {
            adapter.ValidateOrdinaryRefreshPreflight(forged);
        }
        catch (const glscheme::rns::GlrError&) {
            return true;
        }
        return false;
    };
    Require(rejectedRefreshForgery([](auto& forged) {
                forged.parameterFingerprint.bytes[0] ^= 1;
            }),
            "cross-fingerprint refresh preflight did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                forged.traceKeys[14].id.amount = 127;
            }),
            "forged refresh trace-key list did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                ++forged.endpoint.normalization_multiplier;
            }),
            "forged endpoint normalization K did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                forged.endpoint.dft_scale = std::ldexp(1.0, 45);
            }),
            "forged endpoint DFT scale did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                forged.endpoint.input_level = 17;
            }),
            "forged endpoint level ledger did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                forged.endpoint.would_require_scale_snapping = true;
            }),
            "forged scale-snapping endpoint did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                forged.endpoint.production_execution_admitted = true;
            }),
            "forged native endpoint admission did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                forged.traceKeyLevel = 17;
            }),
            "forged trace-key level did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                forged.nonTraceKeyLevel = 17;
            }),
            "forged endpoint non-trace key level did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                forged.keyLevelModels[0].ringRPerKeyBytes *= 2;
            }),
            "forged/doubled Q7 key byte model did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                ++forged.listedNonTraceKeyDebtResidentBytes;
            }),
            "forged listed key-debt byte total did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                forged.corridorSpecialPrimeCount = 13;
            }),
            "forged P14 corridor did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                forged.securityAuthorizationRequired = false;
            }),
            "forged security-authorization requirement did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                forged.productionExecutionExposed = true;
            }),
            "forged production refresh readiness did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                forged.compactSelectorBindingRequired = false;
            }),
            "forged compact-selector requirement did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                forged.authenticatedLeasedKskRequired = false;
            }),
            "forged authenticated-leased-KSK requirement did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                forged.streamedGadgetProviderRequired = false;
            }),
            "forged streamed-gadget requirement did not fail closed");
    Require(rejectedRefreshForgery([](auto& forged) {
                forged.streamedDftProviderRequired = false;
            }),
            "forged streamed-DFT requirement did not fail closed");

    // The execution seam must bind a successful native result to the exact
    // full all-Y census, not merely to a high-level "packed SHIP" boolean.
    Adapter::NativeRefreshEndpointResult canonicalNativeResult;
    canonicalNativeResult.input_level = refresh.endpoint.input_level;
    canonicalNativeResult.output_level = refresh.endpoint.output_level;
    Adapter::NativeRefreshEndpointEvidence canonicalNativeEvidence;
    canonicalNativeEvidence.cts_xinv_used = true;
    canonicalNativeEvidence.public_scale_normalization_used = true;
    canonicalNativeEvidence.primary_to_sparse_used = true;
    canonicalNativeEvidence.packed_ship_used = true;
    canonicalNativeEvidence.stc_xfwd_used = true;
    canonicalNativeEvidence.provider_secret_free = true;
    canonicalNativeEvidence.normalization_multiplier =
        refresh.endpoint.normalization_multiplier;
    canonicalNativeEvidence.input_level = refresh.endpoint.input_level;
    canonicalNativeEvidence.cts_output_level =
        refresh.endpoint.cts_output_level;
    canonicalNativeEvidence.normalized_level =
        refresh.endpoint.normalized_level;
    canonicalNativeEvidence.packed_level = refresh.endpoint.packed_level;
    canonicalNativeEvidence.output_level = refresh.endpoint.output_level;
    canonicalNativeEvidence.rescale_stride = refresh.endpoint.rescale_stride;
    canonicalNativeEvidence.required_input_live_q_primes =
        refresh.endpoint.required_input_live_q_primes;
    canonicalNativeEvidence.normalization_rescale_count =
        refresh.endpoint.normalization_rescale_count;
    canonicalNativeEvidence.strict_integer_normalization = true;
    canonicalNativeEvidence.fold_level = refresh.endpoint.fold_level;
    canonicalNativeEvidence.transform_material_level =
        refresh.endpoint.transform_material_level;
    canonicalNativeEvidence.validated_key_level = refresh.endpoint.fold_level;
    canonicalNativeEvidence.transform_material_level_drop = 1;
    canonicalNativeEvidence.transform_material_alignment_safe = true;
    canonicalNativeEvidence.canonical_production_authorized = true;
    canonicalNativeEvidence.pack_parameter_fingerprint =
        glscheme::rns::glr_parameter_fingerprint(context.params);
    canonicalNativeEvidence.pack_input_ciphertext_commitment_sha256 =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    canonicalNativeEvidence.pack_execution_material_commitment_sha256 =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    canonicalNativeEvidence.pack_checkpoint_chain_commitment_sha256 =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    canonicalNativeEvidence.pack_complete_coordinate_cover = true;
    canonicalNativeEvidence.ciphertext_value_execution_performed = true;
    canonicalNativeEvidence.value_noise_acceptance_recorded = false;
    auto& canonicalPack = canonicalNativeEvidence.pack;
    canonicalPack.centered_refreshes = refresh.native.centered_refreshes;
    canonicalPack.coefficients_packed = refresh.native.coefficients_packed;
    canonicalPack.sparse_to_primary_switches =
        refresh.native.centered_refreshes;
    canonicalPack.exponent_ladder_nodes =
        2ULL * context.n() * refresh.requiredSparseHammingWeight *
        refresh.native.centered_refreshes;
    canonicalPack.gadget_applies =
        2ULL * canonicalPack.exponent_ladder_nodes;
    canonicalPack.x_trace_rotations =
        refresh.native.centered_refreshes *
        refresh.native.x_trace_rotations_per_readout;
    canonicalPack.w_trace_rotations =
        refresh.native.centered_refreshes *
        refresh.native.w_trace_rotations_per_readout;
    canonicalPack.x_centering_monomial_multiplies =
        refresh.native.x_centering_monomial_multiplies;
    canonicalPack.w_dual_monomial_multiplies =
        refresh.native.w_dual_monomial_multiplies;
    canonicalPack.w_dual_accumulator_additions =
        refresh.native.w_dual_accumulator_additions;
    canonicalPack.streamed_exponent_leaf_batch_used = true;
    canonicalPack.streamed_exponent_leaf_batch_invocations = 41943040ULL;
    canonicalPack.streamed_exponent_leaf_tables_batched = 335544320ULL;
    canonicalPack.streamed_exponent_leaf_pair_visits = 671088640ULL;
    canonicalPack.streamed_exponent_leaf_scalar_equivalent_pair_visits =
        5368709120ULL;
    canonicalPack.streamed_exponent_leaf_max_batch_size = 8;
    canonicalPack.streamed_exponent_leaf_peak_accumulators = 8;
    canonicalPack.streamed_exponent_leaf_peak_scratch_polys = 1;
    canonicalPack.checkpoint_chunks_merged = 1;
    canonicalPack.checkpoint_commitment_validated_merge_used = true;
    canonicalPack.public_centering_used = true;
    canonicalPack.homomorphic_readout_projection_used = true;
    canonicalPack.provider_secret_free = true;
    canonicalPack.exact_prime_w_dual_used = true;
    canonicalPack.allocation_free_preflight_used = true;
    adapter.ValidateOrdinaryRefreshExecutionEvidence(
        canonicalNativeResult, canonicalNativeEvidence);
    auto replayedCheckpointEvidence = canonicalNativeEvidence;
    ++replayedCheckpointEvidence.pack.x_centering_monomial_multiplies;
    ++replayedCheckpointEvidence.pack
          .checkpoint_replay_x_centering_monomial_multiplies;
    replayedCheckpointEvidence.pack.checkpoint_chunks_merged = 2;
    adapter.ValidateOrdinaryRefreshExecutionEvidence(
        canonicalNativeResult, replayedCheckpointEvidence);

    const auto rejectedExecutionEvidence = [&](auto mutate) {
        auto forged = canonicalNativeEvidence;
        mutate(forged);
        try {
            adapter.ValidateOrdinaryRefreshExecutionEvidence(
                canonicalNativeResult, forged);
        }
        catch (const glscheme::rns::GlrError&) {
            return true;
        }
        return false;
    };
    Require(rejectedExecutionEvidence([](auto& forged) {
                forged.cts_xinv_used = false;
            }),
            "stage-incomplete ordinary-refresh evidence did not fail closed");
    Require(rejectedExecutionEvidence([](auto& forged) {
                --forged.pack.centered_refreshes;
            }),
            "partial centered-refresh evidence did not fail closed");
    Require(rejectedExecutionEvidence([](auto& forged) {
                --forged.pack.coefficients_packed;
            }),
            "partial all-Y coefficient evidence did not fail closed");
    Require(rejectedExecutionEvidence([](auto& forged) {
                --forged.pack.x_trace_rotations;
            }),
            "partial trace evidence did not fail closed");
    Require(rejectedExecutionEvidence([](auto& forged) {
                --forged.pack.streamed_exponent_leaf_pair_visits;
            }),
            "partial physical pair-visit evidence did not fail closed");
    Require(rejectedExecutionEvidence([](auto& forged) {
                forged.pack.checkpoint_commitment_validated_merge_used =
                    false;
            }),
            "unvalidated checkpoint merge evidence did not fail closed");
    Require(rejectedExecutionEvidence([](auto& forged) {
                forged.pack
                    .checkpoint_replay_x_centering_monomial_multiplies =
                    forged.pack.x_centering_monomial_multiplies + 1;
            }),
            "underflowing checkpoint replay evidence did not fail closed");
    Require(rejectedExecutionEvidence([](auto& forged) {
                forged.pack_complete_coordinate_cover = false;
            }),
            "partial coordinate-cover evidence did not fail closed");
    Require(rejectedExecutionEvidence([](auto& forged) {
                forged.pack_checkpoint_chain_commitment_sha256 = "sha256:0";
            }),
            "malformed checkpoint lineage root did not fail closed");
    Require(rejectedExecutionEvidence([](auto& forged) {
                forged.value_noise_acceptance_recorded = true;
            }),
            "forged value/noise acceptance evidence did not fail closed");

    // Production policy admission is typed evidence bound to the actual
    // support commitment and authenticated estimator report.  It deliberately
    // remains distinct from (and cannot be upgraded into) value execution.
    const std::string refreshSupportCommitment =
        "openfhe-glr-canonical-refresh-support";
    const Adapter::SecurityReport refreshSecurityReport =
        MakeGl128CorridorReport(context.params, 40,
                                refreshSupportCommitment);
    std::string revokedOrdinaryRefreshAuthorizationError;
    try {
        (void)adapter.AuthorizeOrdinaryRefreshProduction(
            refreshSupportCommitment, refreshSecurityReport, 40, true);
    }
    catch (const glscheme::rns::GlrError& error) {
        revokedOrdinaryRefreshAuthorizationError = error.what();
    }
    Require(revokedOrdinaryRefreshAuthorizationError.find(
                "structured public-window one-signed-monomial-per-window") !=
                std::string::npos,
            "ordinary refresh resurrected the revoked free-support h40 "
            "production certificate");

    if constexpr (Adapter::kStructuredH40ProductionAuthorizationAvailable) {
    const Adapter::OrdinaryRefreshAuthorization refreshAuthorization =
        adapter.AuthorizeOrdinaryRefreshProduction(
            refreshSupportCommitment, refreshSecurityReport, 40, true);
    adapter.ValidateOrdinaryRefreshAuthorization(
        refreshAuthorization, refreshSupportCommitment,
        refreshSecurityReport, 40, true);
    Require(refreshAuthorization.profileBindingFingerprint.View() ==
                    profile.binding_fingerprint &&
                refreshAuthorization.supportCommitment.View() ==
                    refreshSupportCommitment &&
                refreshAuthorization.bootstrapProfileFingerprint.View() ==
                    refreshSecurityReport.bootstrap_profile_fingerprint &&
                refreshAuthorization.estimatorTranscriptSha256.View() ==
                    refreshSecurityReport.estimator_transcript_sha256,
            "ordinary-refresh authorization lost an exact report binding");
    Require(refreshAuthorization.sparseHammingWeight == 40 &&
                refreshAuthorization.foldKeyLevel == 18 &&
                refreshAuthorization.transformMaterialLevel == 17 &&
                refreshAuthorization.exposedQPrimeCount == 7 &&
                refreshAuthorization.exposedSpecialPrimeCount == 14 &&
                refreshAuthorization.reducedExposureCorridor &&
                refreshAuthorization.profileFingerprintBound &&
                refreshAuthorization.supportCommitmentBound &&
                refreshAuthorization.securityPolicyValidated &&
                refreshAuthorization.productionAuthorizationAdmitted &&
                !refreshAuthorization.productionExecutionExposed &&
                !refresh.productionExecutionExposed,
            "ordinary-refresh authorization is not exact Q7+P14/h40 "
            "policy-only evidence");
    const auto& allYReceipt =
        refreshAuthorization.nativeAllYProductionPreflight;
    Require(allYReceipt.schemaVersion == 1 &&
                allYReceipt.y_rows == 128 &&
                allYReceipt.branches_per_y_row == 2 &&
                allYReceipt.logical_all_y_branch_items == 256ULL &&
                allYReceipt.pair_major_row_tile_width == 8 &&
                allYReceipt.pair_major_row_tiles_per_centered_refresh == 16 &&
                allYReceipt.total_pair_major_branch_tile_invocations ==
                    1048576ULL &&
                allYReceipt.scalar_equivalent_branch_invocations ==
                    8388608ULL &&
                allYReceipt.scalar_equivalent_exponent_ladder_nodes ==
                    335544320ULL &&
                allYReceipt.scalar_equivalent_gadget_key_applications ==
                    671088640ULL &&
                allYReceipt.streamed_unsigned_candidate_count == 320 &&
                allYReceipt.streamed_signed_pair_count == 640 &&
                allYReceipt.streamed_signed_pairs_per_window == 16 &&
                allYReceipt.streamed_exponent_leaf_batch_invocations ==
                    41943040ULL &&
                allYReceipt.streamed_exponent_leaf_tables_batched ==
                    335544320ULL &&
                allYReceipt.streamed_exponent_leaf_pair_visits ==
                    671088640ULL &&
                allYReceipt
                        .streamed_exponent_leaf_scalar_equivalent_pair_visits ==
                    5368709120ULL &&
                allYReceipt.streamed_exponent_leaf_max_batch_size == 8 &&
                allYReceipt.streamed_exponent_leaf_peak_accumulators == 8 &&
                allYReceipt.streamed_exponent_leaf_peak_scratch_polys == 1 &&
                allYReceipt.exact_all_y_coverage &&
                allYReceipt.full_streamed_physical_schedule_pinned &&
                !allYReceipt.context_ciphertext_or_key_allocation_required &&
                allYReceipt.material_schedule_metadata_admitted &&
                !allYReceipt.ciphertext_value_execution_performed &&
                !allYReceipt.value_noise_acceptance_recorded,
            "ordinary-refresh authorization lost the canonical all-Y receipt");

    const auto rejectedAuthorizationCall = [&](const std::string& support,
                                                const auto& report,
                                                std::uint32_t h,
                                                bool corridor) {
        try {
            (void)adapter.AuthorizeOrdinaryRefreshProduction(
                support, report, h, corridor);
        }
        catch (const glscheme::rns::GlrError&) {
            return true;
        }
        return false;
    };
    Require(rejectedAuthorizationCall(
                refreshSupportCommitment + "-forged",
                refreshSecurityReport, 40, true),
            "cross-support ordinary-refresh authorization did not fail "
            "closed");
    Require(rejectedAuthorizationCall(
                refreshSupportCommitment, refreshSecurityReport, 16, true),
            "h16 ordinary-refresh authorization did not fail closed");
    Require(rejectedAuthorizationCall(
                refreshSupportCommitment, refreshSecurityReport, 40, false),
            "non-corridor ordinary-refresh authorization did not fail "
            "closed");

    Adapter::SecurityReport forgedExposureReport = refreshSecurityReport;
    forgedExposureReport.sparse_exposure_q_primes.pop_back();
    forgedExposureReport.sparse_estimate_modulus_bits = 0.0;
    for (const std::uint64_t prime :
         forgedExposureReport.sparse_exposure_q_primes) {
        forgedExposureReport.sparse_estimate_modulus_bits +=
            std::log2(static_cast<double>(prime));
    }
    Require(rejectedAuthorizationCall(
                refreshSupportCommitment, forgedExposureReport, 40, true),
            "P13 report exposure ordinary-refresh authorization did not "
            "fail closed");

    Adapter::SecurityReport forgedFingerprintReport = refreshSecurityReport;
    Require(!forgedFingerprintReport
                 .estimator_input_parameter_fingerprint.empty(),
            "test report unexpectedly lacks its parameter fingerprint");
    forgedFingerprintReport.estimator_input_parameter_fingerprint.back() ^=
        1;
    Require(rejectedAuthorizationCall(
                refreshSupportCommitment, forgedFingerprintReport, 40,
                true),
            "cross-fingerprint report ordinary-refresh authorization did "
            "not fail closed");

    const auto rejectedAuthorizationForgery = [&](auto mutate) {
        Adapter::OrdinaryRefreshAuthorization forged =
            refreshAuthorization;
        mutate(forged);
        try {
            adapter.ValidateOrdinaryRefreshAuthorization(
                forged, refreshSupportCommitment, refreshSecurityReport,
                40, true);
        }
        catch (const glscheme::rns::GlrError&) {
            return true;
        }
        return false;
    };
    Require(rejectedAuthorizationForgery([](auto& forged) {
                forged.supportCommitment.bytes[0] ^= 1;
            }),
            "copied cross-support authorization evidence did not fail "
            "closed");
    Require(rejectedAuthorizationForgery([](auto& forged) {
                --forged.nativeAllYProductionPreflight
                      .total_pair_major_branch_tile_invocations;
            }),
            "forged all-Y production receipt did not fail closed");
    Require(rejectedAuthorizationForgery([](auto& forged) {
                --forged.nativeAllYProductionPreflight
                      .streamed_exponent_leaf_pair_visits;
            }),
            "forged physical all-Y receipt did not fail closed");
    Require(rejectedAuthorizationForgery([](auto& forged) {
                forged.estimatorTranscriptSha256.bytes[0] ^= 1;
            }),
            "copied cross-report authorization evidence did not fail "
            "closed");
    Require(rejectedAuthorizationForgery([](auto& forged) {
                forged.sparseHammingWeight = 16;
            }),
            "copied h16 authorization evidence did not fail closed");
    Require(rejectedAuthorizationForgery([](auto& forged) {
                forged.exposedSpecialPrimeCount = 13;
            }),
            "copied P13 authorization evidence did not fail closed");
    Require(rejectedAuthorizationForgery([](auto& forged) {
                forged.productionAuthorizationAdmitted = false;
            }),
            "copied non-admitted authorization evidence did not fail "
            "closed");
    Require(rejectedAuthorizationForgery([](auto& forged) {
                forged.productionExecutionExposed = true;
            }),
            "copied authorization evidence overstated execution readiness");
    }

    // Planning is exact and allocation-free even for the production geometry.
    // It must deduplicate the Hermitian key shared by the explicit transform
    // and ciphertext MatMul, while retaining the two new §3.5/§3.6 families.
    Adapter::EvaluationKeyRequest allRequest;
    allRequest.rowRotations = {1, 1};
    allRequest.matrixRotations = {1};
    allRequest.transpose = true;
    allRequest.conjugation = true;
    allRequest.hermitianTranspose = true;
    allRequest.ciphertextMatMul = true;
    allRequest.ciphertextHadamard = true;
    const Adapter::EvaluationKeyPlan allPlan =
        adapter.PlanEvaluationKeys(allRequest);
    Require(allPlan.canonicalProfile == profile.canonical_name,
            "evaluation plan lost its canonical profile binding");
    Require(allPlan.parameterFingerprint == profile.binding_fingerprint,
            "evaluation plan lost its parameter fingerprint binding");
    Require(allPlan.keyLevel == 0 && allPlan.entries.size() == 7,
            "wrong deduplicated ordinary GL evaluation-key plan");
    const std::uint64_t plannedSum = std::accumulate(
        allPlan.entries.begin(), allPlan.entries.end(), std::uint64_t{0},
        [](std::uint64_t sum,
           const Adapter::EvaluationKeyPlanEntry& entry) {
            return sum + entry.residentBytes;
        });
    Require(allPlan.residentBytes == plannedSum && plannedSum > 0,
            "evaluation-key resident-byte total is not exact");
    for (const auto& entry : allPlan.entries) {
        Require(
            entry.residentBytes == glscheme::rns::glr_model_switch_key_bytes(
                                       context.params, entry.ring,
                                       static_cast<std::uint32_t>(
                                           glscheme::rns::glr_digit_groups(
                                               context.params, 0)
                                               .size())),
            "level-0 plan disagrees with the native switch-key size model");
    }
    const auto hasDirection = [&allPlan](Direction direction) {
        for (const auto& entry : allPlan.entries) {
            if (entry.id.direction == direction) {
                return true;
            }
        }
        return false;
    };
    Require(hasDirection(Direction::primary_conjtranspose_to_primary) &&
                hasDirection(
                    Direction::primary_product_conjtranspose_to_primary) &&
                hasDirection(Direction::primary_sq_to_primary),
            "ct-ct MatMul/Hadamard key debts are absent from the plan");

    Adapter::EvaluationKeyRequest lateRequest = allRequest;
    lateRequest.keyLevel =
        context.params.levels() - context.params.rescale_stride - 1;
    const auto latePlan = adapter.PlanEvaluationKeys(lateRequest);
    Require(latePlan.residentBytes < allPlan.residentBytes,
            "late-level key planning did not reduce resident bytes");

    bool rejectedNoRescaleHeadroom = false;
    try {
        Adapter::EvaluationKeyRequest invalid;
        invalid.ciphertextHadamard = true;
        invalid.keyLevel = context.params.levels() - 1;
        (void)adapter.PlanEvaluationKeys(invalid);
    }
    catch (const glscheme::rns::GlrError&) {
        rejectedNoRescaleHeadroom = true;
    }
    Require(rejectedNoRescaleHeadroom,
            "ct-ct plan without logical-rescale headroom did not fail closed");

    bool rejectedBadRotation = false;
    try {
        Adapter::EvaluationKeyRequest invalid;
        invalid.rowRotations = {128};
        (void)adapter.PlanEvaluationKeys(invalid);
    }
    catch (const glscheme::rns::GlrError&) {
        rejectedBadRotation = true;
    }
    Require(rejectedBadRotation,
            "out-of-range row-rotation key did not fail closed");

    Adapter::MatrixBatch wFreeRows;
    wFreeRows.n = 4096;
    wFreeRows.count = 1;
    bool rejectedWFreeRows = false;
    try {
        (void)adapter.Encode(wFreeRows, context.params.delta);
    }
    catch (const glscheme::rns::GlrError&) {
        rejectedWFreeRows = true;
    }
    Require(rejectedWFreeRows, "W-free dense rows aliased the GLR tensor");

    Adapter::SecretKey secretKey = adapter.KeyGen(0x474c523132383235ULL);
    Require(secretKey.key_id == "primary", "wrong key domain");
    Require(secretKey.s.ring == glscheme::rns::GlrRing::R,
            "primary key is not native ring R");
    Require(secretKey.s.extended, "primary key is missing the QP basis");
    const std::uint64_t expectedKeyResidues =
        std::uint64_t{context.active_qp_primes(0)} * 2 *
        context.params.coeffs_R();
    Require(secretKey.s.data.size() == expectedKeyResidues,
            "primary key storage does not match native GLR QP geometry");

    // The compact ring-R public key is production-sized but remains only
    // 25 MiB, so exercise real owner-side generation here.  Full R' matrix
    // plaintext/ciphertext allocation remains in the resource-qualified lane.
    Adapter::PublicKey publicKey = adapter.PublicKeyGen(
        secretKey, 0x474c525055424b45ULL);
    const std::string primarySecretLineage =
        glscheme::rns::glr_ship_direct_primary_secret_lineage_commitment(
            context, secretKey);
    Require(publicKey.key_id == "primary" &&
                publicKey.parameter_fingerprint == profile.binding_fingerprint &&
                publicKey.key_lineage_commitment == primarySecretLineage,
            "production public key lost its concrete primary-secret lineage");
    Require(publicKey.b.ring == glscheme::rns::GlrRing::R &&
                publicKey.a.ring == glscheme::rns::GlrRing::R &&
                !publicKey.b.extended && !publicKey.a.extended &&
                publicKey.byte_size() == expectedPublicKeyBytes,
            "production public key is not the compact Q-only ring-R pair");
    publicKey.secure_clear();
    Require(publicKey.key_lineage_commitment.empty(),
            "public-key secure_clear retained the secret-lineage root");

    // A nonempty production plan must be rejected before generation when the
    // caller's explicit byte budget is one byte short.  Do not materialize
    // these multi-GiB keys in this metadata test.
    bool rejectedBudget = false;
    try {
        (void)adapter.MaterializeEvaluationKeys(
            secretKey, allPlan, "metadata-test-primary-commitment",
            allPlan.residentBytes - 1, 0x4556414c4b455953ULL);
    }
    catch (const glscheme::rns::GlrError&) {
        rejectedBudget = true;
    }
    Require(rejectedBudget,
            "evaluation-key materialization ignored its byte budget");

    // Empty materialization still crosses the real provider factory and
    // proves that the exported evaluator object is parameter-bound,
    // secret-free, move-only, and contains no hidden default keys.
    const Adapter::EvaluationKeyPlan emptyPlan =
        adapter.PlanEvaluationKeys(Adapter::EvaluationKeyRequest{});
    Require(emptyPlan.entries.empty() && emptyPlan.residentBytes == 0,
            "empty evaluation plan is not allocation-free");
    bool rejectedEmptyCommitment = false;
    try {
        (void)adapter.MaterializeEvaluationKeys(secretKey, emptyPlan, "", 0);
    }
    catch (const glscheme::rns::GlrError&) {
        rejectedEmptyCommitment = true;
    }
    Require(rejectedEmptyCommitment,
            "empty primary-key commitment did not fail closed");

    Adapter::EvaluationKeyPlan forgedPlan = emptyPlan;
    forgedPlan.residentBytes = 1;
    bool rejectedForgedPlan = false;
    try {
        (void)adapter.MaterializeEvaluationKeys(
            secretKey, forgedPlan, "metadata-test-primary-commitment", 1);
    }
    catch (const glscheme::rns::GlrError&) {
        rejectedForgedPlan = true;
    }
    Require(rejectedForgedPlan,
            "forged evaluation-key plan total did not fail closed");

    auto emptyKeys = adapter.MaterializeEvaluationKeys(
        secretKey, emptyPlan, "metadata-test-primary-commitment", 0,
        0x454d5054594b4559ULL);
    Require(emptyKeys.ResidentBytes() == 0 &&
                emptyKeys.GetManifest().records.empty() &&
                !emptyKeys.GetNativeProvider().secret_material_accessed(),
            "empty evaluator provider violated its public-material contract");
    Require(!emptyKeys.HasKey({Direction::row_rotation, 1}),
            "empty evaluator provider invented a default rotation key");

    // Execution is exposed only through genuine typed non-owning material.
    // The resident DFT-bank arm is absent from the OpenFHE view, and both the
    // streamed provider and its independent external binding are mandatory.
    // A valid authenticated metadata envelope then reaches the next typed
    // gadget binding and fails before the empty ciphertext or either provider
    // payload visitor can be inspected.
    MetadataOnlyGadgetProvider metadataGadgetProvider;
    Adapter::NativeRefreshGadgetBinding metadataGadgetBinding;
    Adapter::NativeRefreshCompactSelectorManifest metadataSelector;
    Adapter::NativeRefreshCompactSelectorBinding metadataSelectorBinding;
    Adapter::SecurityReport metadataReport;
    const auto metadataDftManifest = MakeMetadataDftManifest(
        context, 17, std::ldexp(1.0, 46));
    MetadataOnlyDftProvider metadataDftProvider(metadataDftManifest);
    const auto metadataDftBinding =
        glscheme::rns::glr_dft_plaintext_binding(metadataDftManifest);
    Adapter::NativeLeasedKeyBinding metadataKeyBinding;
    Adapter::OrdinaryRefreshExecutionMaterialView metadataMaterial{
        &emptyKeys.GetNativeProvider(),
        &metadataKeyBinding,
        &metadataDftProvider,
        &metadataDftBinding,
        &metadataGadgetProvider,
        &metadataGadgetBinding,
        &metadataSelector,
        &metadataSelectorBinding,
        &metadataReport,
    };
    auto missingKeyBinding = metadataMaterial;
    missingKeyBinding.keyBinding = nullptr;
    std::string missingKeyBindingError;
    try {
        (void)adapter.ExecuteOrdinaryRefresh(Adapter::Ciphertext{},
                                             missingKeyBinding);
    }
    catch (const glscheme::rns::GlrError& error) {
        missingKeyBindingError = error.what();
    }
    Require(missingKeyBindingError.find(
                "authenticated leased KSK provider/binding") !=
                std::string::npos,
            "missing ordinary-refresh KSK binding did not fail closed");

    auto missingDftProvider = metadataMaterial;
    missingDftProvider.dftProvider = nullptr;
    std::string missingDftProviderError;
    try {
        (void)adapter.ExecuteOrdinaryRefresh(Adapter::Ciphertext{},
                                             missingDftProvider);
    }
    catch (const glscheme::rns::GlrError& error) {
        missingDftProviderError = error.what();
    }
    Require(missingDftProviderError.find("streamed-DFT provider/binding") !=
                std::string::npos,
            "missing ordinary-refresh DFT provider did not fail closed");

    auto missingDftBinding = metadataMaterial;
    missingDftBinding.dftBinding = nullptr;
    std::string missingDftBindingError;
    try {
        (void)adapter.ExecuteOrdinaryRefresh(Adapter::Ciphertext{},
                                             missingDftBinding);
    }
    catch (const glscheme::rns::GlrError& error) {
        missingDftBindingError = error.what();
    }
    Require(missingDftBindingError.find("streamed-DFT provider/binding") !=
                std::string::npos,
            "missing ordinary-refresh DFT binding did not fail closed");

    auto mismatchedDftBinding = metadataDftBinding;
    mismatchedDftBinding.expected_manifest_commitment.front() = '0';
    auto mismatchedDftMaterial = metadataMaterial;
    mismatchedDftMaterial.dftBinding = &mismatchedDftBinding;
    std::string mismatchedDftBindingError;
    try {
        (void)adapter.ExecuteOrdinaryRefresh(Adapter::Ciphertext{},
                                             mismatchedDftMaterial);
    }
    catch (const glscheme::rns::GlrError& error) {
        mismatchedDftBindingError = error.what();
    }
    Require(mismatchedDftBindingError.find("DFT plaintext provider") !=
                std::string::npos,
            "mismatched ordinary-refresh DFT binding did not fail closed");

    std::string mismatchedExternalBindingError;
    try {
        (void)adapter.ExecuteOrdinaryRefresh(Adapter::Ciphertext{},
                                             metadataMaterial);
    }
    catch (const glscheme::rns::GlrError& error) {
        mismatchedExternalBindingError = error.what();
    }
    Require(mismatchedExternalBindingError.find("SHIP gadget provider") !=
                std::string::npos,
            "mismatched ordinary-refresh external binding did not fail "
            "before execution");

    Adapter::Ciphertext malformed;
    bool rejectedMalformedCiphertext = false;
    try {
        (void)adapter.Negate(malformed);
    }
    catch (const glscheme::rns::GlrError&) {
        rejectedMalformedCiphertext = true;
    }
    Require(rejectedMalformedCiphertext,
            "undersized native ciphertext did not fail closed");
    secretKey.secure_clear();

    std::cout << "glr_production_adapter_metadata_test: ALL PASS\n";
    return 0;
}
