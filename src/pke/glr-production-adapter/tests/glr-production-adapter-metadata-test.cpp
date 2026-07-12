#include "openfhe/pke/glr-production-adapter.h"

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
    report.estimator_transcript_sha256 = std::string(64, 'b');
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
                  Adapter::OrdinaryRefreshAuthorization>);
    static_assert(std::is_aggregate_v<
                  Adapter::OrdinaryRefreshExecutionMaterialView>);
    static_assert(std::is_trivially_copyable_v<
                  Adapter::OrdinaryRefreshExecutionMaterialView>);
    using ExecutionMaterial =
        Adapter::OrdinaryRefreshExecutionMaterialView;
    static_assert(std::is_same_v<
                  decltype(std::declval<ExecutionMaterial>().keyProvider),
                  const Adapter::NativeKeyProvider*>);
    static_assert(std::is_same_v<
                  decltype(std::declval<ExecutionMaterial>().dftBank),
                  const Adapter::NativeRefreshDftBank*>);
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
    Require(nullExecutionMaterialError.find("non-null KSK") !=
                std::string::npos,
            "null ordinary-refresh execution material did not fail closed");

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
                refresh.dftBankRequired &&
                !refresh.productionExecutionExposed &&
                refresh.compactSelectorBindingRequired &&
                refresh.streamedGadgetProviderRequired,
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
                forged.streamedGadgetProviderRequired = false;
            }),
            "forged streamed-gadget requirement did not fail closed");

    // Production policy admission is typed evidence bound to the actual
    // support commitment and authenticated estimator report.  It deliberately
    // remains distinct from (and cannot be upgraded into) value execution.
    const std::string refreshSupportCommitment =
        "openfhe-glr-canonical-refresh-support";
    const Adapter::SecurityReport refreshSecurityReport =
        MakeGl128CorridorReport(context.params, 40,
                                refreshSupportCommitment);
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
    Require(publicKey.key_id == "primary" &&
                publicKey.parameter_fingerprint == profile.binding_fingerprint,
            "production public key lost its primary/fingerprint binding");
    Require(publicKey.b.ring == glscheme::rns::GlrRing::R &&
                publicKey.a.ring == glscheme::rns::GlrRing::R &&
                !publicKey.b.extended && !publicKey.a.extended &&
                publicKey.byte_size() == expectedPublicKeyBytes,
            "production public key is not the compact Q-only ring-R pair");
    publicKey.secure_clear();

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

    // Non-null is not sufficient.  First an unpinned DFT bank, then a
    // superficially level/scale-correct bank joined to an invalid external
    // gadget opening, must both fail before the empty ciphertext is inspected
    // and before MetadataOnlyGadgetProvider::visit_pair can run.
    MetadataOnlyGadgetProvider metadataGadgetProvider;
    Adapter::NativeRefreshGadgetBinding metadataGadgetBinding;
    Adapter::NativeRefreshCompactSelectorManifest metadataSelector;
    Adapter::NativeRefreshCompactSelectorBinding metadataSelectorBinding;
    Adapter::SecurityReport metadataReport;
    Adapter::NativeRefreshDftBank metadataDft;
    Adapter::OrdinaryRefreshExecutionMaterialView metadataMaterial{
        &emptyKeys.GetNativeProvider(),
        &metadataDft,
        &metadataGadgetProvider,
        &metadataGadgetBinding,
        &metadataSelector,
        &metadataSelectorBinding,
        &metadataReport,
    };
    std::string mismatchedDftError;
    try {
        (void)adapter.ExecuteOrdinaryRefresh(Adapter::Ciphertext{},
                                             metadataMaterial);
    }
    catch (const glscheme::rns::GlrError& error) {
        mismatchedDftError = error.what();
    }
    Require(mismatchedDftError.find("level-17 DFT bank") !=
                std::string::npos,
            "mismatched ordinary-refresh DFT material did not fail closed");

    metadataDft.level = 17;
    metadataDft.scale = std::ldexp(1.0, 46);
    metadataDft.u_x_fwd.level = 17;
    metadataDft.u_x_inv.level = 17;
    metadataDft.u_w_fwd.level = 17;
    metadataDft.u_w_inv.level = 17;
    metadataDft.u_x_fwd.poly.level = 17;
    metadataDft.u_x_inv.poly.level = 17;
    metadataDft.u_w_fwd.poly.level = 17;
    metadataDft.u_w_inv.poly.level = 17;
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
