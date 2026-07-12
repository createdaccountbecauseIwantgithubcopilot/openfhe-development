#include "openfhe/pke/glr-production-adapter.h"

#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

void Require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

}  // namespace

int main() {
    using Adapter = lbcrypto::GLRProductionAdapter;
    using Direction = glscheme::rns::GlrKsDirection;

    Adapter adapter = Adapter::Create();
    const auto profile = adapter.GetH64ResearchProfile();
    Require(profile.schema == "glscheme.gl128_h64_research_profile.v1" &&
                profile.profile_name ==
                    glscheme::rns::kGl128H64ResearchProfileName &&
                profile.matrix_order == 128 &&
                profile.matrix_count == 256 &&
                profile.sparse_hamming_weight == 64 &&
                profile.unsigned_choices_per_support == 512 &&
                profile.signed_choices_per_support == 1024 &&
                profile.window_count == 64 &&
                profile.raw_choice_entropy_bits == 640 &&
                profile.design_structured_floor_bits == 160 &&
                profile.exact_gl128_geometry &&
                profile.distinct_from_canonical_h40 &&
                profile.canonical_h40_unchanged &&
                profile.research_full_qp_estimator_proxy_present &&
                !profile.exact_estimator_evidence_present &&
                !profile.exact_noise_evidence_present &&
                !profile.production_security_authorized,
            "H64 research profile overstates production evidence");

    const auto plan = adapter.PlanH64HiddenSelector();
    Require(plan.schema == "glscheme.gl128_h64_hidden_selector_plan.v2" &&
                plan.profile.parameter_fingerprint ==
                    profile.parameter_fingerprint &&
                plan.profile.support_commitment ==
                    profile.support_commitment &&
                plan.storage.key_level == 0 &&
                plan.storage.active_q_primes == 25 &&
                plan.storage.active_special_primes == 13 &&
                plan.storage.control_record_count == 640 &&
                plan.storage.compact_bytes_per_control_pair == 39845952ULL &&
                plan.storage.full_bytes_per_control_pair == 159383552ULL &&
                plan.storage.compact_control_material_bytes ==
                    25501409280ULL &&
                plan.storage.full_control_material_bytes ==
                    102005473280ULL &&
                plan.storage.exact_cryptographic_material_census &&
                !plan.storage.restricted_p1_research_plan &&
                !plan.storage.restricted_p1_noise_certified &&
                plan.direct_cmux_output_level == 0 &&
                plan.direct_leaf_rescale_level == 2 &&
                plan.direct_h64_root_level == 14 &&
                plan.sparse_tree_depth == 6 &&
                plan.sparse_tree_product_nodes == 63 &&
                plan.sparse_tree_frontier_input_levels ==
                    std::vector<std::uint32_t>{2, 4, 6, 8, 10, 12} &&
                plan.sparse_domain_key_requirements.size() == 3 &&
                plan.sparse_domain_key_requirements[0].id.direction ==
                    Direction::sparse_sq_to_sparse &&
                plan.sparse_domain_key_requirements[0].key_level == 2 &&
                plan.sparse_domain_key_requirements[0].special_prime_count ==
                    1 &&
                plan.sparse_domain_key_requirements[1].id.direction ==
                    Direction::conjugation_to_sparse &&
                plan.sparse_domain_key_requirements[1].key_level == 14 &&
                plan.sparse_domain_key_requirements[1]
                        .special_prime_count == 1 &&
                plan.sparse_domain_key_requirements[2].id.direction ==
                    Direction::sparse_to_primary &&
                plan.sparse_domain_key_requirements[2].key_level == 14 &&
                plan.sparse_domain_key_requirements[2]
                        .special_prime_count == 1 &&
                plan.authenticated_sparse_ksk_schedule &&
                plan.full_64_support_fold_composed &&
                !plan.primary_domain_direct_tree_compatible &&
                plan.sparse_to_primary_before_forward_stc_required &&
                !plan.production_security_authorized &&
                !plan.bootstrap_direct_admitted,
            "H64 hidden-selector plan lost its research L0/L2/L14 schedule");

    const auto wPlan = adapter.PlanH64WActionResearch();
    const auto wCapabilities =
        adapter.GetH64WActionResearchCapabilities();
    Require(wPlan.schema == glscheme::rns::kGlrH64WActionPlanSchema &&
                wPlan.operations.current_oracle_cmux_external_products ==
                    16760832ULL &&
                wPlan.operations.total_external_products == 622592ULL &&
                wPlan.material.logarithmic_compact_material_bytes ==
                    26338175296ULL &&
                wPlan.material.control_special_prime_count == 13 &&
                wPlan.material.prefix_mask_special_prime_count == 13 &&
                wPlan.material.action_key_special_prime_count == 13 &&
                wPlan.material.sparse_fold_special_prime_count == 1 &&
                wPlan.evidence.allocation_free_cryptographic_plan &&
                !wPlan.evidence.encrypted_logarithmic_circuit_executed &&
                !wPlan.evidence.exact_estimator_evidence_present &&
                !wPlan.evidence.exact_noise_evidence_present &&
                !wPlan.evidence.production_security_authorized &&
                !wPlan.evidence.bootstrap_direct_admitted &&
                !wPlan.production_security_authorized &&
                !wPlan.bootstrap_direct_admitted,
            "H64 logarithmic W-action plan overstates execution or security");
    Require(wCapabilities.schema ==
                    "openfhe.gl128_h64_w_action_research_capabilities.v1" &&
                wCapabilities.nativePlanSchema ==
                    glscheme::rns::kGlrH64WActionPlanSchema &&
                wCapabilities.currentOracleExternalProducts == 16760832ULL &&
                wCapabilities.logarithmicExternalProducts == 622592ULL &&
                wCapabilities.logarithmicCompactMaterialBytes ==
                    26338175296ULL &&
                wCapabilities.compactBytesIncludingSparseFold ==
                    26357049760ULL &&
                wCapabilities.controlSpecialPrimeCount == 13 &&
                wCapabilities.prefixMaskSpecialPrimeCount == 13 &&
                wCapabilities.actionKeySpecialPrimeCount == 13 &&
                wCapabilities.sparseFoldSpecialPrimeCount == 1 &&
                wCapabilities.allocationFreeCryptographicPlan &&
                !wCapabilities.capabilityQueryMaterializesMaterial &&
                !wCapabilities.encryptedLogarithmicCircuitExecuted &&
                !wCapabilities.exactEstimatorEvidencePresent &&
                !wCapabilities.exactNoiseEvidencePresent &&
                !wCapabilities.productionSecurityAuthorized &&
                !wCapabilities.bootstrapDirectAdmitted,
            "OpenFHE H64 W-action capability projection is malformed");

    const auto oneBit = adapter.GetH64P257OneBitCapabilities();
    Require(oneBit.schema ==
                    "openfhe.gl128_h64_p257_one_bit_capabilities.v1" &&
                oneBit.nativeMaterialSchema ==
                    "glscheme.gl128_h64_p257_one_bit_material.v1" &&
                oneBit.nativeEvidenceSchema ==
                    "glscheme.gl128_h64_p257_one_bit_evidence.v1" &&
                oneBit.matrixOrder == 128 && oneBit.matrixCount == 256 &&
                oneBit.xwCoordinatesPerRequest == 32768 &&
                oneBit.encryptedWBitsExecuted == 1 &&
                oneBit.controlSpecialPrimeCount == 13 &&
                oneBit.relinearizationSpecialPrimeCount == 13 &&
                oneBit.inputLevel == 0 && oneBit.outputLevel == 2 &&
                oneBit.cpuValueExecutionExposed &&
                oneBit.gpuValueExecutionExposed &&
                oneBit.gpuDeviceAvailable ==
                    glscheme::rns::glr_device_ks_available() &&
                oneBit.actualCiphertextProductExecuted &&
                oneBit.exactPairedRescaleExecuted &&
                !oneBit.outputReanchoredToDelta &&
                !oneBit.encryptedPrefixSpliceExecuted &&
                !oneBit.keyedWRotationsExecuted &&
                !oneBit.completeEightBitWActionExecuted &&
                !oneBit.hiddenFineXSelectionExecuted &&
                !oneBit.hiddenSignSelectionExecuted &&
                !oneBit.exactNoiseEvidencePresent &&
                !oneBit.productionSecurityAuthorized &&
                !oneBit.bootstrapDirectAdmitted,
            "OpenFHE canonical H64 one-bit capability is malformed");

    auto generateOneBit = &Adapter::GenerateH64P257OneBitMaterial;
    auto executeOneBit = &Adapter::EvaluateH64P257OneBitCpu;
    auto executeOneBitGpu = &Adapter::EvaluateH64P257OneBitGpu;
    Require(generateOneBit != nullptr && executeOneBit != nullptr &&
                executeOneBitGpu != nullptr,
            "OpenFHE canonical H64 one-bit execution seam is absent");

    const auto prefix = adapter.GetH64P257PrefixSpliceCapabilities();
    Require(prefix.schema ==
                    "openfhe.gl128_h64_p257_prefix_splice_capabilities.v1" &&
                prefix.xwCoordinatesPerRequest == 32768 &&
                prefix.encryptedWBitsExecuted == 1 &&
                prefix.controlSpecialPrimeCount == 13 &&
                prefix.maskLevel == 0 && prefix.outputLevel == 2 &&
                prefix.peakExpandedControlBytes == 159383552 &&
                prefix.cpuValueExecutionExposed &&
                prefix.encryptedBinaryMaskReturned &&
                prefix.encryptedPrefixSpliceExecuted &&
                !prefix.fixedWholeFormulaArmsSelected &&
                !prefix.keyedWRotationsExecuted &&
                !prefix.encryptedDenominatorExecuted &&
                !prefix.completeEightBitWActionExecuted &&
                !prefix.exactNoiseEvidencePresent &&
                !prefix.productionSecurityAuthorized &&
                !prefix.bootstrapDirectAdmitted,
            "OpenFHE canonical H64 prefix-splice capability is malformed");
    auto generatePrefix = &Adapter::GenerateH64P257PrefixSpliceMaterial;
    auto executePrefix = &Adapter::EvaluateH64P257PrefixSpliceCpu;
    Require(generatePrefix != nullptr && executePrefix != nullptr,
            "OpenFHE canonical H64 prefix-splice execution seam is absent");

    const auto muxrot = adapter.GetH64P257RightMuxRotCapabilities();
    Require(muxrot.schema ==
                    "openfhe.gl128_h64_p257_right_muxrot_capabilities.v1" &&
                muxrot.xwCoordinatesPerRequest == 32768 &&
                muxrot.distinctEncryptedWBitsExecuted == 1 &&
                muxrot.authenticatedWBitControlUses == 2 &&
                muxrot.rightRotationAmount == 255 &&
                muxrot.rotationKeyLevel == 2 &&
                muxrot.rotationSpecialPrimeCount == 13 &&
                muxrot.peakExpandedKeyBytes == 159383552 &&
                muxrot.cpuValueExecutionExposed &&
                muxrot.encryptedPrefixSpliceExecuted &&
                muxrot.keyedWRotationsExecuted &&
                !muxrot.encryptedDenominatorExecuted &&
                !muxrot.completeEightBitWActionExecuted &&
                !muxrot.exactNoiseEvidencePresent &&
                !muxrot.productionSecurityAuthorized &&
                !muxrot.bootstrapDirectAdmitted,
            "OpenFHE canonical H64 right-MuxRot capability is malformed");
    auto generateMuxRot = &Adapter::GenerateH64P257RightMuxRotMaterial;
    auto executeMuxRot = &Adapter::EvaluateH64P257RightMuxRotCpu;
    Require(generateMuxRot != nullptr && executeMuxRot != nullptr,
            "OpenFHE canonical H64 right-MuxRot seam is absent");

    const auto structuredAudit = adapter.AuditH64StructuredSecurity();
    const auto structuredCapabilities =
        adapter.GetH64StructuredSecurityCapabilities();
    Require(structuredAudit.schema ==
                    glscheme::rns::kGl128H64StructuredSecurityAuditSchema &&
                structuredAudit.checked_free_support_transcript.
                        reported_classical_bits ==
                    134.21396542245802 &&
                structuredAudit.checked_free_support_transcript.
                    free_support_proxy_only &&
                !structuredAudit.checked_free_support_transcript.
                    structured_distribution_modeled &&
                !structuredAudit.
                    exact_structured_security_certificate_present &&
                !structuredAudit.production_security_authorized &&
                !structuredAudit.bootstrap_direct_admitted &&
                structuredCapabilities.freeSupportProxyClassicalBits ==
                    134.21396542245802 &&
                structuredCapabilities.rawPublicWindowChoiceBits == 640 &&
                structuredCapabilities.genericSplitTimeBits == 320 &&
                structuredCapabilities.genericSplitMemoryBits == 320 &&
                structuredCapabilities.freeSupportProxyOnly &&
                !structuredCapabilities.
                    structuredPublicWindowDistributionModeled &&
                !structuredCapabilities.
                    exactStructuredSecurityCertificatePresent &&
                !structuredCapabilities.composedKeyLeakageTheoremPresent &&
                !structuredCapabilities.productionSecurityAuthorized &&
                !structuredCapabilities.bootstrapDirectAdmitted,
            "structured H64 audit must retain free-support proxy posture");

    const auto dft = adapter.GetCanonicalDirectDftGenerationConfig();
    Require(dft.profile ==
                    Adapter::NativeDftPlaintextGenerationConfig::Profile::
                        forward_only_two_record_v2 &&
                dft.forward_level == 13 && dft.inverse_level == 17 &&
                Adapter::kForwardDftPlaintextEntryCount == 2,
            "H64 forward StC is not pinned to directional DFT schema v2");

    Adapter::NativeGL128H64ResearchAllYStcEvidence evidence;
    Require(evidence.schema ==
                    "glscheme.gl128_h64_research_all_y_stc_evidence.v1" &&
                evidence.source_schedule_entries == 0 &&
                evidence.provider_resolver_calls == 0 &&
                evidence.branch_folds == 0 &&
                evidence.y_rows_composed == 0 &&
                !evidence.ciphertext_arithmetic_executed &&
                !evidence.full_all_y_stc_composed &&
                !evidence.exact_estimator_evidence_present &&
                !evidence.exact_noise_evidence_present &&
                !evidence.value_noise_acceptance_recorded &&
                !evidence.production_security_authorized &&
                !evidence.bootstrap_direct_admitted,
            "default H64 all-Y evidence overstates research execution");

    auto resolver = adapter.MakeH64AllYPublicRootProviderResolver();
    Require(static_cast<bool>(resolver),
            "H64 synchronous public-root provider resolver is absent");
    Require(Adapter::kH64AllYRows == 128 &&
                Adapter::kH64AllYBranchesPerRow == 2 &&
                Adapter::kH64AllYBranchFoldCount == 256 &&
                Adapter::NativeGL128H64ResearchPosture::research_only &&
                Adapter::NativeGL128H64ResearchPosture::
                    full_all_y_stc_composed &&
                !Adapter::NativeGL128H64ResearchPosture::
                    exact_estimator_evidence_present &&
                !Adapter::NativeGL128H64ResearchPosture::
                    exact_noise_evidence_present &&
                !Adapter::NativeGL128H64ResearchPosture::
                    production_security_claim &&
                !Adapter::NativeGL128H64ResearchPosture::
                    production_authorization_admitted,
            "OpenFHE H64 research posture is malformed");
    return 0;
}
