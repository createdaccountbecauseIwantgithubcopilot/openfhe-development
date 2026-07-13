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

    const auto selectedFold =
        adapter.GetH64SelectedLeafFoldCapabilities();
    Require(selectedFold.schema ==
                    "openfhe.gl128_h64_selected_leaf_fold_capabilities.v1" &&
                selectedFold.nativeCoreCommit ==
                    "3f2675b1514f6535e63164074bf079bc8ecc7f36" &&
                selectedFold.nativeBindingSchema ==
                    "glscheme.gl128_h64_selected_leaf_fold_binding.v1" &&
                selectedFold.nativeEvidenceSchema ==
                    "glscheme.gl128_h64_selected_leaf_fold_evidence.v1" &&
                selectedFold.parameterFingerprint ==
                    "glrsha256:66a12778024471924327683b7f52e8df4dd038cb3f7f803a516b393e1363e6ab" &&
                selectedFold.supportCommitment ==
                    "glr-ship-support-v1:n=128:phi=256:count=64:fnv64=16830100300970850058" &&
                selectedFold.matrixOrder == 128 &&
                selectedFold.matrixCount == 256 &&
                selectedFold.xwCoordinatesPerLeaf == 32768 &&
                selectedFold.selectedLeafCount == 64 &&
                selectedFold.leafLevel == 2 &&
                selectedFold.rootLevel == 14 &&
                selectedFold.outputLevel == 14 &&
                selectedFold.frontierInputLevels ==
                    std::array<std::uint32_t, 6>{2, 4, 6, 8, 10, 12} &&
                selectedFold.frontierProductCounts ==
                    std::array<std::uint32_t, 6>{32, 16, 8, 4, 2, 1} &&
                selectedFold.treeProductNodes == 63 &&
                selectedFold.treeRelinearizations == 63 &&
                selectedFold.treePairedRescales == 63 &&
                selectedFold.physicalQPrimeDrops == 126 &&
                selectedFold.conjugationToSparseSwitches == 1 &&
                selectedFold.sparseToPrimarySwitches == 1 &&
                selectedFold.sparseRelinKeyLeases == 1 &&
                selectedFold.fullP14SpecialPrimeSentinel == 0 &&
                selectedFold.effectiveSpecialPrimeCount == 14 &&
                selectedFold.compactThreeKeyBytes == 32505952 &&
                selectedFold.peakLiveLeafLeases == 1 &&
                selectedFold.peakLiveSparseTreeFrontierCiphertexts == 7 &&
                selectedFold.peakLiveEvaluationKeys == 1 &&
                selectedFold.cpuValueDelegationExposed &&
                selectedFold.coreOwnerAcceptanceValueExecuted &&
                !selectedFold.frameworkNativeValuePassExecuted &&
                selectedFold.randomizedNontransparentSparseLeavesRequired &&
                selectedFold.synchronousOneLeafProviderRequired &&
                selectedFold.fullP14FoldScheduleRequired &&
                !selectedFold.underprovisionedP13Accepted &&
                !selectedFold.restrictedP1Accepted &&
                !selectedFold.hiddenControlSelectionExecuted &&
                !selectedFold.full64SupportHiddenControlFold &&
                !selectedFold.fullAllYStcComposed &&
                !selectedFold.exactEstimatorEvidencePresent &&
                !selectedFold.formalComposedNoiseCertificatePresent &&
                !selectedFold.structuredSecurityCertificatePresent &&
                !selectedFold.gpuValueExecutionExposed &&
                !selectedFold.productionSecurityAuthorized &&
                !selectedFold.bootstrapDirectAdmitted,
            "OpenFHE H64 selected-leaf fold capability is malformed");
    auto executeSelectedFold = &Adapter::EvaluateH64SelectedLeafFoldCpu;
    Require(executeSelectedFold != nullptr,
            "OpenFHE H64 selected-leaf fold delegation seam is absent");

    const auto ownerCursor =
        adapter.GetH64HiddenSelectorOwnerCursorCapabilities();
    Require(ownerCursor.schema ==
                    "openfhe.gl128_h64_hidden_selector_owner_cursor_capabilities.v1" &&
                ownerCursor.nativeCoreCommit ==
                    "599dde94b91b10249eb6d222e008bf67b5b6b457" &&
                ownerCursor.parameterFingerprint ==
                    "glrsha256:66a12778024471924327683b7f52e8df4dd038cb3f7f803a516b393e1363e6ab" &&
                ownerCursor.supportCommitment ==
                    "glr-ship-support-v1:n=128:phi=256:count=64:fnv64=16830100300970850058" &&
                ownerCursor.sparseSupportCount == 64 &&
                ownerCursor.controlsPerSupport == 10 &&
                ownerCursor.canonicalControlRecordCount == 640 &&
                ownerCursor.materialKeyLevel == 0 &&
                ownerCursor.materialSpecialPrimeCount == 13 &&
                ownerCursor.minimumRecordsPerEmission == 1 &&
                ownerCursor.maximumRecordsPerEmission == 10 &&
                ownerCursor.boundedAcceptanceRecordsEmitted == 10 &&
                ownerCursor.boundedAcceptanceChunkPattern ==
                    std::array<std::uint32_t, 2>{1, 9} &&
                ownerCursor.recordsLoadedOrVerifiedPerEmission == 0 &&
                ownerCursor.peakLiveFullPairs == 1 &&
                ownerCursor.peakLiveCompactRecords == 1 &&
                ownerCursor.ownerOnly && ownerCursor.moveOnlyCursor &&
                ownerCursor.storeOnlySink &&
                !ownerCursor.loadCallbackExposed &&
                ownerCursor.privateLibraryCheckpointState &&
                ownerCursor.privateCheckpointUnforgeableByPublicApi &&
                !ownerCursor.callerCheckpointInjectionExposed &&
                ownerCursor.poisonedPersistenceRetryRejected &&
                ownerCursor.exactlyOnceChunkProgressionExecuted &&
                ownerCursor.legacyRecordZeroByteParity &&
                ownerCursor.boundedFirstSupportGenerationExecuted &&
                !ownerCursor.canonical640RecordExecutionCompleted &&
                !ownerCursor.completeManifestProduced &&
                !ownerCursor.fullMaterialBankMaterialized &&
                !ownerCursor.full64SupportHiddenControlFold &&
                !ownerCursor.fullAllYStcComposed &&
                !ownerCursor.exactEstimatorEvidencePresent &&
                !ownerCursor.exactNoiseEvidencePresent &&
                !ownerCursor.structuredSecurityCertificatePresent &&
                !ownerCursor.gpuExecutionExposed &&
                !ownerCursor.productionSecurityAuthorized &&
                !ownerCursor.bootstrapDirectAdmitted,
            "OpenFHE H64 owner cursor capability is malformed");
    auto createOwnerCursor =
        &Adapter::CreateH64HiddenSelectorOwnerCursor;
    auto emitOwnerCursor =
        &Adapter::EmitNextH64HiddenSelectorOwnerCursorChunk;
    Require(createOwnerCursor != nullptr && emitOwnerCursor != nullptr,
            "OpenFHE H64 owner cursor material seam is absent");

    const auto gpuH4 =
        adapter.GetH64SelectedLeafH4GpuCapabilities();
    Require(gpuH4.schema ==
                    "openfhe.gl128_h64_selected_leaf_h4_gpu_capabilities.v1" &&
                gpuH4.nativeCoreCommit ==
                    "f9324e8a73f8ca98e0bc4e334890e0e83a84f3e1" &&
                gpuH4.nativeEvidenceSchema ==
                    "glscheme.gl128_h64_selected_leaf_gpu_frontier_evidence.v1" &&
                gpuH4.parameterFingerprint ==
                    "glrsha256:66a12778024471924327683b7f52e8df4dd038cb3f7f803a516b393e1363e6ab" &&
                gpuH4.supportCommitment ==
                    "glr-ship-support-v1:n=128:phi=256:count=64:fnv64=16830100300970850058" &&
                gpuH4.selectedLeafCount == 4 &&
                gpuH4.xwCoordinatesPerLeaf == 32768 &&
                gpuH4.treeDepth == 2 && gpuH4.leafLevel == 2 &&
                gpuH4.rootLevel == 6 &&
                gpuH4.frontierInputLevels ==
                    std::array<std::uint32_t, 2>{2, 4} &&
                gpuH4.frontierProductCounts ==
                    std::array<std::uint32_t, 2>{2, 1} &&
                gpuH4.treeProductNodes == 3 &&
                gpuH4.treeRelinearizations == 3 &&
                gpuH4.treePairedRescales == 3 &&
                gpuH4.physicalQPrimeDrops == 6 &&
                gpuH4.fullP14SpecialPrimeSentinel == 0 &&
                gpuH4.effectiveSpecialPrimeCount == 14 &&
                gpuH4.inputLeafBoundaryH2DBytes == 96468992 &&
                gpuH4.ownerReadbackD2HBytes == 19922944 &&
                gpuH4.stageCiphertextValueH2DBytes == 0 &&
                gpuH4.stageCiphertextValueD2HBytes == 0 &&
                gpuH4.decryptedCoordinateCount == 32768 &&
                gpuH4.maximumObservedValueError == 1.086e-10 &&
                gpuH4.internalRuntimeSeconds == 5.81 &&
                gpuH4.wallRuntimeSeconds == 6.00 &&
                gpuH4.peakRssMiB == 595.46 &&
                gpuH4.deviceConditional &&
                gpuH4.gpuDeviceAvailable ==
                    glscheme::rns::glr_device_ks_available() &&
                gpuH4.gpuCallableExposed &&
                gpuH4.coreCudaValueExecutionObserved &&
                !gpuH4.openfheNativeValueExecutionObserved &&
                gpuH4.randomizedNontransparentSparseLeaves &&
                gpuH4.exactP14SparseRelinearizationExecuted &&
                gpuH4.exactN32PairedRescalesExecuted &&
                gpuH4.exactInputUploadOnce &&
                gpuH4.noStageCiphertextValuePcie &&
                gpuH4.outputDeviceDirty && gpuH4.outputAuthoritative &&
                gpuH4.exactCpuCiphertextByteParity &&
                gpuH4.allCoordinatesOwnerDecrypted &&
                !gpuH4.hiddenControlSelectionExecuted &&
                !gpuH4.complete64SupportFoldExecuted &&
                !gpuH4.conjugationReturnExecuted &&
                !gpuH4.sparseToPrimaryReturnExecuted &&
                !gpuH4.fullAllYStcComposed &&
                !gpuH4.exactNoiseCertificatePresent &&
                !gpuH4.structuredSecurityCertificatePresent &&
                !gpuH4.gpuH64BootstrapReady &&
                !gpuH4.productionSecurityAuthorized &&
                !gpuH4.bootstrapDirectAdmitted,
            "OpenFHE H64 h4 GPU frontier capability is malformed");
    auto executeGpuH4 =
        &Adapter::EvaluateH64SelectedLeafH4GpuFrontier;
    Require(executeGpuH4 != nullptr,
            "OpenFHE H64 h4 GPU frontier seam is absent");

    const auto gpu64 =
        adapter.GetH64SelectedLeaf64GpuCapabilities();
    Require(gpu64.schema ==
                    "openfhe.gl128_h64_selected_leaf_64_gpu_capabilities.v1" &&
                gpu64.nativeCoreCommit ==
                    "cef5ac76b72b9c4b6da2e6d14519172305002739" &&
                gpu64.nativeEvidenceSchema ==
                    "glscheme.gl128_h64_selected_leaf_gpu_frontier_evidence.v1" &&
                gpu64.parameterFingerprint ==
                    "glrsha256:66a12778024471924327683b7f52e8df4dd038cb3f7f803a516b393e1363e6ab" &&
                gpu64.supportCommitment ==
                    "glr-ship-support-v1:n=128:phi=256:count=64:fnv64=16830100300970850058" &&
                gpu64.selectedLeafCount == 64 &&
                gpu64.xwCoordinatesPerLeaf == 32768 &&
                gpu64.treeDepth == 6 && gpu64.leafLevel == 2 &&
                gpu64.rootLevel == 14 &&
                gpu64.frontierInputLevels ==
                    std::array<std::uint32_t, 6>{2, 4, 6, 8, 10, 12} &&
                gpu64.frontierProductCounts ==
                    std::array<std::uint32_t, 6>{32, 16, 8, 4, 2, 1} &&
                gpu64.treeProductNodes == 63 &&
                gpu64.treeRelinearizations == 63 &&
                gpu64.treePairedRescales == 63 &&
                gpu64.physicalQPrimeDrops == 126 &&
                gpu64.fullP14SpecialPrimeSentinel == 0 &&
                gpu64.effectiveSpecialPrimeCount == 14 &&
                gpu64.inputLeafBoundaryH2DBytes == 1543503872 &&
                gpu64.ownerReadbackD2HBytes == 11534336 &&
                gpu64.stageCiphertextValueH2DBytes == 0 &&
                gpu64.stageCiphertextValueD2HBytes == 0 &&
                gpu64.decryptedCoordinateCount == 32768 &&
                gpu64.maximumObservedValueError == 4.340e-10 &&
                gpu64.internalRuntimeSeconds == 34.71 &&
                gpu64.wallRuntimeSeconds == 34.92 &&
                gpu64.peakRssMiB == 604.52 &&
                gpu64.deviceConditional &&
                gpu64.gpuDeviceAvailable ==
                    glscheme::rns::glr_device_ks_available() &&
                gpu64.gpuCallableExposed &&
                gpu64.coreCudaValueExecutionObserved &&
                !gpu64.openfheNativeValueExecutionObserved &&
                gpu64.randomizedNontransparentSparseLeaves &&
                gpu64.exactP14SparseRelinearizationExecuted &&
                gpu64.exactN32PairedRescalesExecuted &&
                gpu64.exactSixFrontierL2ToL14Schedule &&
                gpu64.complete64SelectedLeafProductTreeExecuted &&
                gpu64.exactInputUploadOnce &&
                gpu64.noStageCiphertextValuePcie &&
                gpu64.outputDeviceDirty && gpu64.outputAuthoritative &&
                gpu64.allCoordinatesOwnerDecrypted &&
                !gpu64.hiddenControlSelectionExecuted &&
                !gpu64.complete64SupportHiddenControlFold &&
                !gpu64.conjugationReturnExecuted &&
                !gpu64.sparseToPrimaryReturnExecuted &&
                !gpu64.fullAllYStcComposed &&
                !gpu64.exactNoiseCertificatePresent &&
                !gpu64.structuredSecurityCertificatePresent &&
                !gpu64.gpuH64BootstrapReady &&
                !gpu64.productionSecurityAuthorized &&
                !gpu64.bootstrapDirectAdmitted,
            "OpenFHE H64 selected-leaf 64 GPU capability is malformed");
    auto executeGpu64 =
        &Adapter::EvaluateH64SelectedLeaf64GpuTree;
    Require(executeGpu64 != nullptr,
            "OpenFHE H64 selected-leaf 64 GPU seam is absent");

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
