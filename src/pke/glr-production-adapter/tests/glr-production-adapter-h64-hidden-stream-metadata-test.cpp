#include "openfhe/pke/glr-production-adapter.h"

#include <stdexcept>
#include <string>
#include <string_view>

namespace {

void Require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

}  // namespace

int main() {
    using Adapter = lbcrypto::GLRProductionAdapter;

    const Adapter adapter = Adapter::Create();
    const bool gpuAvailable = glscheme::rns::glr_device_ks_available();

    const auto completeW = adapter.GetH64P257CompleteWGpuCapabilities();
    Require(
        completeW.schema ==
                "openfhe.gl128_h64_p257_complete_w_gpu_capabilities.v1" &&
            completeW.nativeCoreCommit ==
                "71d4252a1b3e807751c5495b65494ffab62bf2bc" &&
            completeW.nativeEvidenceSchema ==
                "glscheme.gl128_h64_p257_complete_w_gpu_evidence.v1" &&
            completeW.xwCoordinatesPerRequest == 32768 &&
            completeW.authenticatedWControls == 8 &&
            completeW.distinctEncryptedWBits == 8 &&
            completeW.keyedWAutomorphisms == 16 &&
            completeW.cmuxOperations == 8 &&
            completeW.inputLevel == 0 && completeW.outputLevel == 2 &&
            completeW.effectiveSpecialPrimeCount == 13 &&
            completeW.gpuDeviceAvailable == gpuAvailable &&
            completeW.gpuCallableExposed &&
            completeW.preparedOperandGpuCallableExposed &&
            completeW.coreCudaValueExecutionObserved &&
            !completeW.openfheNativeValueExecutionObserved &&
            completeW.completeEightBitWActionExecuted &&
            completeW.outputDeviceDirty && completeW.outputAuthoritative &&
            !completeW.hiddenFineXSelectionExecuted &&
            !completeW.hiddenSignSelectionExecuted &&
            !completeW.stationaryBFactorComposed &&
            !completeW.completeBranchPhase &&
            !completeW.full64SupportFoldComposed &&
            !completeW.fullAllYStcComposed &&
            !completeW.exactNoiseEvidencePresent &&
            !completeW.structuredSecurityCertificatePresent &&
            !completeW.gpuH64BootstrapReady &&
            !completeW.productionSecurityAuthorized &&
            !completeW.bootstrapDirectAdmitted,
        "resident complete-W GPU receipt overstates hidden/security state");

    const auto hiddenLeaf = adapter.GetH64P257HiddenLeafCapabilities();
    Require(
        hiddenLeaf.schema ==
                "openfhe.gl128_h64_p257_hidden_leaf_capabilities.v1" &&
            hiddenLeaf.nativeCoreCommit ==
                "dd48b5c888eba7e2404cf7ac5d476cc0ee11b68e" &&
            hiddenLeaf.nativeMaterialSchema ==
                "glscheme.gl128_h64_p257_hidden_leaf_material.v1" &&
            hiddenLeaf.nativePreWEvidenceSchema ==
                "glscheme.gl128_h64_p257_hidden_pre_w_operands_evidence.v1" &&
            hiddenLeaf.nativeLeafEvidenceSchema ==
                "glscheme.gl128_h64_p257_hidden_leaf_evidence.v1" &&
            hiddenLeaf.xwCoordinatesPerLeaf == 32768 &&
            hiddenLeaf.controlsPerSupportChunk == 10 &&
            hiddenLeaf.publicPrefixOperandSchedules == 4 &&
            hiddenLeaf.preWHiddenCmuxOperations == 6 &&
            hiddenLeaf.materialBindingExposed &&
            hiddenLeaf.preWCpuDelegationExposed &&
            hiddenLeaf.optimizedLeafCpuDelegationExposed &&
            hiddenLeaf.selectedFoldBindingExposed &&
            hiddenLeaf.coreOptimizedCpuValueExecutionObserved &&
            !hiddenLeaf.openfheNativeValueExecutionObserved &&
            hiddenLeaf.preWHiddenSelectionHoisted &&
            hiddenLeaf.sameIndependentOracleAsBoundedReference &&
            !hiddenLeaf.boundedReferenceCiphertextRerun &&
            hiddenLeaf.hiddenFineXSelectionExecuted &&
            hiddenLeaf.hiddenSignSelectionExecuted &&
            hiddenLeaf.completeEightBitWActionExecuted &&
            hiddenLeaf.nontransparentSparseL2LeafReturned &&
            !hiddenLeaf.stationaryBFactorComposed &&
            !hiddenLeaf.completeBranchPhase &&
            !hiddenLeaf.full64SupportHiddenControlFold &&
            !hiddenLeaf.fullAllYStcComposed &&
            !hiddenLeaf.exactEstimatorEvidencePresent &&
            !hiddenLeaf.exactNoiseEvidencePresent &&
            !hiddenLeaf.structuredSecurityCertificatePresent &&
            !hiddenLeaf.productionSecurityAuthorized &&
            !hiddenLeaf.bootstrapDirectAdmitted,
        "optimized hidden-leaf receipt overstates branch/security state");

    const auto resident =
        adapter.GetH64ResidentSelectedLeafGpuCapabilities();
    Require(
        resident.schema ==
                "openfhe.gl128_h64_resident_selected_leaf_gpu_capabilities.v1" &&
            resident.nativeCoreCommit ==
                "8fdcbc2fe3b8d58f5dcd0cc5071560c793f87432" &&
            resident.nativeReceiptSchema ==
                "glscheme.gl128_h64_resident_selected_leaf_receipt.v1" &&
            resident.h2LeafCount == 2 && resident.h4LeafCount == 4 &&
            resident.full64LeafCount == 64 && resident.leafLevel == 2 &&
            resident.h4RootLevel == 6 && resident.full64RootLevel == 14 &&
            resident.gpuDeviceAvailable == gpuAvailable &&
            resident.residentH2CallableExposed &&
            resident.residentH4CallableExposed &&
            resident.residentFull64CallableExposed &&
            resident.coreResidentH4ValueExecutionObserved &&
            !resident.residentFull64ValueExecutionObserved &&
            !resident.openfheNativeValueExecutionObserved &&
            resident.strictDeviceDirtyInputLeaves &&
            resident.authoritativeLeafReceiptsRequired &&
            resident.inputLeafOwnershipTransferred &&
            resident.zeroInputLeafCiphertextH2D &&
            resident.noStageCiphertextValuePcie &&
            !resident.hiddenControlSelectionExecuted &&
            !resident.stationaryBFactorComposed &&
            !resident.completeBranchPhase &&
            !resident.full64SupportHiddenControlFold &&
            !resident.fullAllYStcComposed &&
            !resident.exactNoiseCertificatePresent &&
            !resident.structuredSecurityCertificatePresent &&
            !resident.gpuH64BootstrapReady &&
            !resident.productionSecurityAuthorized &&
            !resident.bootstrapDirectAdmitted,
        "resident selected-leaf receipt overstates full64/security state");

    const auto stream =
        adapter.GetH64P257HiddenLeafStreamGpuCapabilities();
    Require(
        stream.schema ==
                "openfhe.gl128_h64_p257_hidden_leaf_stream_gpu_capabilities.v1" &&
            stream.nativeH4CoreCommit ==
                "baa27c4f015fae1e52ae81aa6cdd997e240b4a2b" &&
            stream.nativeStreamCoreCommit ==
                "cbb9e9de06eda3a0de0c7bf6e85b3511fbc4948b" &&
            stream.nativeOwnerSeedCoreCommit ==
                "609df4dd5bfeeb20c4b15f1a8a43046c8091316c" &&
            stream.nativeEvidenceSchema ==
                "glscheme.gl128_h64_p257_hidden_leaf_stream_gpu_evidence.v1" &&
            stream.h2LeafCount == 2 && stream.h4LeafCount == 4 &&
            stream.full64LeafCount == 64 &&
            stream.controlsPerSupportChunk == 10 &&
            stream.boundedH4CursorChunks == 4 &&
            stream.boundedH4CursorRecords == 40 &&
            stream.gpuDeviceAvailable == gpuAvailable &&
            stream.hiddenH2CallableExposed &&
            stream.hiddenH4CallableExposed &&
            stream.hiddenFull64CallableExposed &&
            stream.coreBoundedH4CompositionValueExecutionObserved &&
            !stream.nativeStreamWrapperValueExecutionObserved &&
            !stream.full64ValueExecutionObserved &&
            !stream.openfheNativeValueExecutionObserved &&
            stream.evaluatorSecretFree &&
            stream.maxLiveOneSupportDeployment &&
            stream.supportLocalPrefixMaterialJit &&
            stream.oneSharedActionKeyBundleRequired &&
            stream.ownerSeedCommitmentReceiptExposed &&
            stream.oneOwnerSeedCommitmentRequired &&
            stream.optimizedPreWHiddenSelectionExecuted &&
            stream.completeEightBitWActionExecuted &&
            stream.authoritativeDeviceDirtyL2Leaves &&
            stream.zeroReturnedLeafToFoldPcie &&
            stream.residentP14FrontierExecutedInBoundedH4 &&
            !stream.full64SupportHiddenControlFold &&
            !stream.stationaryBFactorComposed &&
            !stream.completeBranchPhase &&
            !stream.fullAllYStcComposed &&
            !stream.exactNoiseCertificatePresent &&
            !stream.structuredSecurityCertificatePresent &&
            !stream.gpuH64BootstrapReady &&
            !stream.productionSecurityAuthorized &&
            !stream.bootstrapDirectAdmitted,
        "hidden stream receipt overstates full64/branch/security state");

    const Adapter::NativeGL128H64P257HiddenLeafStreamGpuEvidence emptyReceipt;
    Require(emptyReceipt.owner_seed_commitment.empty() &&
                !emptyReceipt.one_owner_seed_commitment_bound &&
                !emptyReceipt.complete_64_support_hidden_control_fold &&
                !emptyReceipt.stationary_b_factor_composed &&
                !emptyReceipt.complete_branch_phase &&
                !emptyReceipt.full_all_y_composed &&
                !emptyReceipt.exact_noise_certificate_present &&
                !emptyReceipt.structured_security_certificate_present &&
                !emptyReceipt.production_security_authorized &&
                !emptyReceipt.gpu_h64_bootstrap_ready,
            "default owner-seed stream receipt must fail closed");

    return 0;
}
