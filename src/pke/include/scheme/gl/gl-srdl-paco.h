//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#ifndef LBCRYPTO_PKE_SCHEME_GL_SRDL_PACO_H
#define LBCRYPTO_PKE_SCHEME_GL_SRDL_PACO_H

#include "scheme/gl/gl-schemelet.h"

#include <cstdint>
#include <string>

namespace lbcrypto {

/**
 * Fail-closed contract for the external GLScheme SRDL PaCo provider.
 *
 * OpenFHE intentionally does not copy the profile compiler, exact prefix
 * oracle, frozen Q/P arithmetic-control factory, hybrid-gadget receipt, bank
 * catalog, evaluator-public polyphase builder, explicit candidate-phase
 * encoder, typed phase--bank scheduler, physical Z/W evaluators, staged
 * early-gauge suffix, Native-C adapter/entry/input/bank/phase/proof-K2/
 * normalized-ZInvSum/W composition, proof-carrying K5/K6 suffix, residue-X/
 * grouped-output contracts, encrypted grouped-M4 evaluator, exact sigma
 * aggregation, authenticated PackY assembly, final forward-U_W standard-output
 * evaluator, typed CUDA K2 and single-Y/16-sigma M4 payload-parity admission,
 * SM89 resource/device-limit planning, confidential
 * factor container, or owner structured-key/input-switch operations. Those
 * remain owned by GLScheme::glscheme. This record makes each dependency
 * boundary inspectable without claiming that standalone OpenFHE can execute
 * any of them or perform an SRDL bootstrap.
 */
struct GLSRDLPacoContractCapabilities {
    std::string schema;
    std::string requiredCMakeTarget;
    std::string requiredHeader;
    std::string requiredBankHeader;
    std::string requiredPhaseBankHeader;
    std::string requiredPublicPolyphaseHeader;
    std::string requiredPhaseCandidateHeader;
    std::string requiredBlockZHeader;
    std::string requiredWHeader;
    std::string requiredSuffixHeader;
    std::string requiredOwnerHeader;
    std::string requiredHybridKsHeader;
    std::string requiredCudaHeader;
    std::string requiredNativeCAdapterHeader;
    std::string requiredNativeCEntryHeader;
    std::string requiredNativeCInputHeader;
    std::string requiredNativeCBankHeader;
    std::string requiredNativeCPhaseHeader;
    std::string requiredNativeCProofK2Header;
    std::string requiredNativeCZInvSumHeader;
    std::string requiredNativeCWHeader;
    std::string requiredNativeCZWHeader;
    std::string requiredNativeCSuffixHeader;
    std::string requiredNativeCOutputHeader;
    std::string requiredGroupedXPhysicalHeader;
    std::string requiredGroupedXEncryptedHeader;
    std::string requiredNativeCPackHeader;
    std::string requiredNativeCStandardOutputHeader;
    std::string requiredNativeCCudaK2Header;
    std::string requiredNativeCCudaM4BatchHeader;
    std::string requiredSm89PlannerHeader;
    std::string requiredDirectGaugeMathHeader;
    std::string requiredDirectGaugeRowCompilerHeader;
    std::string requiredDirectGaugeBankHeader;
    std::string requiredDirectGaugeCpuHeader;
    std::string requiredDirectGaugeSuffixHeader;
    std::string requiredDirectGaugeCoreHeader;
    std::string requiredPacoSourceSpecSha256;
    std::string requiredGpuSourceSpecSha256;
    std::string requiredNativeCSourceSpecFilename;
    std::string requiredNativeCSourceSpecSha256;
    std::string requiredNativeCRevision;
    std::string requiredDirectGaugeSourceSpecFilename;
    std::string requiredDirectGaugeSourceSpecSha256;
    std::string requiredDirectGaugeContractVersion;
    std::string requiredDirectGaugeCoreContractVersion;
    std::string requiredContractVersion;
    std::string requiredNativeCAdapterContractVersion;
    std::string requiredBankCiphertextSetSchema;
    std::string requiredPhaseBankBatchSchema;
    std::string requiredPhaseBankEvaluationSchema;
    std::string requiredPhaseSourceCommitmentSchema;
    std::string requiredPublicPolyphaseSchema;
    std::string requiredPhaseCandidateBatchSchema;
    std::string requiredEarlyGaugeSuffixManifestSchema;
    std::string requiredEarlyGaugeSuffixReceiptSchema;
    std::string requiredCudaPublicPhaseReceiptSchema;
    std::string requiredCudaPhaseBankReceiptSchema;
    std::string requiredCudaBlockZReceiptSchema;
    std::string requiredCudaBlockZBranchReceiptSchema;
    std::string requiredNativeCAdapterSchema;
    std::string requiredNativeCEntryBatchSchema;
    std::string requiredNativeCEntrySwitchBatchSchema;
    std::string requiredNativeCLowInputSliceSchema;
    std::string requiredNativeCBankGeneratorSchema;
    std::string requiredNativeCPhaseBatchSchema;
    std::string requiredNativeCProofK2ResultSchema;
    std::string requiredNativeCZInvSumResultSchema;
    std::string requiredNativeCWResultSchema;
    std::string requiredNativeCZWResultSchema;
    std::string requiredNativeCSuffixResultSchema;
    std::string requiredNativeCResidueXSynthesisResultSchema;
    std::string requiredGroupedXSynthesisManifestSchema;
    std::string requiredGroupedXPhysicalManifestSchema;
    std::string requiredGroupedXEncryptedResultSchema;
    std::string requiredNativeCSigmaSumResultSchema;
    std::string requiredNativeCPackedYResultSchema;
    std::string requiredNativeCStandardOutputResultSchema;
    std::string requiredNativeCCudaK2ResultSchema;
    std::string requiredNativeCCudaK2RuntimePlanSchema;
    std::string requiredNativeCCudaM4BatchKernelResourcesSchema;
    std::string requiredNativeCCudaM4BatchRuntimePlanSchema;
    std::string requiredNativeCCudaM4BatchResultSchema;
    std::string requiredSm89PlannerSchema;
    std::string requiredSm89DeviceLimitQuerySchema;
    std::string requiredDirectGaugeReferenceSchema;
    std::string requiredDirectGaugeRowCompilerSchema;
    std::string requiredDirectGaugeBankSchema;
    std::string requiredDirectGaugeCpuPrefixSchema;
    std::string requiredDirectGaugeSuffixManifestSchema;
    std::string requiredDirectGaugeSuffixResultSchema;
    std::string requiredDirectGaugeCoreManifestSchema;
    std::string requiredDirectGaugeCoreReceiptSchema;
    std::string requiredNativeCZInvSumContractVersion;
    std::string requiredNativeCZInverseTransformBinding;
    std::string requiredNativeCWContractVersion;
    std::string requiredNativeCZWContractVersion;
    std::string requiredNativeCSuffixContractVersion;
    std::string requiredNativeCResidueXSynthesisContractVersion;
    std::string requiredGroupedXEncryptedContractVersion;
    std::string requiredNativeCSigmaSumContractVersion;
    std::string requiredNativeCPackedYContractVersion;
    std::string requiredNativeCStandardOutputContractVersion;
    std::string requiredLayoutPrefix;
    std::string requiredFactorShardBindingId;
    std::string requiredControlParameterFactory;
    std::string requiredControlParameterName;
    std::uint32_t targetN{64};
    std::uint32_t targetP{67};
    std::uint32_t targetPhi{66};
    std::uint32_t targetOuterYSlices{64};
    std::uint64_t baseSliceIntegerRank{8448};
    std::uint64_t baseKskDigitRowScalarResiduesPerLimb{16896};
    std::uint64_t fullKskDigitRowScalarResiduesPerLimb{1081344};
    std::uint32_t requiredPacoSwitchBigInvocationCount{0};
    std::uint32_t requiredControlQPrimeCount{12};
    std::uint32_t requiredControlSpecialPrimeCount{4};
    std::uint32_t requiredControlSelectedSpecialPrimeCount{3};
    bool hammingWeightRequired{true};
    bool externalProviderRequired{true};
    bool externalPhaseSourcePayloadBindingRequired{true};
    bool externalPublicPolyphaseBuilderRequired{true};
    bool externalImmutablePublicPolyphaseResultRequired{true};
    bool externalPhaseCandidateEncoderRequired{true};
    bool externalImmutablePhaseBankResultRequired{true};
    bool externalImmutableCudaPhaseBankResultRequired{true};
    bool externalImmutableCudaBlockZBranchResultRequired{true};
    bool externalImmutableEarlyGaugeSuffixResultRequired{true};
    bool externalFrozenControlParameterFactoryRequired{true};
    bool externalNativeCAdapterRequired{true};
    bool externalNativeCEntryRequired{true};
    bool externalNativeCEntryArtifactCommitmentRequired{true};
    bool externalNativeCEntryEveryActualSliceBindingRequired{true};
    bool externalNativeCEntryDeterministicArtifactRequired{true};
    bool externalNativeCInputRequired{true};
    bool externalNativeCLowBatchSourceEntryArtifactRequired{true};
    bool externalNativeCLowBatchArtifactCommitmentRequired{true};
    bool externalNativeCLowBatchEveryActualSwitchedSliceBindingRequired{true};
    bool externalNativeCLowBatchDeterministicArtifactRequired{true};
    bool externalNativeCBankRequired{true};
    bool externalNativeCPhaseRequired{true};
    bool externalNativeCProofK2Required{true};
    bool externalNativeCZInvSumRequired{true};
    bool externalNativeCWRequired{true};
    bool externalNativeCZWRequired{true};
    bool externalNativeCSuffixRequired{true};
    bool externalNativeCOutputContractsRequired{true};
    bool externalGroupedM4PhysicalClearManifestRequired{true};
    bool externalEncryptedGroupedM4ProviderRequired{true};
    bool externalImmutableGroupedM4ResultRequired{true};
    bool externalExactSigmaAggregationProviderRequired{true};
    bool externalImmutableSigmaSumResultRequired{true};
    bool externalAuthenticatedPackYProviderRequired{true};
    bool externalPackYCommonEntryProvenanceRequired{true};
    bool externalPackYEveryYActualCiphertextRehashRequired{true};
    bool externalPackYSourceEntryArtifactRequired{true};
    bool externalImmutablePackedYResultRequired{true};
    bool externalFinalForwardUwStandardOutputProviderRequired{true};
    bool externalStandardOutputSourceEntryArtifactRequired{true};
    bool externalImmutableStandardGLOutputResultRequired{true};
    bool externalNativeCCudaK2Required{true};
    bool externalNativeCCudaM4BatchKernelResourceQueryRequired{true};
    bool externalNativeCCudaM4BatchPlannerRequired{true};
    bool externalNativeCCudaM4BatchSingleYAdmissionRequired{true};
    bool externalImmutableNativeCCudaM4BatchResultRequired{true};
    bool externalSm89PlannerRequired{true};
    bool externalSm89DeviceLimitQueryRequired{true};
    bool externalDirectGaugeReferenceCompilerRequired{true};
    bool externalDirectGaugeRowCompilerRequired{true};
    bool externalDirectGaugeNontrivialBankSetRequired{true};
    bool externalDirectGaugeCpuPrefixRequired{true};
    bool externalDirectGaugeGaugeFreeSuffixRequired{true};
    bool externalDirectGaugeAuthenticatedCpuCoreRequired{true};
    bool externalImmutableDirectGaugeCpuCoreResultRequired{true};
    bool postCrossYEntryBoundaryRequired{true};
    bool sharedSwitchSmallKeyAcrossYSlicesRequired{true};
    bool normalizedZInvSumRequired{true};
    bool coefficientProjectionCommutesWithDecryption{true};
    bool coefficientSlabsAlgebraicallySeparableUnderSharedSecret{true};
    bool coefficientProjectionRingHomomorphism{false};
    bool coefficientSlabsIndependentRingFactors{false};
    bool genericAndHadamardMultiplicationMayCoupleYSlices{true};
    bool pacoKeyGraphBaseRingOnlyRequired{true};
    bool universalM64GemmBatching{false};
    bool exactGroupedM4LogicalManifestRequired{true};
    // Unprefixed admission/execution capabilities describe standalone
    // OpenFHE only. External proof-carrying results do not turn these on.
    bool groupedM4PhysicalEvaluationAdmitted{false};
    bool nativeCExactM1ResidueXSynthesisOnly{true};
    bool cudaArchitectureSm89OrOlderOnly{true};
    bool postSm89FeaturesPermitted{false};
    bool localManifestCompiler{false};
    bool localSelectorLayoutSelfCheck{false};
    bool localExactPrefixOracle{false};
    bool localBankCatalog{false};
    bool localPhaseBankScheduler{false};
    bool localPhaseCandidateEncoder{false};
    bool localGenericBlockZEvaluator{false};
    bool localGenericWEvaluator{false};
    bool localEarlyGaugeSuffix{false};
    bool localOwnerStructuredSecret{false};
    bool localPrimaryToStructuredInputSwitch{false};
    bool localQpGadgetArithmeticReceipt{false};
    bool localNativeCAdapterCompiler{false};
    bool localNativeCEntryProjection{false};
    bool localNativeCSwitchSmallBatch{false};
    bool localNativeCBankGeneration{false};
    bool localNativeCPhaseBuilder{false};
    bool localNativeCProofK2{false};
    bool localNativeCZInvSum{false};
    bool localNativeCW{false};
    bool localNativeCZW{false};
    bool localNativeCSuffix{false};
    bool localNativeCResidueXSynthesis{false};
    bool localGroupedXSynthesisCompiler{false};
    bool localEncryptedGroupedM4Evaluator{false};
    bool localNativeCSigmaAggregation{false};
    bool localNativeCPackY{false};
    bool localNativeCForwardUwStandardOutput{false};
    bool localNativeCCudaK2{false};
    bool localNativeCCudaM4BatchKernelResourceQuery{false};
    bool localNativeCCudaM4BatchPlanner{false};
    bool localNativeCCudaM4BatchAdmission{false};
    bool localNativeCCudaM4BatchParityKernel{false};
    bool nativeCCudaM4BatchMultiYLaunchAuthorized{false};
    bool nativeCCudaM4FullDeviceSwitchSmall{false};
    bool nativeCCudaM4FullDeviceGroupedM4{false};
    bool localSm89ResourcePlanner{false};
    bool localSm89DeviceLimitQuery{false};
    bool localDirectGaugeReferenceCompiler{false};
    bool localDirectGaugeRowCompiler{false};
    bool localDirectGaugeNontrivialBankGeneration{false};
    bool localDirectGaugeCpuPrefix{false};
    bool localDirectGaugeGaugeFreeSuffix{false};
    bool localDirectGaugeAuthenticatedCpuCore{false};
    bool encryptedBankGeneration{false};
    bool coefficientSlabRefresh{false};
    bool standardGLOutput{false};
    bool fullBootstrap{false};
    bool cudaExecution{false};
    bool precisionValidated{false};
    bool repeatabilityValidated{false};
    bool securityValidated{false};
    bool productionParameterSetAdmitted{false};
    std::string rejection;
};

class GLSRDLPacoUnavailableError final : public GLException {
public:
    using GLException::GLException;
};

class GLSRDLPacoContractBridge final {
public:
    static GLSRDLPacoContractCapabilities GetCapabilities();

    // Standalone OpenFHE has no local Phase-0 provider.  This method always
    // throws and exists so callers cannot accidentally interpret the contract
    // record as an executable manifest compiler.
    [[noreturn]] static void RequireLocalPhase0Provider();
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_PKE_SCHEME_GL_SRDL_PACO_H
