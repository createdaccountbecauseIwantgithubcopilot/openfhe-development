//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#include "gtest/gtest.h"

#include "scheme/gl/gl-srdl-paco.h"

#include <string>

namespace lbcrypto {
namespace {

TEST(GLSRDLPacoContractBridge, DeclaresExternalStagesAndFailsClosedLocally) {
    const auto capabilities = GLSRDLPacoContractBridge::GetCapabilities();
    EXPECT_EQ(capabilities.schema, "openfhe.gl.srdl_paco_contract.v12");
    EXPECT_EQ(capabilities.requiredCMakeTarget, "GLScheme::glscheme");
    EXPECT_EQ(capabilities.requiredHeader, "glscheme/rns_srdl_paco.hpp");
    EXPECT_EQ(capabilities.requiredBankHeader, "glscheme/rns_srdl_bank.hpp");
    EXPECT_EQ(capabilities.requiredPhaseBankHeader, "glscheme/rns_srdl_phase_bank.hpp");
    EXPECT_EQ(capabilities.requiredPublicPolyphaseHeader, "glscheme/rns_srdl_public_polyphase.hpp");
    EXPECT_EQ(capabilities.requiredPhaseCandidateHeader, "glscheme/rns_srdl_phase_candidate.hpp");
    EXPECT_EQ(capabilities.requiredBlockZHeader, "glscheme/rns_srdl_z.hpp");
    EXPECT_EQ(capabilities.requiredWHeader, "glscheme/rns_srdl_w.hpp");
    EXPECT_EQ(capabilities.requiredSuffixHeader, "glscheme/rns_srdl_suffix.hpp");
    EXPECT_EQ(capabilities.requiredOwnerHeader, "glscheme/rns_srdl_owner.hpp");
    EXPECT_EQ(capabilities.requiredHybridKsHeader, "glscheme/rns_hybrid_ks.hpp");
    EXPECT_EQ(capabilities.requiredCudaHeader, "glscheme/flashgl_srdl_cuda.hpp");
    EXPECT_EQ(capabilities.requiredNativeCAdapterHeader, "glscheme/rns_srdl_native_c.hpp");
    EXPECT_EQ(capabilities.requiredNativeCEntryHeader, "glscheme/rns_srdl_native_c_entry.hpp");
    EXPECT_EQ(capabilities.requiredNativeCInputHeader, "glscheme/rns_srdl_native_c_input.hpp");
    EXPECT_EQ(capabilities.requiredNativeCBankHeader, "glscheme/rns_srdl_native_c_bank.hpp");
    EXPECT_EQ(capabilities.requiredNativeCPhaseHeader, "glscheme/rns_srdl_native_c_phase.hpp");
    EXPECT_EQ(capabilities.requiredNativeCProofK2Header, "glscheme/rns_srdl_native_c_phase_bank.hpp");
    EXPECT_EQ(capabilities.requiredNativeCZInvSumHeader, "glscheme/rns_srdl_native_c_z.hpp");
    EXPECT_EQ(capabilities.requiredNativeCWHeader, "glscheme/rns_srdl_native_c_w.hpp");
    EXPECT_EQ(capabilities.requiredNativeCZWHeader, "glscheme/rns_srdl_native_c_zw.hpp");
    EXPECT_EQ(capabilities.requiredNativeCSuffixHeader, "glscheme/rns_srdl_native_c_suffix.hpp");
    EXPECT_EQ(capabilities.requiredNativeCOutputHeader, "glscheme/rns_srdl_native_c_output.hpp");
    EXPECT_EQ(capabilities.requiredGroupedXPhysicalHeader, "glscheme/rns_srdl_grouped_output_physical.hpp");
    EXPECT_EQ(capabilities.requiredGroupedXEncryptedHeader, "glscheme/rns_srdl_grouped_output_encrypted.hpp");
    EXPECT_EQ(capabilities.requiredNativeCPackHeader, "glscheme/rns_srdl_native_c_pack.hpp");
    EXPECT_EQ(capabilities.requiredNativeCStandardOutputHeader, "glscheme/rns_srdl_native_c_standard_output.hpp");
    EXPECT_EQ(capabilities.requiredNativeCCudaK2Header, "glscheme/flashgl_srdl_native_c_cuda.hpp");
    EXPECT_EQ(capabilities.requiredNativeCCudaM4BatchHeader,
              "glscheme/flashgl_srdl_native_c_cuda.hpp");
    EXPECT_EQ(capabilities.requiredSm89PlannerHeader, "glscheme/flashgl_srdl_sm89_planner.hpp");
    EXPECT_EQ(capabilities.requiredPacoSourceSpecSha256,
              "22665294f36ea97a0dd80ed0682e1da9656d546a0a455dc7ef48d4879ac035f6");
    EXPECT_EQ(capabilities.requiredGpuSourceSpecSha256,
              "ea97a682728fe43c745551fe5546b4355c2ea2065556c25581112cdfaa788263");
    EXPECT_EQ(capabilities.requiredNativeCSourceSpecFilename, "PACO_GL_NativeC_redesign_formulation.md");
    EXPECT_EQ(capabilities.requiredNativeCSourceSpecSha256,
              "7e54bd7792df106288fbc9025bcc5e70eff6ddb711206b97907749e9b3d539b3");
    EXPECT_EQ(capabilities.requiredNativeCRevision, "5");
    EXPECT_EQ(capabilities.requiredContractVersion, "srdl-phase0-v1");
    EXPECT_EQ(capabilities.requiredNativeCAdapterContractVersion, "srdl-native-c-r5-adapter-v1");
    EXPECT_EQ(capabilities.requiredBankCiphertextSetSchema, "glscheme.srdl_bank_ciphertext_set.v1");
    EXPECT_EQ(capabilities.requiredPhaseBankBatchSchema, "glscheme.srdl_phase_bank_batch.v2");
    EXPECT_EQ(capabilities.requiredPhaseBankEvaluationSchema, "glscheme.srdl_phase_bank_evaluation.v2");
    EXPECT_EQ(capabilities.requiredPhaseSourceCommitmentSchema, "glscheme.srdl_phase_source_payload_commitment.v1");
    EXPECT_EQ(capabilities.requiredPublicPolyphaseSchema, "glscheme.srdl_public_polyphase_plane.v1");
    EXPECT_EQ(capabilities.requiredPhaseCandidateBatchSchema, "glscheme.srdl_phase_candidate_batch.v1");
    EXPECT_EQ(capabilities.requiredEarlyGaugeSuffixManifestSchema, "glscheme.srdl_early_gauge_suffix_manifest.v1");
    EXPECT_EQ(capabilities.requiredEarlyGaugeSuffixReceiptSchema, "glscheme.srdl_early_gauge_suffix_receipt.v1");
    EXPECT_EQ(capabilities.requiredCudaPublicPhaseReceiptSchema, "glscheme.flashgl_srdl_cuda_public_phase_receipt.v2");
    EXPECT_EQ(capabilities.requiredCudaPhaseBankReceiptSchema, "glscheme.flashgl_srdl_cuda_phase_bank_receipt.v1");
    EXPECT_EQ(capabilities.requiredCudaBlockZReceiptSchema, "glscheme.flashgl_srdl_cuda_block_z_receipt.v2");
    EXPECT_EQ(capabilities.requiredCudaBlockZBranchReceiptSchema,
              "glscheme.flashgl_srdl_cuda_block_z_branch_receipt.v1");
    EXPECT_EQ(capabilities.requiredNativeCAdapterSchema, "glscheme.srdl_native_c_adapter.v1");
    EXPECT_EQ(capabilities.requiredNativeCEntryBatchSchema, "glscheme.srdl_native_c_entry_batch.v2");
    EXPECT_EQ(capabilities.requiredNativeCEntrySwitchBatchSchema, "glscheme.srdl_native_c_entry_switch_batch.v2");
    EXPECT_EQ(capabilities.requiredNativeCLowInputSliceSchema, "glscheme.srdl_native_c_low_input_slice.v1");
    EXPECT_EQ(capabilities.requiredNativeCBankGeneratorSchema, "glscheme.srdl_native_c_bank_generator.v1");
    EXPECT_EQ(capabilities.requiredNativeCPhaseBatchSchema, "glscheme.srdl_native_c_phase_batch.v1");
    EXPECT_EQ(capabilities.requiredNativeCProofK2ResultSchema, "glscheme.srdl_native_c_phase_bank_result.v1");
    EXPECT_EQ(capabilities.requiredNativeCZInvSumResultSchema, "glscheme.srdl_native_c_zinvsum.v1");
    EXPECT_EQ(capabilities.requiredNativeCWResultSchema, "glscheme.srdl_native_c_w_post_czero.v1");
    EXPECT_EQ(capabilities.requiredNativeCZWResultSchema, "glscheme.srdl_native_c_zw_composition.v1");
    EXPECT_EQ(capabilities.requiredNativeCSuffixResultSchema, "glscheme.srdl_native_c_zw_k5_k6.v1");
    EXPECT_EQ(capabilities.requiredNativeCResidueXSynthesisResultSchema,
              "glscheme.srdl_native_c_residue_x_synthesis.v1");
    EXPECT_EQ(capabilities.requiredGroupedXSynthesisManifestSchema, "glscheme.srdl_grouped_x_synthesis_manifest.v1");
    EXPECT_EQ(capabilities.requiredGroupedXPhysicalManifestSchema, "glscheme.srdl_grouped_x_physical_manifest.v1");
    EXPECT_EQ(capabilities.requiredGroupedXEncryptedResultSchema, "glscheme.srdl_grouped_x_encrypted.v1");
    EXPECT_EQ(capabilities.requiredNativeCSigmaSumResultSchema, "glscheme.srdl_native_c_sigma_sum.v1");
    EXPECT_EQ(capabilities.requiredNativeCPackedYResultSchema, "glscheme.srdl_native_c_packed_y.v2");
    EXPECT_EQ(capabilities.requiredNativeCStandardOutputResultSchema, "glscheme.srdl_native_c_standard_output.v2");
    EXPECT_EQ(capabilities.requiredNativeCCudaK2ResultSchema, "glscheme.flashgl_srdl_native_c_cuda_k2_result.v1");
    EXPECT_EQ(capabilities.requiredNativeCCudaK2RuntimePlanSchema,
              "glscheme.flashgl_srdl_native_c_cuda_k2_runtime_plan.v1");
    EXPECT_EQ(capabilities.requiredNativeCCudaM4BatchKernelResourcesSchema,
              "glscheme.flashgl_srdl_native_c_cuda_m4_batch_kernel_resources.v1");
    EXPECT_EQ(capabilities.requiredNativeCCudaM4BatchRuntimePlanSchema,
              "glscheme.flashgl_srdl_native_c_cuda_m4_batch_runtime_plan.v2");
    EXPECT_EQ(capabilities.requiredNativeCCudaM4BatchResultSchema,
              "glscheme.flashgl_srdl_native_c_cuda_m4_batch_result.v2");
    EXPECT_EQ(capabilities.requiredSm89PlannerSchema, "glscheme.flashgl_srdl_sm89_resource_plan.v1");
    EXPECT_EQ(capabilities.requiredSm89DeviceLimitQuerySchema, "glscheme.flashgl_srdl_sm89_device_limit_query.v1");
    EXPECT_EQ(capabilities.requiredNativeCZInvSumContractVersion, "srdl-native-c-zinvsum-r5-v1");
    EXPECT_EQ(capabilities.requiredNativeCZInverseTransformBinding, "F_2C_inverse[d,s]=exp(-2pi*i*d*s/(2C))/(2C)");
    EXPECT_EQ(capabilities.requiredNativeCWContractVersion, "srdl-native-c-w-r5-v1");
    EXPECT_EQ(capabilities.requiredNativeCZWContractVersion, "srdl-native-c-zw-composition-r5-v1");
    EXPECT_EQ(capabilities.requiredNativeCSuffixContractVersion, "srdl-native-c-zw-k5-k6-r5-v1");
    EXPECT_EQ(capabilities.requiredNativeCResidueXSynthesisContractVersion, "srdl-native-c-residue-x-synthesis-r5-v1");
    EXPECT_EQ(capabilities.requiredGroupedXEncryptedContractVersion, "srdl-grouped-x-encrypted-sparse-bsgs-r5-v1");
    EXPECT_EQ(capabilities.requiredNativeCSigmaSumContractVersion, "srdl-native-c-sigma-sum-r5-v1");
    EXPECT_EQ(capabilities.requiredNativeCPackedYContractVersion, "srdl-native-c-pack-y-r5-v2");
    EXPECT_EQ(capabilities.requiredNativeCStandardOutputContractVersion,
              "srdl-native-c-standard-output-forward-uw-r5-v2");
    EXPECT_EQ(capabilities.requiredLayoutPrefix, "srdl.phase0.row-v2");
    EXPECT_EQ(capabilities.requiredFactorShardBindingId, "srdl.factor-shard.contiguous-floor-divmod-v1");
    EXPECT_EQ(capabilities.requiredControlParameterFactory, "srdl_flashgl_h64_s16_q12_p4_selected_p3_control_params");
    EXPECT_EQ(capabilities.requiredControlParameterName, "SRDL-FLASHGL-H64-S16-Q12X20-P4-SELECTED-P3-CONTROL-V1");
    EXPECT_EQ(capabilities.targetN, 64u);
    EXPECT_EQ(capabilities.targetP, 67u);
    EXPECT_EQ(capabilities.targetPhi, 66u);
    EXPECT_EQ(capabilities.targetOuterYSlices, 64u);
    EXPECT_EQ(capabilities.baseSliceIntegerRank, 8448u);
    EXPECT_EQ(capabilities.baseKskDigitRowScalarResiduesPerLimb, 16896u);
    EXPECT_EQ(capabilities.fullKskDigitRowScalarResiduesPerLimb, 1081344u);
    EXPECT_EQ(capabilities.requiredPacoSwitchBigInvocationCount, 0u);
    EXPECT_EQ(capabilities.requiredControlQPrimeCount, 12u);
    EXPECT_EQ(capabilities.requiredControlSpecialPrimeCount, 4u);
    EXPECT_EQ(capabilities.requiredControlSelectedSpecialPrimeCount, 3u);
    EXPECT_TRUE(capabilities.hammingWeightRequired);
    EXPECT_TRUE(capabilities.externalProviderRequired);
    EXPECT_TRUE(capabilities.externalPhaseSourcePayloadBindingRequired);
    EXPECT_TRUE(capabilities.externalPublicPolyphaseBuilderRequired);
    EXPECT_TRUE(capabilities.externalImmutablePublicPolyphaseResultRequired);
    EXPECT_TRUE(capabilities.externalPhaseCandidateEncoderRequired);
    EXPECT_TRUE(capabilities.externalImmutablePhaseBankResultRequired);
    EXPECT_TRUE(capabilities.externalImmutableCudaPhaseBankResultRequired);
    EXPECT_TRUE(capabilities.externalImmutableCudaBlockZBranchResultRequired);
    EXPECT_TRUE(capabilities.externalImmutableEarlyGaugeSuffixResultRequired);
    EXPECT_TRUE(capabilities.externalFrozenControlParameterFactoryRequired);
    EXPECT_TRUE(capabilities.externalNativeCAdapterRequired);
    EXPECT_TRUE(capabilities.externalNativeCEntryRequired);
    EXPECT_TRUE(capabilities.externalNativeCEntryArtifactCommitmentRequired);
    EXPECT_TRUE(capabilities.externalNativeCEntryEveryActualSliceBindingRequired);
    EXPECT_TRUE(capabilities.externalNativeCEntryDeterministicArtifactRequired);
    EXPECT_TRUE(capabilities.externalNativeCInputRequired);
    EXPECT_TRUE(capabilities.externalNativeCLowBatchSourceEntryArtifactRequired);
    EXPECT_TRUE(capabilities.externalNativeCLowBatchArtifactCommitmentRequired);
    EXPECT_TRUE(capabilities.externalNativeCLowBatchEveryActualSwitchedSliceBindingRequired);
    EXPECT_TRUE(capabilities.externalNativeCLowBatchDeterministicArtifactRequired);
    EXPECT_TRUE(capabilities.externalNativeCBankRequired);
    EXPECT_TRUE(capabilities.externalNativeCPhaseRequired);
    EXPECT_TRUE(capabilities.externalNativeCProofK2Required);
    EXPECT_TRUE(capabilities.externalNativeCZInvSumRequired);
    EXPECT_TRUE(capabilities.externalNativeCWRequired);
    EXPECT_TRUE(capabilities.externalNativeCZWRequired);
    EXPECT_TRUE(capabilities.externalNativeCSuffixRequired);
    EXPECT_TRUE(capabilities.externalNativeCOutputContractsRequired);
    EXPECT_TRUE(capabilities.externalGroupedM4PhysicalClearManifestRequired);
    EXPECT_TRUE(capabilities.externalEncryptedGroupedM4ProviderRequired);
    EXPECT_TRUE(capabilities.externalImmutableGroupedM4ResultRequired);
    EXPECT_TRUE(capabilities.externalExactSigmaAggregationProviderRequired);
    EXPECT_TRUE(capabilities.externalImmutableSigmaSumResultRequired);
    EXPECT_TRUE(capabilities.externalAuthenticatedPackYProviderRequired);
    EXPECT_TRUE(capabilities.externalPackYCommonEntryProvenanceRequired);
    EXPECT_TRUE(capabilities.externalPackYEveryYActualCiphertextRehashRequired);
    EXPECT_TRUE(capabilities.externalPackYSourceEntryArtifactRequired);
    EXPECT_TRUE(capabilities.externalImmutablePackedYResultRequired);
    EXPECT_TRUE(capabilities.externalFinalForwardUwStandardOutputProviderRequired);
    EXPECT_TRUE(capabilities.externalStandardOutputSourceEntryArtifactRequired);
    EXPECT_TRUE(capabilities.externalImmutableStandardGLOutputResultRequired);
    EXPECT_TRUE(capabilities.externalNativeCCudaK2Required);
    EXPECT_TRUE(capabilities.externalNativeCCudaM4BatchKernelResourceQueryRequired);
    EXPECT_TRUE(capabilities.externalNativeCCudaM4BatchPlannerRequired);
    EXPECT_TRUE(capabilities.externalNativeCCudaM4BatchSingleYAdmissionRequired);
    EXPECT_TRUE(capabilities.externalImmutableNativeCCudaM4BatchResultRequired);
    EXPECT_TRUE(capabilities.externalSm89PlannerRequired);
    EXPECT_TRUE(capabilities.externalSm89DeviceLimitQueryRequired);
    EXPECT_TRUE(capabilities.postCrossYEntryBoundaryRequired);
    EXPECT_TRUE(capabilities.sharedSwitchSmallKeyAcrossYSlicesRequired);
    EXPECT_TRUE(capabilities.normalizedZInvSumRequired);
    EXPECT_TRUE(capabilities.coefficientProjectionCommutesWithDecryption);
    EXPECT_TRUE(capabilities.coefficientSlabsAlgebraicallySeparableUnderSharedSecret);
    EXPECT_FALSE(capabilities.coefficientProjectionRingHomomorphism);
    EXPECT_FALSE(capabilities.coefficientSlabsIndependentRingFactors);
    EXPECT_TRUE(capabilities.genericAndHadamardMultiplicationMayCoupleYSlices);
    EXPECT_TRUE(capabilities.pacoKeyGraphBaseRingOnlyRequired);
    EXPECT_FALSE(capabilities.universalM64GemmBatching);
    EXPECT_TRUE(capabilities.exactGroupedM4LogicalManifestRequired);
    EXPECT_FALSE(capabilities.groupedM4PhysicalEvaluationAdmitted);
    EXPECT_TRUE(capabilities.nativeCExactM1ResidueXSynthesisOnly);
    EXPECT_TRUE(capabilities.cudaArchitectureSm89OrOlderOnly);
    EXPECT_FALSE(capabilities.postSm89FeaturesPermitted);
    EXPECT_FALSE(capabilities.localManifestCompiler);
    EXPECT_FALSE(capabilities.localSelectorLayoutSelfCheck);
    EXPECT_FALSE(capabilities.localExactPrefixOracle);
    EXPECT_FALSE(capabilities.localBankCatalog);
    EXPECT_FALSE(capabilities.localPhaseBankScheduler);
    EXPECT_FALSE(capabilities.localPhaseCandidateEncoder);
    EXPECT_FALSE(capabilities.localGenericBlockZEvaluator);
    EXPECT_FALSE(capabilities.localGenericWEvaluator);
    EXPECT_FALSE(capabilities.localEarlyGaugeSuffix);
    EXPECT_FALSE(capabilities.localOwnerStructuredSecret);
    EXPECT_FALSE(capabilities.localPrimaryToStructuredInputSwitch);
    EXPECT_FALSE(capabilities.localQpGadgetArithmeticReceipt);
    EXPECT_FALSE(capabilities.localNativeCAdapterCompiler);
    EXPECT_FALSE(capabilities.localNativeCEntryProjection);
    EXPECT_FALSE(capabilities.localNativeCSwitchSmallBatch);
    EXPECT_FALSE(capabilities.localNativeCBankGeneration);
    EXPECT_FALSE(capabilities.localNativeCPhaseBuilder);
    EXPECT_FALSE(capabilities.localNativeCProofK2);
    EXPECT_FALSE(capabilities.localNativeCZInvSum);
    EXPECT_FALSE(capabilities.localNativeCW);
    EXPECT_FALSE(capabilities.localNativeCZW);
    EXPECT_FALSE(capabilities.localNativeCSuffix);
    EXPECT_FALSE(capabilities.localNativeCResidueXSynthesis);
    EXPECT_FALSE(capabilities.localGroupedXSynthesisCompiler);
    EXPECT_FALSE(capabilities.localEncryptedGroupedM4Evaluator);
    EXPECT_FALSE(capabilities.localNativeCSigmaAggregation);
    EXPECT_FALSE(capabilities.localNativeCPackY);
    EXPECT_FALSE(capabilities.localNativeCForwardUwStandardOutput);
    EXPECT_FALSE(capabilities.localNativeCCudaK2);
    EXPECT_FALSE(capabilities.localNativeCCudaM4BatchKernelResourceQuery);
    EXPECT_FALSE(capabilities.localNativeCCudaM4BatchPlanner);
    EXPECT_FALSE(capabilities.localNativeCCudaM4BatchAdmission);
    EXPECT_FALSE(capabilities.localNativeCCudaM4BatchParityKernel);
    EXPECT_FALSE(capabilities.nativeCCudaM4BatchMultiYLaunchAuthorized);
    EXPECT_FALSE(capabilities.nativeCCudaM4FullDeviceSwitchSmall);
    EXPECT_FALSE(capabilities.nativeCCudaM4FullDeviceGroupedM4);
    EXPECT_FALSE(capabilities.localSm89ResourcePlanner);
    EXPECT_FALSE(capabilities.localSm89DeviceLimitQuery);
    EXPECT_FALSE(capabilities.encryptedBankGeneration);
    EXPECT_FALSE(capabilities.coefficientSlabRefresh);
    EXPECT_FALSE(capabilities.standardGLOutput);
    EXPECT_FALSE(capabilities.fullBootstrap);
    EXPECT_FALSE(capabilities.cudaExecution);
    EXPECT_FALSE(capabilities.precisionValidated);
    EXPECT_FALSE(capabilities.repeatabilityValidated);
    EXPECT_FALSE(capabilities.securityValidated);
    EXPECT_FALSE(capabilities.productionParameterSetAdmitted);
    EXPECT_NE(capabilities.rejection.find("standalone OpenFHE"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("evaluator-public pre-transform polyphase planes"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("phase--bank scheduling"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("immutable staged-F0 K2"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("post-cross-Y PaCo entry boundary"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("non-ring-homomorphic"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("one common SwitchSmall key"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("M=64 is not universally legal"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("immutable encrypted grouped-M4 sparse-BSGS result"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("exact ordered 16-sigma aggregation"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("authenticated 64-y PackY tied to one common entry-switch batch"),
              std::string::npos);
    EXPECT_NE(capabilities.rejection.find("every Y source ciphertext rehashed"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("source-entry artifact carried explicitly"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("unnormalized forward-U_W standard GL output result"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("standalone OpenFHE implements none of their evaluators"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("algebraically separable under one shared secret"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("generic/Hadamard multiplication may couple"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("PaCo requires zero SwitchBig calls"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("typed CUDA K2"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("single-outer-Y/16-sigma resource-derived M4 payload-parity admission"),
              std::string::npos);
    EXPECT_NE(capabilities.rejection.find("does not evaluate full-device SwitchSmall or grouped M4"),
              std::string::npos);
    EXPECT_NE(capabilities.rejection.find("No post-SM89 feature"), std::string::npos);
    EXPECT_NE(capabilities.rejection.find("no local Native-C, scheduler, CUDA, precision, security"),
              std::string::npos);

    EXPECT_THROW(GLSRDLPacoContractBridge::RequireLocalPhase0Provider(), GLSRDLPacoUnavailableError);
}

}  // namespace
}  // namespace lbcrypto
