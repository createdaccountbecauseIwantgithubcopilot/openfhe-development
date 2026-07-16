//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#include "scheme/gl/gl-srdl-paco.h"

namespace lbcrypto {

GLSRDLPacoContractCapabilities GLSRDLPacoContractBridge::GetCapabilities() {
    GLSRDLPacoContractCapabilities capabilities;
    capabilities.schema                              = "openfhe.gl.srdl_paco_contract.v12";
    capabilities.requiredCMakeTarget                 = "GLScheme::glscheme";
    capabilities.requiredHeader                      = "glscheme/rns_srdl_paco.hpp";
    capabilities.requiredBankHeader                  = "glscheme/rns_srdl_bank.hpp";
    capabilities.requiredPhaseBankHeader             = "glscheme/rns_srdl_phase_bank.hpp";
    capabilities.requiredPublicPolyphaseHeader       = "glscheme/rns_srdl_public_polyphase.hpp";
    capabilities.requiredPhaseCandidateHeader        = "glscheme/rns_srdl_phase_candidate.hpp";
    capabilities.requiredBlockZHeader                = "glscheme/rns_srdl_z.hpp";
    capabilities.requiredWHeader                     = "glscheme/rns_srdl_w.hpp";
    capabilities.requiredSuffixHeader                = "glscheme/rns_srdl_suffix.hpp";
    capabilities.requiredOwnerHeader                 = "glscheme/rns_srdl_owner.hpp";
    capabilities.requiredHybridKsHeader              = "glscheme/rns_hybrid_ks.hpp";
    capabilities.requiredCudaHeader                  = "glscheme/flashgl_srdl_cuda.hpp";
    capabilities.requiredNativeCAdapterHeader        = "glscheme/rns_srdl_native_c.hpp";
    capabilities.requiredNativeCEntryHeader          = "glscheme/rns_srdl_native_c_entry.hpp";
    capabilities.requiredNativeCInputHeader          = "glscheme/rns_srdl_native_c_input.hpp";
    capabilities.requiredNativeCBankHeader           = "glscheme/rns_srdl_native_c_bank.hpp";
    capabilities.requiredNativeCPhaseHeader          = "glscheme/rns_srdl_native_c_phase.hpp";
    capabilities.requiredNativeCProofK2Header        = "glscheme/rns_srdl_native_c_phase_bank.hpp";
    capabilities.requiredNativeCZInvSumHeader        = "glscheme/rns_srdl_native_c_z.hpp";
    capabilities.requiredNativeCWHeader              = "glscheme/rns_srdl_native_c_w.hpp";
    capabilities.requiredNativeCZWHeader             = "glscheme/rns_srdl_native_c_zw.hpp";
    capabilities.requiredNativeCSuffixHeader         = "glscheme/rns_srdl_native_c_suffix.hpp";
    capabilities.requiredNativeCOutputHeader         = "glscheme/rns_srdl_native_c_output.hpp";
    capabilities.requiredGroupedXPhysicalHeader      = "glscheme/rns_srdl_grouped_output_physical.hpp";
    capabilities.requiredGroupedXEncryptedHeader     = "glscheme/rns_srdl_grouped_output_encrypted.hpp";
    capabilities.requiredNativeCPackHeader           = "glscheme/rns_srdl_native_c_pack.hpp";
    capabilities.requiredNativeCStandardOutputHeader = "glscheme/rns_srdl_native_c_standard_output.hpp";
    capabilities.requiredNativeCCudaK2Header         = "glscheme/flashgl_srdl_native_c_cuda.hpp";
    capabilities.requiredNativeCCudaM4BatchHeader    = "glscheme/flashgl_srdl_native_c_cuda.hpp";
    capabilities.requiredSm89PlannerHeader           = "glscheme/flashgl_srdl_sm89_planner.hpp";
    capabilities.requiredPacoSourceSpecSha256      = "22665294f36ea97a0dd80ed0682e1da9656d546a0a455dc7ef48d4879ac035f6";
    capabilities.requiredGpuSourceSpecSha256       = "ea97a682728fe43c745551fe5546b4355c2ea2065556c25581112cdfaa788263";
    capabilities.requiredNativeCSourceSpecFilename = "PACO_GL_NativeC_redesign_formulation.md";
    capabilities.requiredNativeCSourceSpecSha256   = "7e54bd7792df106288fbc9025bcc5e70eff6ddb711206b97907749e9b3d539b3";
    capabilities.requiredNativeCRevision           = "5";
    capabilities.requiredContractVersion           = "srdl-phase0-v1";
    capabilities.requiredNativeCAdapterContractVersion        = "srdl-native-c-r5-adapter-v1";
    capabilities.requiredBankCiphertextSetSchema              = "glscheme.srdl_bank_ciphertext_set.v1";
    capabilities.requiredPhaseBankBatchSchema                 = "glscheme.srdl_phase_bank_batch.v2";
    capabilities.requiredPhaseBankEvaluationSchema            = "glscheme.srdl_phase_bank_evaluation.v2";
    capabilities.requiredPhaseSourceCommitmentSchema          = "glscheme.srdl_phase_source_payload_commitment.v1";
    capabilities.requiredPublicPolyphaseSchema                = "glscheme.srdl_public_polyphase_plane.v1";
    capabilities.requiredPhaseCandidateBatchSchema            = "glscheme.srdl_phase_candidate_batch.v1";
    capabilities.requiredEarlyGaugeSuffixManifestSchema       = "glscheme.srdl_early_gauge_suffix_manifest.v1";
    capabilities.requiredEarlyGaugeSuffixReceiptSchema        = "glscheme.srdl_early_gauge_suffix_receipt.v1";
    capabilities.requiredCudaPublicPhaseReceiptSchema         = "glscheme.flashgl_srdl_cuda_public_phase_receipt.v2";
    capabilities.requiredCudaPhaseBankReceiptSchema           = "glscheme.flashgl_srdl_cuda_phase_bank_receipt.v1";
    capabilities.requiredCudaBlockZReceiptSchema              = "glscheme.flashgl_srdl_cuda_block_z_receipt.v2";
    capabilities.requiredCudaBlockZBranchReceiptSchema        = "glscheme.flashgl_srdl_cuda_block_z_branch_receipt.v1";
    capabilities.requiredNativeCAdapterSchema                 = "glscheme.srdl_native_c_adapter.v1";
    capabilities.requiredNativeCEntryBatchSchema              = "glscheme.srdl_native_c_entry_batch.v2";
    capabilities.requiredNativeCEntrySwitchBatchSchema        = "glscheme.srdl_native_c_entry_switch_batch.v2";
    capabilities.requiredNativeCLowInputSliceSchema           = "glscheme.srdl_native_c_low_input_slice.v1";
    capabilities.requiredNativeCBankGeneratorSchema           = "glscheme.srdl_native_c_bank_generator.v1";
    capabilities.requiredNativeCPhaseBatchSchema              = "glscheme.srdl_native_c_phase_batch.v1";
    capabilities.requiredNativeCProofK2ResultSchema           = "glscheme.srdl_native_c_phase_bank_result.v1";
    capabilities.requiredNativeCZInvSumResultSchema           = "glscheme.srdl_native_c_zinvsum.v1";
    capabilities.requiredNativeCWResultSchema                 = "glscheme.srdl_native_c_w_post_czero.v1";
    capabilities.requiredNativeCZWResultSchema                = "glscheme.srdl_native_c_zw_composition.v1";
    capabilities.requiredNativeCSuffixResultSchema            = "glscheme.srdl_native_c_zw_k5_k6.v1";
    capabilities.requiredNativeCResidueXSynthesisResultSchema = "glscheme.srdl_native_c_residue_x_synthesis.v1";
    capabilities.requiredGroupedXSynthesisManifestSchema      = "glscheme.srdl_grouped_x_synthesis_manifest.v1";
    capabilities.requiredGroupedXPhysicalManifestSchema       = "glscheme.srdl_grouped_x_physical_manifest.v1";
    capabilities.requiredGroupedXEncryptedResultSchema        = "glscheme.srdl_grouped_x_encrypted.v1";
    capabilities.requiredNativeCSigmaSumResultSchema          = "glscheme.srdl_native_c_sigma_sum.v1";
    capabilities.requiredNativeCPackedYResultSchema           = "glscheme.srdl_native_c_packed_y.v2";
    capabilities.requiredNativeCStandardOutputResultSchema    = "glscheme.srdl_native_c_standard_output.v2";
    capabilities.requiredNativeCCudaK2ResultSchema            = "glscheme.flashgl_srdl_native_c_cuda_k2_result.v1";
    capabilities.requiredNativeCCudaK2RuntimePlanSchema       = "glscheme.flashgl_srdl_native_c_cuda_k2_runtime_plan.v1";
    capabilities.requiredNativeCCudaM4BatchKernelResourcesSchema =
        "glscheme.flashgl_srdl_native_c_cuda_m4_batch_kernel_resources.v1";
    capabilities.requiredNativeCCudaM4BatchRuntimePlanSchema =
        "glscheme.flashgl_srdl_native_c_cuda_m4_batch_runtime_plan.v2";
    capabilities.requiredNativeCCudaM4BatchResultSchema =
        "glscheme.flashgl_srdl_native_c_cuda_m4_batch_result.v2";
    capabilities.requiredSm89PlannerSchema                    = "glscheme.flashgl_srdl_sm89_resource_plan.v1";
    capabilities.requiredSm89DeviceLimitQuerySchema           = "glscheme.flashgl_srdl_sm89_device_limit_query.v1";
    capabilities.requiredNativeCZInvSumContractVersion        = "srdl-native-c-zinvsum-r5-v1";
    capabilities.requiredNativeCZInverseTransformBinding      = "F_2C_inverse[d,s]=exp(-2pi*i*d*s/(2C))/(2C)";
    capabilities.requiredNativeCWContractVersion              = "srdl-native-c-w-r5-v1";
    capabilities.requiredNativeCZWContractVersion             = "srdl-native-c-zw-composition-r5-v1";
    capabilities.requiredNativeCSuffixContractVersion         = "srdl-native-c-zw-k5-k6-r5-v1";
    capabilities.requiredNativeCResidueXSynthesisContractVersion = "srdl-native-c-residue-x-synthesis-r5-v1";
    capabilities.requiredGroupedXEncryptedContractVersion        = "srdl-grouped-x-encrypted-sparse-bsgs-r5-v1";
    capabilities.requiredNativeCSigmaSumContractVersion          = "srdl-native-c-sigma-sum-r5-v1";
    capabilities.requiredNativeCPackedYContractVersion           = "srdl-native-c-pack-y-r5-v2";
    capabilities.requiredNativeCStandardOutputContractVersion    = "srdl-native-c-standard-output-forward-uw-r5-v2";
    capabilities.requiredLayoutPrefix                            = "srdl.phase0.row-v2";
    capabilities.requiredFactorShardBindingId                    = "srdl.factor-shard.contiguous-floor-divmod-v1";
    capabilities.requiredControlParameterFactory = "srdl_flashgl_h64_s16_q12_p4_selected_p3_control_params";
    capabilities.requiredControlParameterName    = "SRDL-FLASHGL-H64-S16-Q12X20-P4-SELECTED-P3-CONTROL-V1";
    capabilities.rejection =
        "standalone OpenFHE does not link GLScheme::glscheme; use the external "
        "GLScheme SRDL headers (or their zero-logic FIDES adapter) for row-v2 "
        "manifests, exact prefix checks, bank-catalog validation, typed "
        "phase-source payload binding, immutable evaluator-public pre-transform "
        "polyphase planes, explicit-orientation raw candidate-phase encoding, "
        "immutable phase--bank scheduling, generic Z/W evaluation, the staged "
        "caller-supplied post-Czero early-gauge suffix, explicitly owner-side "
        "s_P/input-switch operations, the "
        "pinned Q12/P4-selected-P3 arithmetic-control factory, and the "
        "availability-gated immutable staged-F0 K2/keyed-generic-K3 plus other "
        "SM89-or-older CUDA controls; Native-C revision-5 additionally "
        "requires the dual-pinned adapter, the post-cross-Y PaCo entry "
        "boundary plus deterministic artifacts over every actual extracted and "
        "switched slice, coefficient projection only as a decryption-commuting "
        "non-ring-homomorphic operation, one common SwitchSmall key across Y "
        "slices, proof-carrying K2, normalized ZInvSum, authenticated Z/W "
        "composition, the proof-carrying K5/K6 suffix, exact M=1 residue-X "
        "synthesis, the logical grouped-M4 manifest, the clear-only exact "
        "P-block physical direct/BSGS manifest, the immutable encrypted "
        "grouped-M4 sparse-BSGS result, exact ordered 16-sigma aggregation, "
        "authenticated 64-y PackY tied to one common entry-switch batch/full "
        "ciphertext with every Y source ciphertext rehashed and the source-entry "
        "artifact carried explicitly into PackY/final W, the final direct "
        "unnormalized forward-U_W standard GL output result, typed CUDA K2, the "
        "single-outer-Y/16-sigma resource-derived M4 payload-parity admission, and "
        "the SM89-or-older resource/device-limit planner. The CUDA M4 boundary "
        "does not evaluate full-device SwitchSmall or grouped M4 and does not "
        "authorize a generic multi-Y launch. These completed CPU "
        "stages must come from the external proof-carrying provider; standalone "
        "OpenFHE implements none of their evaluators. Y "
        "slabs are algebraically separable under one shared secret, not "
        "independent ring factors; generic/Hadamard multiplication may couple "
        "them, PaCo requires zero SwitchBig calls, and M=64 is not universally "
        "legal. No "
        "post-SM89 feature and no local Native-C, scheduler, CUDA, precision, "
        "security, production, output, or full-bootstrap execution is available";
    return capabilities;
}

[[noreturn]] void GLSRDLPacoContractBridge::RequireLocalPhase0Provider() {
    const auto capabilities = GetCapabilities();
    throw GLSRDLPacoUnavailableError(capabilities.rejection);
}

}  // namespace lbcrypto
