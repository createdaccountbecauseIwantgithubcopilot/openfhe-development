#ifndef LBCRYPTO_PKE_GLR_PRODUCTION_ADAPTER_H
#define LBCRYPTO_PKE_GLR_PRODUCTION_ADAPTER_H

// Optional provider for the native W-batched GL RNS engine in GLScheme.
//
// This is intentionally separate from GLSchemelet.  The canonical production
// layout is phi=256 matrices of shape 128x128 in R'[X,Y,W]; none of these types
// are OpenFHE DCRT rows, and the adapter exposes no DCRT conversion seam.

#include "glscheme/production_profiles.hpp"
#include "glscheme/gl128_scheme.hpp"
#include "glscheme/gl128_bootstrap.hpp"
#include "glscheme/gl128_bootstrap_research.hpp"
#include "glscheme/gl128_bootstrap_acceptance.hpp"
#include "glscheme/gl128_ciphertext_artifact.hpp"
#include "glscheme/gl128_h64_bootstrap_research.hpp"
#include "glscheme/gl128_h64_hidden_selector.hpp"
#include "glscheme/gl128_h64_p257_one_bit.hpp"
#include "glscheme/gl128_h64_p257_one_bit_gpu.hpp"
#include "glscheme/gl128_h64_p257_prefix_splice.hpp"
#include "glscheme/gl128_h64_p257_right_muxrot.hpp"
#include "glscheme/gl128_h64_root_product_oracle.hpp"
#include "glscheme/gl128_h64_selected_leaf_fold.hpp"
#include "glscheme/gl128_h64_selected_leaf_fold_gpu.hpp"
#include "glscheme/gl128_h64_selected_leaf_return_gpu.hpp"
#include "glscheme/gl128_h64_structured_security_audit.hpp"
#include "glscheme/gl128_h64_w_action_plan.hpp"
#include "glscheme/glr_device_ks.hpp"
#include "glscheme/rns_dft_plaintext_provider.hpp"
#include "glscheme/rns_encode.hpp"
#include "glscheme/rns_hybrid_ks.hpp"
#include "glscheme/rns_keygen.hpp"
#include "glscheme/rns_public_key.hpp"
#include "glscheme/rns_ship.hpp"
#include "glscheme/rns_ship_compact_selector.hpp"
#include "glscheme/rns_ship_direct_composition.hpp"
#include "glscheme/rns_ship_direct_gpu_all_y.hpp"
#include "glscheme/rns_ship_direct_vector.hpp"
#include "glscheme/rns_ship_gadget_provider.hpp"
#include "glscheme/rns_w_algebra.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace lbcrypto {

class GLRProductionAdapter final {
public:
    using Profile = glscheme::production::Profile;
    using Context = glscheme::rns::GlrContext;
    using SecretKey = glscheme::rns::GlrSecretKey;
    using PublicKey = glscheme::rns::GlrPublicKey;
    using CompactPublicKey = glscheme::rns::GlrCompactPublicKey;
    using MatrixBatch = glscheme::rns::GlrMatrixBatch;
    using Plaintext = glscheme::rns::GlrPlaintext;
    using Ciphertext = glscheme::rns::GlrCiphertext;
    using SparseSecretKey = glscheme::rns::GlrSparseSecretKey;
    using KeyId = glscheme::rns::GlrKskId;
    using NativeSwitchKey = glscheme::rns::GlrSwitchKey;
    using NativeKskRecord = glscheme::rns::GlrKskRecord;
    using KeyRing = glscheme::rns::GlrRing;
    using KeyManifest = glscheme::rns::GlrKskManifest;
    using NativeKeyProvider = glscheme::rns::GlrKskProvider;
    using NativeLeasedKeyBinding = glscheme::rns::GlrLeasedKskBinding;
    using SecurityReport = ::glscheme::SecurityReport;
    using NativeRefreshTracePreflight =
        glscheme::rns::GlrShipRefreshOnlyPackPreflight;
    using NativeRefreshEndpointPreflight =
        glscheme::rns::GlrShipRefreshOnlyEndpointPreflight;
    using NativeRefreshEndpointResult =
        glscheme::rns::GlrShipRefreshOnlyEndpointResult;
    using NativeRefreshEndpointEvidence =
        glscheme::rns::GlrShipRefreshOnlyEndpointEvidence;
    using NativeRefreshDftPlaintextProvider =
        glscheme::rns::GlrDftPlaintextProvider;
    using NativeRefreshDftPlaintextBinding =
        glscheme::rns::GlrDftPlaintextBinding;
    using NativeDftPlaintextKind = glscheme::rns::GlrDftPlaintextKind;
    using NativeDftPlaintextMaterialPolicy =
        glscheme::rns::GlrDftPlaintextMaterialPolicy;
    using NativeDftPlaintextManifestEntry =
        glscheme::rns::GlrDftPlaintextManifestEntry;
    using NativeDftPlaintextManifest =
        glscheme::rns::GlrDftPlaintextManifest;
    using NativeDftPlaintextEntrySink =
        glscheme::rns::GlrDftPlaintextEntrySink;
    using NativeDftPlaintextGenerationConfig =
        glscheme::rns::GlrDftPlaintextGenerationConfig;
    using NativeDftPlaintextGenerationResult =
        glscheme::rns::GlrDftPlaintextGenerationResult;
    using NativeDftPlaintextRecordSink =
        glscheme::rns::GlrDftPlaintextRecordSink;
    using NativeDftPlaintextRecordSource =
        glscheme::rns::GlrDftPlaintextRecordSource;
    using NativeDftPlaintextRecordReceipt =
        glscheme::rns::GlrDftPlaintextRecordReceipt;
    using NativeRecordedDftPlaintextProvider =
        glscheme::rns::GlrRecordedDftPlaintextProvider;
    using NativeDftPlaintextByteCensus =
        glscheme::rns::GlrDftPlaintextByteCensus;
    using NativeRefreshGadgetProvider =
        glscheme::rns::GlrShipGadgetProvider;
    using NativeRefreshGadgetBinding =
        glscheme::rns::GlrShipGadgetBinding;
    using NativeRefreshCompactSelectorManifest =
        glscheme::rns::GlrShipCompactSelectorManifest;
    using NativeRefreshCompactSelectorBinding =
        glscheme::rns::GlrShipCompactSelectorBinding;
    using NativeRefreshPackParameters =
        glscheme::rns::GlrShipRefreshOnlyParameters;
    using NativeRefreshPackConfig = glscheme::rns::GlrShipConfig;
    using NativeRefreshPackAccumulator =
        glscheme::rns::GlrShipRefreshOnlyPackAccumulator;
    using NativeRefreshPackResult =
        glscheme::rns::GlrShipRefreshOnlyPackedResult;
    using NativeRefreshPackEvidence =
        glscheme::rns::GlrShipRefreshOnlyPackEvidence;
    using NativeRefreshPackCheckpointSink =
        glscheme::rns::GlrShipRefreshOnlyPackCheckpointSink;
    using NativeRefreshPackCheckpointSource =
        glscheme::rns::GlrShipRefreshOnlyPackCheckpointSource;
    using NativeRefreshPackCheckpointReceipt =
        glscheme::rns::GlrShipRefreshOnlyPackCheckpointReceipt;
    using NativeDirectVectorPlan =
        glscheme::rns::GlrShipDirectVectorPlan;
    using NativeDirectVectorEvidence =
        glscheme::rns::GlrShipDirectVectorEvidence;
    using NativeDirectVectorDensePrimarySecurityEvidence =
        glscheme::rns::GlrShipDirectVectorDensePrimarySecurityEvidence;
    using NativeDirectVectorProductionAuthorizationEvidence =
        glscheme::rns::GlrShipDirectVectorProductionAuthorizationEvidence;
    using NativeDirectVectorSelectorStorageAdmissionEvidence =
        glscheme::rns::
            GlrShipDirectVectorProductionSelectorStorageAdmissionEvidence;
    using NativeDirectVectorSelectorRecordGenerationResult =
        glscheme::rns::
            GlrShipDirectVectorProductionSelectorRecordGenerationResult;
    using NativeDirectVectorAllYStcEvidence =
        glscheme::rns::GlrShipDirectAllYStcEvidence;
    using NativeDirectVectorFullReturnEvidence =
        glscheme::rns::GlrShipDirectFullReturnEvidence;
    using NativeDirectGpuPublicTableEvidence =
        glscheme::rns::GlrShipDirectDevicePublicTableEvidence;
    using NativeDirectGpuLeafSourceEvidence =
        glscheme::rns::GlrShipDirectGpuLeafSourceEvidence;
    using NativeDirectGpuAllYCachePlan =
        glscheme::rns::GlrShipDirectGpuAllYCachePlan;
    using NativeDirectGpuResidentQ0SliceProducer =
        glscheme::rns::GlrShipDirectGpuResidentQ0SliceProducer;
    using NativeDirectGpuAllYRequest =
        glscheme::rns::GlrShipDirectGpuAllYRequest;
    using NativeDirectGpuAllYEvidence =
        glscheme::rns::GlrShipDirectGpuAllYEvidence;
    using NativeDirectGpuAllYResult =
        glscheme::rns::GlrShipDirectGpuAllYResult;
    using NativeDirectGpuBootstrapRequest =
        glscheme::rns::GlrShipDirectGpuBootstrapRequest;
    using NativeDirectGpuPreparationEvidence =
        glscheme::rns::GlrShipDirectGpuPreparationEvidence;
    using NativeDirectGpuBootstrapEvidence =
        glscheme::rns::GlrShipDirectGpuBootstrapEvidence;
    using NativeDirectGpuBootstrapResult =
        glscheme::rns::GlrShipDirectGpuBootstrapResult;
    using NativeGL128ProfileReceipt = glscheme::rns::Gl128ProfileReceipt;
    using NativeGL128SchemeWorkload = glscheme::rns::Gl128SchemeWorkload;
    using NativeGL128SchemeKeyPlan = glscheme::rns::Gl128SchemeKeyPlan;
    using NativeGL128DirectBootstrapKeyPlan =
        glscheme::rns::Gl128DirectBootstrapKeyPlan;
    using NativeGL128DirectBootstrapKeyLineageBinding =
        glscheme::rns::Gl128DirectBootstrapKeyLineageBinding;
    using NativeGL128DirectBootstrapKeyGenerationResult =
        glscheme::rns::Gl128DirectBootstrapKeyGenerationResult;
    using NativeGL128Operation = glscheme::rns::Gl128Operation;
    using NativeGL128EvaluationEvidence =
        glscheme::rns::Gl128EvaluationEvidence;
    using NativeGL128EvaluationResult =
        glscheme::rns::Gl128EvaluationResult;
    using NativeGL128PlainProductOptions =
        glscheme::rns::Gl128PlainProductOptions;
    using NativeGL128TransposedCodecEvidence =
        glscheme::rns::Gl128TransposedCodecEvidence;
    using NativeGL128TransposedPlaintext =
        glscheme::rns::Gl128TransposedPlaintext;
    using NativeGL128TransposedCiphertext =
        glscheme::rns::Gl128TransposedCiphertext;
    using NativeGL128TransposedDecodeResult =
        glscheme::rns::Gl128TransposedDecodeResult;
    using NativeGL128LeftPlainMatrixMultiplyEvidence =
        glscheme::rns::Gl128LeftPlainMatrixMultiplyEvidence;
    using NativeGL128LeftPlainMatrixMultiplyResult =
        glscheme::rns::Gl128LeftPlainMatrixMultiplyResult;
    using NativeGL128ModulusMaintenanceKind =
        glscheme::rns::Gl128ModulusMaintenanceKind;
    using NativeGL128ModulusMaintenanceEvidence =
        glscheme::rns::Gl128ModulusMaintenanceEvidence;
    using NativeGL128ModulusMaintenanceResult =
        glscheme::rns::Gl128ModulusMaintenanceResult;
    using TransposedPlaintext = NativeGL128TransposedPlaintext;
    using TransposedCiphertext = NativeGL128TransposedCiphertext;
    using NativeCompactKskSetSink = glscheme::rns::GlrCompactKskSetSink;
    using NativeCompactKskSetGenerationResult =
        glscheme::rns::GlrCompactKskSetGenerationResult;
    using NativeCompactKskBlobLeaseCallbacks =
        glscheme::rns::GlrCompactKskBlobLeaseCallbacks;
    using NativeDirectVectorProductionSelectorGenerationSeed =
        glscheme::rns::
            GlrShipDirectVectorProductionSelectorGenerationSeed;
    using NativeDirectVectorProductionSelectorGenerator =
        glscheme::rns::
            GlrShipDirectVectorProductionSelectorGenerator;
    using NativeDirectVectorProductionSelectorManifestCheckpoint =
        glscheme::rns::
            GlrShipDirectVectorProductionSelectorManifestCheckpoint;
    using NativeDirectVectorProductionSelectorManifestFinalizationResult =
        glscheme::rns::
            GlrShipDirectVectorProductionSelectorManifestFinalizationResult;
    using NativeDirectVectorProductionSelectorBlobPersistenceEvidence =
        glscheme::rns::
            GlrShipDirectVectorProductionSelectorBlobPersistenceEvidence;
    using NativeDirectVectorProductionSelectorBlobLeaseCallbacks =
        glscheme::rns::
            GlrShipDirectVectorProductionSelectorBlobLeaseCallbacks;
    using NativeDirectVectorProductionSelectorProviderOpeningResult =
        glscheme::rns::
            GlrShipDirectVectorProductionSelectorProviderOpeningResult;
    using NativeDirectVectorPublicSlice =
        glscheme::rns::GlrShipDirectPublicSlice;
    using NativeValidatedDftPlaintextProviderSession =
        glscheme::rns::GlrValidatedDftPlaintextProviderSession;
    using NativeCtsStcConfig = glscheme::rns::GlrCtsStcConfig;
    using NativeDirectVectorAllYStcResult =
        glscheme::rns::GlrShipDirectAllYStcResult;
    using NativeGL128DirectBootstrapAuthorizationBundle =
        glscheme::rns::Gl128DirectBootstrapAuthorizationBundle;
    using NativeGL128SelectorPersistenceSink =
        glscheme::rns::Gl128SelectorPersistenceSink;
    using NativeGL128PersistedSelectorBankResult =
        glscheme::rns::Gl128PersistedSelectorBankResult;
    using NativeGL128DirectInputPreparationEvidence =
        glscheme::rns::Gl128DirectInputPreparationEvidence;
    using NativeGL128DirectInputPreparationResult =
        glscheme::rns::Gl128DirectInputPreparationResult;
    using NativeGL128BootstrapRepresentation =
        glscheme::rns::Gl128BootstrapRepresentation;
    using NativeGL128BootstrapEvidence =
        glscheme::rns::Gl128BootstrapEvidence;
    using NativeGL128BootstrapResult =
        glscheme::rns::Gl128BootstrapResult;
    using NativeGL128H40FreeSupportProxyResearchReceipt =
        glscheme::rns::GlrGl128H40FreeSupportProxyResearchReceipt;
    using NativeGL128ResearchOnlySession =
        glscheme::rns::Gl128ResearchOnlySession;
    using NativeGL128ResearchSelectorGenerationSeed =
        glscheme::rns::Gl128ResearchSelectorGenerationSeed;
    using NativeGL128ResearchSelectorPersistenceSink =
        glscheme::rns::Gl128ResearchSelectorPersistenceSink;
    using NativeGL128ResearchPersistedSelectorBank =
        glscheme::rns::Gl128ResearchPersistedSelectorBank;
    using NativeGL128ResearchSelectorBlobLeaseCallbacks =
        glscheme::rns::Gl128ResearchSelectorBlobLeaseCallbacks;
    using NativeGL128ResearchSelectorOpeningReceipt =
        glscheme::rns::Gl128ResearchSelectorOpeningReceipt;
    using NativeGL128ResearchSelectorProviderOpeningResult =
        glscheme::rns::Gl128ResearchSelectorProviderOpeningResult;
    using NativeGL128ResearchInputPreparationEvidence =
        glscheme::rns::Gl128ResearchInputPreparationEvidence;
    using NativeGL128ResearchInputPreparationResult =
        glscheme::rns::Gl128ResearchInputPreparationResult;
    using NativeGL128ResearchAllYStcEvidence =
        glscheme::rns::Gl128ResearchAllYStcEvidence;
    using NativeGL128ResearchBootstrapEvidence =
        glscheme::rns::Gl128ResearchBootstrapEvidence;
    using NativeGL128ResearchBootstrapResult =
        glscheme::rns::Gl128ResearchBootstrapResult;
    using NativeGL128BootstrapAcceptanceLimits =
        glscheme::rns::Gl128BootstrapAcceptanceLimits;
    using NativeGL128BootstrapAcceptanceReceipt =
        glscheme::rns::Gl128BootstrapAcceptanceReceipt;
    using NativeGL128ResearchBootstrapAcceptanceReceipt =
        glscheme::rns::Gl128ResearchBootstrapAcceptanceReceipt;
    using NativeGL128H64ResearchProfileReceipt =
        glscheme::rns::GlrH64ResearchProfileReceipt;
    using NativeGL128H64HiddenSelectorStorageReceipt =
        glscheme::rns::GlrH64HiddenSelectorStorageReceipt;
    using NativeGL128H64HiddenSelectorPlan =
        glscheme::rns::GlrH64HiddenSelectorPlan;
    using NativeGL128H64HiddenControlKind =
        glscheme::rns::GlrH64HiddenControlKind;
    using NativeGL128H64HiddenControlDescriptor =
        glscheme::rns::GlrH64HiddenControlDescriptor;
    using NativeGL128H64HiddenSelectorOwnerSeed =
        glscheme::rns::GlrH64HiddenSelectorOwnerSeed;
    using NativeGL128H64HiddenSelectorCheckpoint =
        glscheme::rns::GlrH64HiddenSelectorCheckpoint;
    using NativeGL128H64HiddenSelectorManifest =
        glscheme::rns::GlrH64HiddenSelectorManifest;
    using NativeGL128H64HiddenSelectorBinding =
        glscheme::rns::GlrH64HiddenSelectorBinding;
    using NativeGL128H64HiddenSelectorRecordSink =
        glscheme::rns::GlrH64HiddenSelectorRecordSink;
    using NativeGL128H64HiddenSelectorGenerationResult =
        glscheme::rns::GlrH64HiddenSelectorGenerationResult;
    using NativeGL128H64HiddenSelectorOwnerCursorSink =
        glscheme::rns::GlrH64HiddenSelectorOwnerCursorSink;
    using NativeGL128H64HiddenSelectorOwnerCursorEmission =
        glscheme::rns::GlrH64HiddenSelectorOwnerCursorEmission;
    using NativeGL128H64HiddenSelectorOwnerCursor =
        glscheme::rns::GlrH64HiddenSelectorOwnerCursor;
    using NativeGL128H64HiddenSelectorLeaseCallbacks =
        glscheme::rns::GlrH64HiddenSelectorLeaseCallbacks;
    using NativeGL128H64HiddenSelectorProvider =
        glscheme::rns::GlrH64HiddenSelectorProvider;
    using NativeGL128ValidatedH64HiddenSelectorSession =
        glscheme::rns::GlrValidatedH64HiddenSelectorSession;
    using NativeGL128H64CpuCmuxEvidence =
        glscheme::rns::GlrH64CpuCmuxEvidence;
    using NativeGL128H64PublicRootSource =
        glscheme::rns::GlrH64PublicRootSource;
    using NativeGL128H64PublicRootCandidateRequest =
        glscheme::rns::GlrH64PublicRootCandidateRequest;
    using NativeGL128H64PublicRootCandidatePair =
        glscheme::rns::GlrH64PublicRootCandidatePair;
    using NativeGL128H64PublicRootProviderManifest =
        glscheme::rns::GlrH64PublicRootProviderManifest;
    using NativeGL128H64PublicRootProviderBinding =
        glscheme::rns::GlrH64PublicRootProviderBinding;
    using NativeGL128H64PublicRootProviderCallbacks =
        glscheme::rns::GlrH64PublicRootProviderCallbacks;
    using NativeGL128H64PublicRootCandidateProvider =
        glscheme::rns::GlrH64PublicRootCandidateProvider;
    using NativeGL128H64ConcretePublicRootProviderOpening =
        glscheme::rns::GlrH64ConcretePublicRootProviderOpening;
    using NativeGL128H64SparseFoldKskBinding =
        glscheme::rns::GlrH64SparseFoldKskBinding;
    using NativeGL128H64SparseFoldEvidence =
        glscheme::rns::GlrH64SparseFoldEvidence;
    using NativeGL128H64SparseFoldResult =
        glscheme::rns::GlrH64SparseFoldResult;
    using NativeGL128H64AllYPublicSourceScheduleEntry =
        glscheme::rns::GlrH64AllYPublicSourceScheduleEntry;
    using NativeGL128H64AllYPublicSourceSchedule =
        glscheme::rns::GlrH64AllYPublicSourceSchedule;
    using NativeGL128H64AllYPublicRootProviderResolver =
        glscheme::rns::GlrH64AllYPublicRootProviderResolver;
    using NativeGL128H64ResearchAllYStcEvidence =
        glscheme::rns::Gl128H64ResearchAllYStcEvidence;
    using NativeGL128H64ResearchAllYStcResult =
        glscheme::rns::Gl128H64ResearchAllYStcResult;
    using NativeGL128H64WActionOperationCensus =
        glscheme::rns::GlrH64WActionOperationCensus;
    using NativeGL128H64WActionMaterialCensus =
        glscheme::rns::GlrH64WActionMaterialCensus;
    using NativeGL128H64WActionResearchEvidence =
        glscheme::rns::GlrH64WActionResearchEvidence;
    using NativeGL128H64WActionPlan =
        glscheme::rns::GlrH64WActionPlan;
    using NativeGL128H64OwnerRootProductEvidence =
        glscheme::rns::GlrH64OwnerRootProductEvidence;
    using NativeGL128H64OwnerRootProductResult =
        glscheme::rns::GlrH64OwnerRootProductResult;
    using NativeGL128H64P257OneBitMaterial =
        glscheme::rns::GlrH64P257OneBitMaterial;
    using NativeGL128H64P257OneBitRequest =
        glscheme::rns::GlrH64P257OneBitRequest;
    using NativeGL128H64P257OneBitEvidence =
        glscheme::rns::GlrH64P257OneBitEvidence;
    using NativeGL128H64P257OneBitResult =
        glscheme::rns::GlrH64P257OneBitResult;
    using NativeGL128H64P257OneBitGpuEvidence =
        glscheme::rns::GlrH64P257OneBitGpuEvidence;
    using NativeGL128H64P257OneBitGpuResult =
        glscheme::rns::GlrH64P257OneBitGpuResult;
    using NativeGL128H64P257PrefixSpliceMaterial =
        glscheme::rns::GlrH64P257PrefixSpliceMaterial;
    using NativeGL128H64P257PrefixSpliceEvidence =
        glscheme::rns::GlrH64P257PrefixSpliceEvidence;
    using NativeGL128H64P257PrefixSpliceResult =
        glscheme::rns::GlrH64P257PrefixSpliceResult;
    using NativeGL128H64P257RightMuxRotMaterial =
        glscheme::rns::GlrH64P257RightMuxRotMaterial;
    using NativeGL128H64P257RightMuxRotEvidence =
        glscheme::rns::GlrH64P257RightMuxRotEvidence;
    using NativeGL128H64P257RightMuxRotResult =
        glscheme::rns::GlrH64P257RightMuxRotResult;
    using NativeGL128H64SelectedLeafFoldBinding =
        glscheme::rns::GlrH64SelectedLeafFoldBinding;
    using NativeGL128H64SelectedLeafRequest =
        glscheme::rns::GlrH64SelectedLeafRequest;
    using NativeGL128H64SelectedSparseLeaf =
        glscheme::rns::GlrH64SelectedSparseLeaf;
    using NativeGL128H64SelectedLeafVisitor =
        glscheme::rns::GlrH64SelectedLeafVisitor;
    using NativeGL128H64SelectedLeafProvider =
        glscheme::rns::GlrH64SelectedLeafProvider;
    using NativeGL128H64SelectedLeafFoldEvidence =
        glscheme::rns::GlrH64SelectedLeafFoldEvidence;
    using NativeGL128H64SelectedLeafFoldResult =
        glscheme::rns::GlrH64SelectedLeafFoldResult;
    using NativeGL128H64SelectedLeafFoldCheckpoint =
        glscheme::rns::GlrH64SelectedLeafFoldCheckpoint;
    using NativeGL128H64SelectedLeafFoldCheckpointVisitor =
        glscheme::rns::GlrH64SelectedLeafFoldCheckpointVisitor;
    using NativeGL128H64SelectedLeafGpuFrontierEvidence =
        glscheme::rns::GlrH64SelectedLeafGpuFrontierEvidence;
    using NativeGL128H64SelectedLeafGpuFrontierResult =
        glscheme::rns::GlrH64SelectedLeafGpuFrontierResult;
    using NativeGL128H64SelectedLeafGpuReturnEvidence =
        glscheme::rns::GlrH64SelectedLeafGpuReturnEvidence;
    using NativeGL128H64SelectedLeafGpuReturnResult =
        glscheme::rns::GlrH64SelectedLeafGpuReturnResult;
    using NativeGL128H64CheckedEstimatorTranscript =
        glscheme::rns::GlrH64CheckedEstimatorTranscript;
    using NativeGL128H64StructuredSecurityAudit =
        glscheme::rns::GlrH64StructuredSecurityAudit;
    using NativeGL128CiphertextArtifactSink =
        glscheme::rns::Gl128CiphertextArtifactSink;
    using NativeGL128CiphertextArtifactSource =
        glscheme::rns::Gl128CiphertextArtifactSource;
    using NativeGL128CiphertextArtifactReceipt =
        glscheme::rns::Gl128CiphertextArtifactReceipt;
    using NativeGL128CiphertextArtifactReadResult =
        glscheme::rns::Gl128CiphertextArtifactReadResult;

    static_assert(NativeGL128ResearchOnlySession::research_only);
    static_assert(
        !NativeGL128ResearchOnlySession::production_security_claim);
    static_assert(
        !NativeGL128ResearchOnlySession::production_authorization_admitted);
    static_assert(NativeGL128ResearchPersistedSelectorBank::research_only);
    static_assert(NativeGL128ResearchSelectorOpeningReceipt::research_only);
    static_assert(NativeGL128ResearchBootstrapEvidence::research_only);
    static_assert(
        NativeGL128ResearchBootstrapAcceptanceReceipt::research_only);
    static_assert(!NativeGL128ResearchBootstrapAcceptanceReceipt::
                      production_security_claim);
    static_assert(!NativeGL128ResearchBootstrapAcceptanceReceipt::
                      production_authorization_admitted);
    static_assert(!std::is_convertible_v<
                  NativeGL128ResearchOnlySession,
                  NativeGL128DirectBootstrapAuthorizationBundle>);
    static_assert(!std::is_constructible_v<
                  NativeGL128DirectBootstrapAuthorizationBundle,
                  NativeGL128ResearchOnlySession>);
    static_assert(!std::is_convertible_v<
                  NativeGL128ResearchPersistedSelectorBank,
                  NativeGL128PersistedSelectorBankResult>);
    static_assert(!std::is_constructible_v<
                  NativeGL128PersistedSelectorBankResult,
                  NativeGL128ResearchPersistedSelectorBank>);
    static_assert(!std::is_convertible_v<
                  NativeGL128ResearchSelectorProviderOpeningResult,
                  NativeDirectVectorProductionSelectorProviderOpeningResult>);
    static_assert(!std::is_convertible_v<
                  NativeGL128ResearchBootstrapResult,
                  NativeGL128BootstrapResult>);
    static_assert(!std::is_convertible_v<
                  NativeGL128ResearchBootstrapAcceptanceReceipt,
                  NativeGL128BootstrapAcceptanceReceipt>);
    static_assert(!std::is_constructible_v<
                  NativeGL128BootstrapAcceptanceReceipt,
                  NativeGL128ResearchBootstrapAcceptanceReceipt>);

    // The H64 lane is a bounded executable research composition only.  It
    // retains the one-branch L14 seam and additionally composes all 128 rows,
    // both branches per row, and authenticated forward StC to primary L18.
    // Neither surface has a production-authorization conversion seam.
    struct NativeGL128H64ResearchPosture final {
        static constexpr bool research_only = true;
        static constexpr bool one_branch_sparse_fold_executable = true;
        static constexpr bool full_all_y_stc_composed = true;
        static constexpr bool exact_estimator_evidence_present = false;
        static constexpr bool exact_noise_evidence_present = false;
        static constexpr bool production_security_claim = false;
        static constexpr bool production_authorization_admitted = false;
    };

    // Allocation-free projection of the authenticated logarithmic W-action
    // research plan.  The full native plan remains available separately;
    // these fields are the deployment-facing census/admission summary.
    struct NativeGL128H64WActionResearchCapabilities final {
        std::string schema =
            "openfhe.gl128_h64_w_action_research_capabilities.v1";
        std::string nativePlanSchema =
            glscheme::rns::kGlrH64WActionPlanSchema;
        std::uint64_t currentOracleExternalProducts = 0;
        std::uint64_t logarithmicExternalProducts = 0;
        std::uint64_t logarithmicCompactMaterialBytes = 0;
        std::uint64_t compactBytesIncludingSparseFold = 0;
        std::uint32_t controlSpecialPrimeCount = 0;
        std::uint32_t prefixMaskSpecialPrimeCount = 0;
        std::uint32_t actionKeySpecialPrimeCount = 0;
        std::uint32_t sparseFoldSpecialPrimeCount = 0;
        bool allocationFreeCryptographicPlan = false;
        bool capabilityQueryMaterializesMaterial = false;
        bool encryptedLogarithmicCircuitExecuted = false;
        bool exactEstimatorEvidencePresent = false;
        bool exactNoiseEvidencePresent = false;
        bool productionSecurityAuthorized = false;
        bool bootstrapDirectAdmitted = false;
    };

    struct NativeGL128H64P257PrefixSpliceCapabilities final {
        std::string schema =
            "openfhe.gl128_h64_p257_prefix_splice_capabilities.v1";
        std::string nativeMaterialSchema =
            "glscheme.gl128_h64_p257_prefix_splice_material.v1";
        std::string nativeEvidenceSchema =
            "glscheme.gl128_h64_p257_prefix_splice_evidence.v1";
        std::uint64_t xwCoordinatesPerRequest = 32768;
        std::uint32_t encryptedWBitsExecuted = 1;
        std::uint32_t controlSpecialPrimeCount = 13;
        std::uint32_t maskLevel = 0;
        std::uint32_t outputLevel = 2;
        std::uint64_t peakExpandedControlBytes = 159383552;
        bool cpuValueExecutionExposed = true;
        bool encryptedBinaryMaskReturned = true;
        bool encryptedPrefixSpliceExecuted = true;
        bool fixedWholeFormulaArmsSelected = false;
        bool keyedWRotationsExecuted = false;
        bool encryptedDenominatorExecuted = false;
        bool completeEightBitWActionExecuted = false;
        bool exactNoiseEvidencePresent = false;
        bool productionSecurityAuthorized = false;
        bool bootstrapDirectAdmitted = false;
    };

    struct NativeGL128H64P257RightMuxRotCapabilities final {
        std::string schema =
            "openfhe.gl128_h64_p257_right_muxrot_capabilities.v1";
        std::string nativeMaterialSchema =
            "glscheme.gl128_h64_p257_right_muxrot_material.v1";
        std::string nativeEvidenceSchema =
            "glscheme.gl128_h64_p257_right_muxrot_evidence.v1";
        std::uint64_t xwCoordinatesPerRequest = 32768;
        std::uint32_t distinctEncryptedWBitsExecuted = 1;
        std::uint32_t authenticatedWBitControlUses = 2;
        std::uint32_t rightRotationAmount = 255;
        std::uint32_t rotationKeyLevel = 2;
        std::uint32_t rotationSpecialPrimeCount = 13;
        std::uint64_t peakExpandedKeyBytes = 159383552;
        bool cpuValueExecutionExposed = true;
        bool encryptedPrefixSpliceExecuted = true;
        bool keyedWRotationsExecuted = true;
        bool encryptedDenominatorExecuted = false;
        bool completeEightBitWActionExecuted = false;
        bool exactNoiseEvidencePresent = false;
        bool productionSecurityAuthorized = false;
        bool bootstrapDirectAdmitted = false;
    };

    // Typed projection of the first value-executed, complete H64 product
    // fold.  GLScheme core revision 3f2675b1 accepts exactly 64 already
    // selected randomized sparse-key leaves at L2, executes the full P14
    // six-frontier tree and real/primary return at L14, and reports its own
    // evidence.  This adapter delegates that exact CPU seam; it does not
    // claim that OpenFHE-native ciphertexts, hidden controls, all Y rows, or
    // a production refresh have executed.
    struct NativeGL128H64SelectedLeafFoldCapabilities final {
        std::string schema =
            "openfhe.gl128_h64_selected_leaf_fold_capabilities.v1";
        std::string nativeCoreCommit =
            "3f2675b1514f6535e63164074bf079bc8ecc7f36";
        std::string nativeBindingSchema =
            "glscheme.gl128_h64_selected_leaf_fold_binding.v1";
        std::string nativeEvidenceSchema =
            "glscheme.gl128_h64_selected_leaf_fold_evidence.v1";
        std::string parameterFingerprint =
            "glrsha256:66a12778024471924327683b7f52e8df4dd038cb3f7f803a516b393e1363e6ab";
        std::string supportCommitment =
            "glr-ship-support-v1:n=128:phi=256:count=64:fnv64=16830100300970850058";
        std::uint32_t matrixOrder = 128;
        std::uint32_t matrixCount = 256;
        std::uint64_t xwCoordinatesPerLeaf = 32768;
        std::uint32_t selectedLeafCount = 64;
        std::uint32_t leafLevel = 2;
        std::uint32_t rootLevel = 14;
        std::uint32_t outputLevel = 14;
        std::array<std::uint32_t, 6> frontierInputLevels{
            2, 4, 6, 8, 10, 12};
        std::array<std::uint32_t, 6> frontierProductCounts{
            32, 16, 8, 4, 2, 1};
        std::uint32_t treeProductNodes = 63;
        std::uint32_t treeRelinearizations = 63;
        std::uint32_t treePairedRescales = 63;
        std::uint32_t physicalQPrimeDrops = 126;
        std::uint32_t conjugationToSparseSwitches = 1;
        std::uint32_t sparseToPrimarySwitches = 1;
        std::uint32_t sparseRelinKeyLeases = 1;
        std::uint32_t fullP14SpecialPrimeSentinel = 0;
        std::uint32_t effectiveSpecialPrimeCount = 14;
        std::uint64_t compactThreeKeyBytes = 32505952;
        std::uint32_t peakLiveLeafLeases = 1;
        std::uint32_t peakLiveSparseTreeFrontierCiphertexts = 7;
        std::uint32_t peakLiveEvaluationKeys = 1;
        bool cpuValueDelegationExposed = true;
        bool coreOwnerAcceptanceValueExecuted = true;
        bool frameworkNativeValuePassExecuted = false;
        bool randomizedNontransparentSparseLeavesRequired = true;
        bool synchronousOneLeafProviderRequired = true;
        bool fullP14FoldScheduleRequired = true;
        bool underprovisionedP13Accepted = false;
        bool restrictedP1Accepted = false;
        bool hiddenControlSelectionExecuted = false;
        bool full64SupportHiddenControlFold = false;
        bool fullAllYStcComposed = false;
        bool exactEstimatorEvidencePresent = false;
        bool formalComposedNoiseCertificatePresent = false;
        bool structuredSecurityCertificatePresent = false;
        bool gpuValueExecutionExposed = false;
        bool productionSecurityAuthorized = false;
        bool bootstrapDirectAdmitted = false;
    };

    // Owner-only, write-only projection of the private-checkpoint H64
    // material cursor introduced by GLScheme core 599dde94.  The bounded
    // acceptance emits the first support's ten records and proves exactly-once
    // progression without loading old records.  It is not evidence that all
    // 640 controls, a complete material bank, or the hidden fold executed.
    struct NativeGL128H64HiddenSelectorOwnerCursorCapabilities final {
        std::string schema =
            "openfhe.gl128_h64_hidden_selector_owner_cursor_capabilities.v1";
        std::string nativeCoreCommit =
            "599dde94b91b10249eb6d222e008bf67b5b6b457";
        std::string parameterFingerprint =
            "glrsha256:66a12778024471924327683b7f52e8df4dd038cb3f7f803a516b393e1363e6ab";
        std::string supportCommitment =
            "glr-ship-support-v1:n=128:phi=256:count=64:fnv64=16830100300970850058";
        std::uint32_t sparseSupportCount = 64;
        std::uint32_t controlsPerSupport = 10;
        std::uint32_t canonicalControlRecordCount = 640;
        std::uint32_t materialKeyLevel = 0;
        std::uint32_t materialSpecialPrimeCount = 13;
        std::uint32_t minimumRecordsPerEmission = 1;
        std::uint32_t maximumRecordsPerEmission = 10;
        std::uint32_t boundedAcceptanceRecordsEmitted = 10;
        std::array<std::uint32_t, 2> boundedAcceptanceChunkPattern{1, 9};
        std::uint32_t recordsLoadedOrVerifiedPerEmission = 0;
        std::uint32_t peakLiveFullPairs = 1;
        std::uint32_t peakLiveCompactRecords = 1;
        bool ownerOnly = true;
        bool moveOnlyCursor = true;
        bool storeOnlySink = true;
        bool loadCallbackExposed = false;
        bool privateLibraryCheckpointState = true;
        bool privateCheckpointUnforgeableByPublicApi = true;
        bool callerCheckpointInjectionExposed = false;
        bool poisonedPersistenceRetryRejected = true;
        bool exactlyOnceChunkProgressionExecuted = true;
        bool legacyRecordZeroByteParity = true;
        bool boundedFirstSupportGenerationExecuted = true;
        bool canonical640RecordExecutionCompleted = false;
        bool completeManifestProduced = false;
        bool fullMaterialBankMaterialized = false;
        bool full64SupportHiddenControlFold = false;
        bool fullAllYStcComposed = false;
        bool exactEstimatorEvidencePresent = false;
        bool exactNoiseEvidencePresent = false;
        bool structuredSecurityCertificatePresent = false;
        bool gpuExecutionExposed = false;
        bool productionSecurityAuthorized = false;
        bool bootstrapDirectAdmitted = false;
    };

    // Device-conditional projection of core f9324e8a's bounded h4 CUDA
    // selected-leaf frontier.  Four already-selected randomized sparse L2
    // leaves execute three full-P14 product/relinearization/paired-rescale
    // nodes and return a DeviceDirty sparse L6 root.  The measurements below
    // are the core owner acceptance, not an OpenFHE-native ciphertext run.
    struct NativeGL128H64SelectedLeafH4GpuCapabilities final {
        std::string schema =
            "openfhe.gl128_h64_selected_leaf_h4_gpu_capabilities.v1";
        std::string nativeCoreCommit =
            "f9324e8a73f8ca98e0bc4e334890e0e83a84f3e1";
        std::string nativeEvidenceSchema =
            "glscheme.gl128_h64_selected_leaf_gpu_frontier_evidence.v1";
        std::string parameterFingerprint =
            "glrsha256:66a12778024471924327683b7f52e8df4dd038cb3f7f803a516b393e1363e6ab";
        std::string supportCommitment =
            "glr-ship-support-v1:n=128:phi=256:count=64:fnv64=16830100300970850058";
        std::uint32_t selectedLeafCount = 4;
        std::uint32_t xwCoordinatesPerLeaf = 32768;
        std::uint32_t treeDepth = 2;
        std::uint32_t leafLevel = 2;
        std::uint32_t rootLevel = 6;
        std::array<std::uint32_t, 2> frontierInputLevels{2, 4};
        std::array<std::uint32_t, 2> frontierProductCounts{2, 1};
        std::uint32_t treeProductNodes = 3;
        std::uint32_t treeRelinearizations = 3;
        std::uint32_t treePairedRescales = 3;
        std::uint32_t physicalQPrimeDrops = 6;
        std::uint32_t fullP14SpecialPrimeSentinel = 0;
        std::uint32_t effectiveSpecialPrimeCount = 14;
        std::uint64_t inputLeafBoundaryH2DBytes = 96468992;
        std::uint64_t ownerReadbackD2HBytes = 19922944;
        std::uint64_t stageCiphertextValueH2DBytes = 0;
        std::uint64_t stageCiphertextValueD2HBytes = 0;
        std::uint32_t decryptedCoordinateCount = 32768;
        double maximumObservedValueError = 1.086e-10;
        double internalRuntimeSeconds = 5.81;
        double wallRuntimeSeconds = 6.00;
        double peakRssMiB = 595.46;
        bool deviceConditional = true;
        bool gpuDeviceAvailable = false;
        bool gpuCallableExposed = true;
        bool coreCudaValueExecutionObserved = true;
        bool openfheNativeValueExecutionObserved = false;
        bool randomizedNontransparentSparseLeaves = true;
        bool exactP14SparseRelinearizationExecuted = true;
        bool exactN32PairedRescalesExecuted = true;
        bool exactInputUploadOnce = true;
        bool noStageCiphertextValuePcie = true;
        bool outputDeviceDirty = true;
        bool outputAuthoritative = true;
        bool exactCpuCiphertextByteParity = true;
        bool allCoordinatesOwnerDecrypted = true;
        bool hiddenControlSelectionExecuted = false;
        bool complete64SupportFoldExecuted = false;
        bool conjugationReturnExecuted = false;
        bool sparseToPrimaryReturnExecuted = false;
        bool fullAllYStcComposed = false;
        bool exactNoiseCertificatePresent = false;
        bool structuredSecurityCertificatePresent = false;
        bool gpuH64BootstrapReady = false;
        bool productionSecurityAuthorized = false;
        bool bootstrapDirectAdmitted = false;
    };

    // Append-only projection of core cef5ac76's complete 64-selected-leaf
    // resident CUDA product tree.  It reaches a DeviceDirty sparse L14 root,
    // but deliberately stops before conjugation and sparse-to-primary return.
    // "Complete" here qualifies only the already-selected product tree; it
    // does not qualify hidden selection or a bootstrap.
    struct NativeGL128H64SelectedLeaf64GpuCapabilities final {
        std::string schema =
            "openfhe.gl128_h64_selected_leaf_64_gpu_capabilities.v1";
        std::string nativeCoreCommit =
            "cef5ac76b72b9c4b6da2e6d14519172305002739";
        std::string nativeEvidenceSchema =
            "glscheme.gl128_h64_selected_leaf_gpu_frontier_evidence.v1";
        std::string parameterFingerprint =
            "glrsha256:66a12778024471924327683b7f52e8df4dd038cb3f7f803a516b393e1363e6ab";
        std::string supportCommitment =
            "glr-ship-support-v1:n=128:phi=256:count=64:fnv64=16830100300970850058";
        std::uint32_t selectedLeafCount = 64;
        std::uint32_t xwCoordinatesPerLeaf = 32768;
        std::uint32_t treeDepth = 6;
        std::uint32_t leafLevel = 2;
        std::uint32_t rootLevel = 14;
        std::array<std::uint32_t, 6> frontierInputLevels{
            2, 4, 6, 8, 10, 12};
        std::array<std::uint32_t, 6> frontierProductCounts{
            32, 16, 8, 4, 2, 1};
        std::uint32_t treeProductNodes = 63;
        std::uint32_t treeRelinearizations = 63;
        std::uint32_t treePairedRescales = 63;
        std::uint32_t physicalQPrimeDrops = 126;
        std::uint32_t fullP14SpecialPrimeSentinel = 0;
        std::uint32_t effectiveSpecialPrimeCount = 14;
        std::uint64_t inputLeafBoundaryH2DBytes = 1543503872;
        std::uint64_t ownerReadbackD2HBytes = 11534336;
        std::uint64_t stageCiphertextValueH2DBytes = 0;
        std::uint64_t stageCiphertextValueD2HBytes = 0;
        std::uint32_t decryptedCoordinateCount = 32768;
        double maximumObservedValueError = 4.340e-10;
        double internalRuntimeSeconds = 34.71;
        double wallRuntimeSeconds = 34.92;
        double peakRssMiB = 604.52;
        bool deviceConditional = true;
        bool gpuDeviceAvailable = false;
        bool gpuCallableExposed = true;
        bool coreCudaValueExecutionObserved = true;
        bool openfheNativeValueExecutionObserved = false;
        bool randomizedNontransparentSparseLeaves = true;
        bool exactP14SparseRelinearizationExecuted = true;
        bool exactN32PairedRescalesExecuted = true;
        bool exactSixFrontierL2ToL14Schedule = true;
        bool complete64SelectedLeafProductTreeExecuted = true;
        bool exactInputUploadOnce = true;
        bool noStageCiphertextValuePcie = true;
        bool outputDeviceDirty = true;
        bool outputAuthoritative = true;
        bool allCoordinatesOwnerDecrypted = true;
        bool hiddenControlSelectionExecuted = false;
        bool complete64SupportHiddenControlFold = false;
        bool conjugationReturnExecuted = false;
        bool sparseToPrimaryReturnExecuted = false;
        bool fullAllYStcComposed = false;
        bool exactNoiseCertificatePresent = false;
        bool structuredSecurityCertificatePresent = false;
        bool gpuH64BootstrapReady = false;
        bool productionSecurityAuthorized = false;
        bool bootstrapDirectAdmitted = false;
    };

    // Append-only projection of core ddf77625's resident return from the
    // already-selected sparse L14 root.  The exact lane-swap/conjugation
    // switch, two-component real add, and sparse-to-primary switch remain on
    // device.  This does not imply hidden-control or all-Y execution.
    struct NativeGL128H64SelectedLeaf64GpuReturnCapabilities final {
        std::string schema =
            "openfhe.gl128_h64_selected_leaf_64_gpu_return_capabilities.v1";
        std::string nativeCoreCommit =
            "ddf77625ae1cc4de1183223e761c4d9df0b32411";
        std::string nativeEvidenceSchema =
            "glscheme.gl128_h64_selected_leaf_gpu_return_evidence.v1";
        std::string parameterFingerprint =
            "glrsha256:66a12778024471924327683b7f52e8df4dd038cb3f7f803a516b393e1363e6ab";
        std::string supportCommitment =
            "glr-ship-support-v1:n=128:phi=256:count=64:fnv64=16830100300970850058";
        std::uint32_t inputLevel = 14;
        std::uint32_t outputLevel = 14;
        std::uint32_t fullP14SpecialPrimeSentinel = 0;
        std::uint32_t effectiveSpecialPrimeCount = 14;
        std::uint32_t laneSwapAutomorphisms = 1;
        std::uint32_t conjugationToSparseSwitches = 1;
        std::uint32_t residentComponentAdds = 2;
        std::uint32_t sparseToPrimarySwitches = 1;
        std::uint64_t stageCiphertextValueH2DBytes = 0;
        std::uint64_t stageCiphertextValueD2HBytes = 0;
        std::uint32_t decryptedCoordinateCount = 32768;
        double maximumObservedValueError = 8.666e-10;
        double endToEndInternalRuntimeSeconds = 31.77;
        double endToEndWallRuntimeSeconds = 31.95;
        double peakRssMiB = 604.87;
        bool deviceConditional = true;
        bool gpuDeviceAvailable = false;
        bool gpuCallableExposed = true;
        bool coreCudaValueExecutionObserved = true;
        bool openfheNativeValueExecutionObserved = false;
        bool authenticatedFullP14ReturnSchedule = true;
        bool selectedLeafSparseL14RootConsumed = true;
        bool residentLaneSwapExecuted = true;
        bool conjugationReturnExecuted = true;
        bool sparseRealAddExecuted = true;
        bool sparseToPrimaryReturnExecuted = true;
        bool noStageCiphertextValuePcie = true;
        bool outputDeviceDirty = true;
        bool outputAuthoritative = true;
        bool allCoordinatesOwnerDecrypted = true;
        bool hiddenControlSelectionExecuted = false;
        bool full64SupportHiddenControlFold = false;
        bool fullAllYStcComposed = false;
        bool exactNoiseCertificatePresent = false;
        bool structuredSecurityCertificatePresent = false;
        bool gpuH64BootstrapReady = false;
        bool productionSecurityAuthorized = false;
        bool bootstrapDirectAdmitted = false;
    };

    // Executable CPU anchor for one canonical encrypted W-index bit.  This
    // is deliberately a distinct capability from the metadata-only complete
    // logarithmic plan: it covers the full 32,768-coordinate grid and the
    // real P13 CMux/product/relinearize/paired-rescale path, but not prefix
    // splice, keyed W rotations, all eight bits, or a complete H64 row.
    struct NativeGL128H64P257OneBitCapabilities final {
        std::string schema =
            "openfhe.gl128_h64_p257_one_bit_capabilities.v1";
        std::string nativeMaterialSchema =
            "glscheme.gl128_h64_p257_one_bit_material.v1";
        std::string nativeEvidenceSchema =
            "glscheme.gl128_h64_p257_one_bit_evidence.v1";
        std::uint32_t matrixOrder = 128;
        std::uint32_t matrixCount = 256;
        std::uint64_t xwCoordinatesPerRequest = 32768;
        std::uint32_t encryptedWBitsExecuted = 1;
        std::uint32_t controlSpecialPrimeCount = 13;
        std::uint32_t relinearizationSpecialPrimeCount = 13;
        std::uint32_t inputLevel = 0;
        std::uint32_t outputLevel = 2;
        bool cpuValueExecutionExposed = true;
        bool gpuValueExecutionExposed = true;
        bool gpuDeviceAvailable = false;
        bool actualCiphertextProductExecuted = true;
        bool exactPairedRescaleExecuted = true;
        bool outputReanchoredToDelta = false;
        bool encryptedPrefixSpliceExecuted = false;
        bool keyedWRotationsExecuted = false;
        bool completeEightBitWActionExecuted = false;
        bool hiddenFineXSelectionExecuted = false;
        bool hiddenSignSelectionExecuted = false;
        bool exactNoiseEvidencePresent = false;
        bool productionSecurityAuthorized = false;
        bool bootstrapDirectAdmitted = false;
    };

    // Allocation-free projection of the checked structured-H64 audit.  The
    // 134.213965-bit number is explicitly the free-support SparseTernary(h64)
    // proxy over Q25P14, not a certificate for the implemented public-window
    // distribution or its related evaluation-key/KDM exposure.
    struct NativeGL128H64StructuredSecurityCapabilities final {
        std::string schema =
            "openfhe.gl128_h64_structured_security_capabilities.v1";
        std::string nativeAuditSchema =
            glscheme::rns::kGl128H64StructuredSecurityAuditSchema;
        std::string auditCommitment;
        double freeSupportProxyClassicalBits = 0.0;
        std::uint32_t rawPublicWindowChoiceBits = 0;
        std::uint32_t genericSplitTimeBits = 0;
        std::uint32_t genericSplitMemoryBits = 0;
        bool cryptographicMaterialAllocationFree = false;
        bool capabilityQueryMaterializesMaterial = false;
        bool freeSupportProxyOnly = true;
        bool structuredPublicWindowDistributionModeled = false;
        bool exactStructuredSecurityCertificatePresent = false;
        bool composedKeyLeakageTheoremPresent = false;
        bool productionSecurityAuthorized = false;
        bool bootstrapDirectAdmitted = false;
    };

    static_assert(NativeGL128H64ResearchPosture::research_only);
    static_assert(NativeGL128H64ResearchPosture::full_all_y_stc_composed);
    static_assert(NativeGL128H64ResearchAllYStcEvidence::research_only);
    static_assert(!NativeGL128H64ResearchAllYStcEvidence::
                      production_security_claim);
    static_assert(!NativeGL128H64ResearchAllYStcEvidence::
                      production_authorization_admitted);
    static_assert(
        !NativeGL128H64ResearchPosture::production_security_claim);
    static_assert(
        !NativeGL128H64ResearchPosture::production_authorization_admitted);
    static_assert(!std::is_convertible_v<
                  NativeGL128H64WActionPlan,
                  NativeGL128DirectBootstrapAuthorizationBundle>);
    static_assert(!std::is_constructible_v<
                  NativeGL128DirectBootstrapAuthorizationBundle,
                  NativeGL128H64WActionPlan>);
    static_assert(NativeGL128H64P257OneBitEvidence::research_only);
    static_assert(!NativeGL128H64P257OneBitEvidence::
                      production_security_authorized);
    static_assert(!NativeGL128H64P257OneBitEvidence::
                      bootstrap_direct_admitted);
    static_assert(NativeGL128H64P257OneBitGpuEvidence::research_only);
    static_assert(!NativeGL128H64P257OneBitGpuEvidence::gpu_h64_bootstrap_ready);
    static_assert(NativeGL128H64P257PrefixSpliceEvidence::research_only);
    static_assert(!NativeGL128H64P257PrefixSpliceEvidence::
                      production_security_authorized);
    static_assert(NativeGL128H64P257RightMuxRotEvidence::research_only);
    static_assert(!NativeGL128H64P257RightMuxRotEvidence::
                      production_security_authorized);
    static_assert(!std::is_convertible_v<
                  NativeGL128H64SelectedLeafFoldResult,
                  NativeGL128BootstrapResult>);
    static_assert(!std::is_copy_constructible_v<
                  NativeGL128H64HiddenSelectorOwnerCursor>);
    static_assert(!std::is_copy_assignable_v<
                  NativeGL128H64HiddenSelectorOwnerCursor>);
    static_assert(std::is_nothrow_move_constructible_v<
                  NativeGL128H64HiddenSelectorOwnerCursor>);
    static_assert(std::is_nothrow_move_assignable_v<
                  NativeGL128H64HiddenSelectorOwnerCursor>);
    static_assert(!std::is_convertible_v<
                  NativeGL128H64HiddenSelectorOwnerCursor,
                  NativeGL128H64HiddenSelectorCheckpoint>);
    static_assert(NativeGL128H64SelectedLeafGpuFrontierEvidence::
                      research_only);
    static_assert(!NativeGL128H64SelectedLeafGpuFrontierEvidence::
                      hidden_control_selection_executed);
    static_assert(!NativeGL128H64SelectedLeafGpuFrontierEvidence::
                      conjugation_return_executed);
    static_assert(!NativeGL128H64SelectedLeafGpuFrontierEvidence::
                      sparse_to_primary_return_executed);
    static_assert(!NativeGL128H64SelectedLeafGpuFrontierEvidence::
                      exact_noise_certificate_present);
    static_assert(!NativeGL128H64SelectedLeafGpuFrontierEvidence::
                      structured_security_certificate_present);
    static_assert(!NativeGL128H64SelectedLeafGpuFrontierEvidence::
                      production_security_authorized);
    static_assert(!NativeGL128H64SelectedLeafGpuFrontierEvidence::
                      bootstrap_direct_admitted);
    static_assert(!NativeGL128H64SelectedLeafGpuFrontierEvidence::
                      gpu_h64_bootstrap_ready);
    static_assert(!std::is_convertible_v<
                  NativeGL128H64SelectedLeafGpuFrontierResult,
                  NativeGL128BootstrapResult>);
    static_assert(NativeGL128H64SelectedLeafGpuReturnEvidence::research_only);
    static_assert(!NativeGL128H64SelectedLeafGpuReturnEvidence::
                      hidden_control_selection_executed);
    static_assert(!NativeGL128H64SelectedLeafGpuReturnEvidence::
                      full_all_y_stc_composed);
    static_assert(!NativeGL128H64SelectedLeafGpuReturnEvidence::
                      exact_noise_certificate_present);
    static_assert(!NativeGL128H64SelectedLeafGpuReturnEvidence::
                      structured_security_certificate_present);
    static_assert(!NativeGL128H64SelectedLeafGpuReturnEvidence::
                      production_security_authorized);
    static_assert(!NativeGL128H64SelectedLeafGpuReturnEvidence::
                      bootstrap_direct_admitted);
    static_assert(!NativeGL128H64SelectedLeafGpuReturnEvidence::
                      gpu_h64_bootstrap_ready);
    static_assert(!std::is_convertible_v<
                  NativeGL128H64SelectedLeafGpuReturnResult,
                  NativeGL128BootstrapResult>);
    static_assert(!std::is_convertible_v<
                  NativeGL128H64P257OneBitResult,
                  NativeGL128BootstrapResult>);
    static_assert(NativeGL128H64OwnerRootProductEvidence::owner_only);
    static_assert(!NativeGL128H64OwnerRootProductEvidence::evaluator_callable);
    static_assert(!NativeGL128H64OwnerRootProductEvidence::
                      production_security_authorized);
    static_assert(!std::is_convertible_v<
                  NativeGL128H64StructuredSecurityAudit,
                  NativeGL128DirectBootstrapAuthorizationBundle>);
    static_assert(!std::is_convertible_v<
                  NativeGL128H64ResearchProfileReceipt,
                  NativeGL128DirectBootstrapAuthorizationBundle>);
    static_assert(!std::is_convertible_v<
                  NativeGL128H64HiddenSelectorPlan,
                  NativeGL128DirectBootstrapAuthorizationBundle>);
    static_assert(!std::is_convertible_v<
                  NativeGL128H64SparseFoldKskBinding,
                  NativeGL128DirectBootstrapAuthorizationBundle>);
    static_assert(!std::is_convertible_v<
                  NativeGL128H64SparseFoldResult,
                  NativeGL128BootstrapResult>);
    static_assert(!std::is_convertible_v<
                  NativeGL128H64ConcretePublicRootProviderOpening,
                  NativeDirectVectorProductionSelectorProviderOpeningResult>);
    static_assert(!std::is_constructible_v<
                  NativeGL128BootstrapResult,
                  NativeGL128H64SparseFoldResult>);
    static_assert(!std::is_copy_constructible_v<
                  NativeGL128H64ResearchAllYStcResult>);
    static_assert(!std::is_convertible_v<
                  NativeGL128H64ResearchAllYStcResult,
                  NativeGL128BootstrapResult>);
    static_assert(!std::is_constructible_v<
                  NativeGL128BootstrapResult,
                  NativeGL128H64ResearchAllYStcResult>);
    static_assert(!std::is_convertible_v<
                  NativeGL128H64ResearchAllYStcResult,
                  NativeGL128DirectBootstrapAuthorizationBundle>);

    static constexpr std::uint32_t kH64AllYRows =
        glscheme::rns::kGl128H64AllYRows;
    static constexpr std::uint32_t kH64AllYBranchesPerRow =
        glscheme::rns::kGl128H64AllYBranchesPerRow;
    static constexpr std::uint32_t kH64AllYBranchFoldCount =
        glscheme::rns::kGl128H64AllYBranchFoldCount;

    static constexpr std::size_t kLegacyDftPlaintextEntryCount =
        glscheme::rns::kGlrDftPlaintextEntryCount;
    static constexpr std::size_t kForwardDftPlaintextEntryCount =
        glscheme::rns::kGlrDftPlaintextForwardEntryCount;
    static constexpr bool kStructuredH40ProductionAuthorizationAvailable =
        NativeDirectVectorProductionAuthorizationEvidence::
            structured_h40_distribution_report_bound;
    static_assert(!kStructuredH40ProductionAuthorizationAvailable,
                  "free-support h40 evidence must not authorize the "
                  "structured GL128 secret");

    // Evidence-only projection of the current resident-q0 GPU ABI.  `native`
    // retains every core counter/bit; the append-only named fields make the
    // resident versus explicit-host-fallback decision and q0 metadata rebase
    // visible without retaining request callbacks or material pointers.  This
    // is not an execution result and cannot authorize or claim production.
    struct ResidentQ0GpuBootstrapEvidenceProjection final {
        static constexpr bool research_only = true;
        static constexpr bool evidence_only = true;
        static constexpr bool production_security_claim = false;
        static constexpr bool production_authorization_admitted = false;

        std::string schema =
            "openfhe.glr.resident_q0_gpu_bootstrap_evidence.v1";
        NativeDirectGpuBootstrapEvidence native;
        std::uint64_t modeledResidentPublicTableBuilds = 0;
        std::uint64_t modeledHostFallbackTableUploads = 0;
        std::uint64_t publicTablePrewarmH2DBytes = 0;
        std::uint64_t publicTablePrewarmD2HBytes = 0;
        std::uint64_t publicQ0BoundaryD2HBytes = 0;
        double publicQ0PreRebaseScale = 1.0;
        double publicQ0PostRebaseScale = 1.0;
        bool explicitHostBoundaryFallbackRequested = false;
        bool residentQ0PathRequested = false;
        bool publicQ0RawResidueMetadataRebased = false;
        bool allYPublicQ0TableEncoderResident = false;
        bool publicQ0TableBoundaryDeclared = false;
        bool publicQ0TableEncoderResident = false;
        bool fullyDeviceResident = false;
        bool nativeEvidenceComplete = false;
        bool productionSecurityClaimed = false;
    };

    static_assert(
        ResidentQ0GpuBootstrapEvidenceProjection::research_only);
    static_assert(!ResidentQ0GpuBootstrapEvidenceProjection::
                       production_security_claim);
    static_assert(!std::is_convertible_v<
                  ResidentQ0GpuBootstrapEvidenceProjection,
                  NativeDirectGpuBootstrapResult>);

    struct DirectVectorProductionRowResult {
        Ciphertext ciphertext;
        NativeDirectVectorEvidence evidence;
    };

    struct DirectVectorProductionAllYResult {
        NativeDirectVectorAllYStcResult native;
        NativeDirectVectorAllYStcEvidence evidence;
    };

    // Allocation-free expected shape for composing 128 direct-vector Y rows
    // into one bounded R' tensor and returning it through the genuine StC
    // boundary.  These are requirements for a future canonical h40 run, not
    // measured execution evidence.  The two explicit false flags prevent a
    // preflight from being mistaken for value/noise acceptance.
    struct DirectVectorAllYReturnPreflight {
        std::uint32_t yRows = 0;
        std::uint32_t selectorLevel = 0;
        std::uint32_t activeSelectorQPrimes = 0;
        std::uint32_t directOutputLevel = 0;
        std::uint32_t directMultiplicativeDepth = 0;
        std::uint32_t rescaleStride = 0;
        std::uint32_t physicalQPrimeDropsPerRow = 0;
        std::uint64_t logicalXwSlotsPerRow = 0;
        std::uint64_t totalXwSlots = 0;
        std::uint64_t selectorCiphertextsVisited = 0;
        std::uint64_t selectorProviderLeases = 0;
        std::uint64_t plaintextCiphertextProducts = 0;
        std::uint64_t leafRescales = 0;
        std::uint64_t treeProductNodes = 0;
        std::uint64_t treeRelinearizations = 0;
        std::uint64_t treeRelinearizationKeyProviderLeases = 0;
        std::uint64_t treeCarryLevelAlignments = 0;
        std::uint64_t treeRescales = 0;
        std::uint64_t conjugationKeySwitches = 0;
        std::uint32_t expectedMaxLiveYRows = 0;
        std::uint64_t representationScaleFactor = 0;
        std::uint32_t packedInputLevel = 0;
        std::uint32_t transformMaterialLevel = 0;
        std::uint32_t transformKeyLevel = 0;
        std::uint32_t outputLevel = 0;
        std::uint32_t forwardPhysicalQPrimeDrops = 0;
        std::uint32_t expectedDftPlaintextVisits = 0;
        bool strictYOrderRequired = false;
        bool fullYCoverageRequired = false;
        bool primaryRingRSlotRowsRequired = false;
        bool slotToCoeffPerRowRequired = false;
        bool traceRepresentationScaleRestored = false;
        bool boundedRowPackBoundaryImplemented = false;
        bool fullReturnBoundaryImplemented = false;
        bool canonicalH40CiphertextValueExecutionPerformed = false;
        bool canonicalH40DecryptedValueNoiseAcceptanceRecorded = false;
    };

    struct DirectVectorOwnerKeyLineage {
        std::string ownerKskSeedCommitment;
        std::string primarySecretLineageCommitment;
        std::string sparseSecretLineageCommitment;
    };

    // OpenFHE-facing wrapper around GLScheme's L0/Q25 primary-selector
    // authorization shape.  Core schema v3 currently revokes every
    // free-support h40 receipt because it is not a certificate for the
    // implemented structured public-window secret.  The authorizer therefore
    // throws before this wrapper can be returned; no adapter path promotes
    // that proxy into production authorization or value execution.
    struct DirectVectorPrimaryAuthorization {
        NativeDirectVectorProductionAuthorizationEvidence native;
        DirectVectorAllYReturnPreflight allYReturn;
        DirectVectorOwnerKeyLineage ownerKeyLineage;
        bool metadataAuthorizationOnly = true;
        bool ownerKeyLineageBound = false;
        bool productionH40CiphertextValueExecutionPerformed = false;
        bool productionH40DecryptedValueNoiseAcceptanceRecorded = false;
    };

    // Metadata-only projection of the separately authorized production-sized
    // selector store.  `native` admits the exact canonical encoded payload
    // despite its total exceeding the generic p257 cap; it does not widen
    // that generic cap.  The copied plan and the two transcript roots keep a
    // persisted receipt tied to the same dual-certificate authorization.
    struct DirectVectorPrimarySelectorStorageAuthorization {
        NativeDirectVectorSelectorStorageAdmissionEvidence native;
        NativeDirectVectorPlan canonicalPlan;
        DirectVectorOwnerKeyLineage ownerKeyLineage;
        bool metadataAuthorizationOnly = true;
        bool canonicalPlanBound = false;
        bool bothSecurityRootsBound = false;
        bool ownerKeyLineageBound = false;
        bool selectorGenerationEnabled = false;
        bool selectorManifestOrPayloadGenerated = false;
        bool selectorMaterialReady = false;
        bool valueExecution = false;
    };

    // Allocation-free expected shape for one random-access selector record.
    // This proves only that the authorized core generator is available for
    // indices [0,640); it does not call owner keygen, retain a generation
    // seed, emit a record, or promote storage into evaluator-ready material.
    struct DirectVectorSelectorRecordPreflight {
        std::string schema;
        DirectVectorOwnerKeyLineage ownerKeyLineage;
        std::uint64_t totalRecordCount = 0;
        std::uint32_t selectorLevel = 0;
        std::uint32_t activeQPrimes = 0;
        std::uint64_t encodedRecordBytes = 0;
        std::uint64_t expectedReturnedRecordAndEncodingBytes = 0;
        std::uint64_t authorizedStreamingPeakBytes = 0;
        bool productionAuthorizationBound = false;
        bool storageAdmissionBound = false;
        bool ownerKeyLineageBound = false;
        bool deterministicRandomAccessGeneratorAvailable = false;
        bool recordGenerated = false;
        bool manifestOrPayloadGenerated = false;
        bool selectorMaterialReady = false;
        bool valueExecution = false;
    };

    // Receipt for the already-staged target-geometry h=2/stride-2 value rung.
    // Owner observations are caller-supplied and threshold-checked; the
    // adapter only binds them to the exact native counter/level evidence.  It
    // deliberately cannot be converted into h40 security authorization.
    struct DirectVectorH2Stride2SmokeReceipt {
        NativeDirectVectorEvidence native;
        std::uint64_t ownerCheckedSlots = 0;
        double worstOwnerSlotError = 0.0;
        double runtimeSeconds = 0.0;
        std::uint64_t peakRssBytes = 0;
        std::uint32_t compactSelectorMaxLive = 0;
        std::uint32_t evaluationKeyMaxLive = 0;
        bool targetGl128GeometryAndStrideBound = false;
        bool ownerValueObservationBound = false;
        bool explicitlyInsecure = true;
        bool adapterExecutedSmoke = false;
        bool productionH40AuthorizationAdmitted = false;
        bool productionH40ValueExecutionClaimed = false;
        bool productionH40ValueNoiseAcceptanceClaimed = false;
    };

    // Fixed-capacity binding text keeps the refresh preflight itself free of
    // heap-owning strings while still carrying the exact canonical name and
    // native parameter fingerprint.  View() remains valid for the lifetime
    // of the containing preflight value.
    struct FixedProfileBindingText {
        std::array<char, 96> bytes{};
        std::uint32_t size = 0;

        std::string_view View() const noexcept {
            return size <= bytes.size()
                       ? std::string_view(bytes.data(), size)
                       : std::string_view{};
        }
    };

    // Fixed-layout projection of the native all-Y production preflight.  The
    // native object owns schema/authorization strings; those bindings are
    // carried separately below so authorization remains trivially copyable.
    struct NativeRefreshAllYProductionReceipt {
        NativeRefreshTracePreflight pack;
        NativeRefreshEndpointPreflight endpoint;
        std::uint32_t schemaVersion = 0;
        std::uint32_t y_rows = 0;
        std::uint32_t branches_per_y_row = 0;
        std::uint32_t pair_major_row_tile_width = 0;
        std::uint32_t pair_major_row_tiles_per_centered_refresh = 0;
        std::uint64_t logical_all_y_branch_items = 0;
        std::uint64_t scalar_equivalent_branch_invocations = 0;
        std::uint64_t scalar_equivalent_exponent_ladder_nodes = 0;
        std::uint64_t scalar_equivalent_gadget_key_applications = 0;
        std::uint64_t pair_major_branch_tiles_per_centered_refresh = 0;
        std::uint64_t total_pair_major_branch_tile_invocations = 0;
        std::uint32_t streamed_unsigned_candidate_count = 0;
        std::uint32_t streamed_signed_pair_count = 0;
        std::uint32_t streamed_signed_pairs_per_window = 0;
        std::uint64_t streamed_exponent_leaf_batch_invocations = 0;
        std::uint64_t streamed_exponent_leaf_tables_batched = 0;
        std::uint64_t streamed_exponent_leaf_pair_visits = 0;
        std::uint64_t
            streamed_exponent_leaf_scalar_equivalent_pair_visits = 0;
        std::uint32_t streamed_exponent_leaf_max_batch_size = 0;
        std::uint32_t streamed_exponent_leaf_peak_accumulators = 0;
        std::uint32_t streamed_exponent_leaf_peak_scratch_polys = 0;
        bool exact_all_y_coverage = false;
        bool full_streamed_physical_schedule_pinned = false;
        bool context_ciphertext_or_key_allocation_required = true;
        bool material_schedule_metadata_admitted = false;
        bool ciphertext_value_execution_performed = false;
        bool value_noise_acceptance_recorded = false;
    };

    enum class OrdinaryRefreshAvailability : std::uint8_t {
        // This fixed census never owns or attests execution material.  The
        // separately typed ExecuteOrdinaryRefresh seam remains contingent on
        // caller-supplied material and a successful native endpoint call.
        preflight_only = 1,
    };

    struct RefreshTraceKeyEntry {
        KeyId id;
        // Logarithmic doubling applies each exact key once per centered
        // readout.  This is 32,768 for canonical GL-128-257-N32.
        std::uint64_t applications = 0;
    };

    // Exact native digit payload for one switch key of each ring at a numeric
    // key level.  This uses GLScheme's active-level digit census (not the
    // provisional full-chain dnum), so Q7/Q8 each correctly carry one digit.
    struct RefreshKeyLevelByteModel {
        std::uint32_t keyLevel = 0;
        std::uint64_t ringRPerKeyBytes = 0;
        std::uint64_t ringRpPerKeyBytes = 0;
        std::uint64_t ringRauxPerKeyBytes = 0;
    };

    static constexpr std::size_t kCanonicalRefreshTraceKeyCount = 15;
    static constexpr std::size_t kCanonicalRefreshEndpointKeyDebtCount = 5;
    static constexpr std::size_t kCanonicalRefreshKeyLevelModelCount = 2;

    // Fixed-size, key/ciphertext-free ordinary-refresh census.  traceKeys are
    // exactly row_rotation:{1,2,4,8,16,32,64} followed by
    // w_rotation:{1,2,4,8,16,32,64,128}.  They are the coefficient-projector
    // keys only, not a claim that production SHIP is executable.
    // endpointKeyDebts separately names primary_to_sparse,
    // sparse_to_primary, conjugation_to_sparse, the primary transform key,
    // and the auxiliary transform key required by a full endpoint.  endpoint
    // binds the canonical gamma=64, input-delta, DFT=2^46 strict arithmetic
    // ledger.  The explicit Q7+P14/h40 corridor fields are requirements for
    // separately supplied execution material, never readiness claims.
    struct OrdinaryRefreshPreflight {
        FixedProfileBindingText canonicalProfile;
        FixedProfileBindingText parameterFingerprint;
        glscheme::production::LayoutKind layout =
            glscheme::production::LayoutKind::gl128_257_n32_tensor;
        NativeRefreshTracePreflight native;
        NativeRefreshEndpointPreflight endpoint;
        std::array<RefreshTraceKeyEntry,
                   kCanonicalRefreshTraceKeyCount> traceKeys{};
        std::uint32_t traceKeyCount = 0;
        std::array<KeyId,
                   kCanonicalRefreshEndpointKeyDebtCount> endpointKeyDebts{};
        std::uint32_t endpointKeyDebtCount = 0;
        // Entries are level 18 (Q7) then level 17 (Q8).  The byte totals below
        // cover only the 15 listed trace rotations and five listed non-trace
        // debts; selector/gadget material is neither owned nor attested by the
        // preflight and is deliberately not implied by these planning numbers.
        std::array<RefreshKeyLevelByteModel,
                   kCanonicalRefreshKeyLevelModelCount> keyLevelModels{};
        std::uint32_t keyLevelModelCount = 0;
        std::uint64_t traceRotationKeyResidentBytes = 0;
        std::uint64_t listedNonTraceKeyDebtResidentBytes = 0;
        double refreshGamma = 1.0;
        double normalizationRelativeTolerance = 0.0;
        // Numeric levels count dropped Q primes.  Every trace and non-trace
        // endpoint KSK is generated on the refreshed level-18 Q7 basis; DFT
        // material is authored at level 17 and aligned only by exact drop.
        std::uint32_t traceKeyLevel = 0;
        std::uint32_t nonTraceKeyLevel = 0;
        std::uint32_t corridorQPrimeCount = 0;
        std::uint32_t corridorSpecialPrimeCount = 0;
        std::uint32_t requiredSparseHammingWeight = 0;
        OrdinaryRefreshAvailability availability =
            OrdinaryRefreshAvailability::preflight_only;
        bool canonicalProfileBound = false;
        bool reducedExposureCorridorRequired = false;
        bool securityAuthorizationRequired = false;
        bool sparseKeyRequired = false;
        // Legacy resident-bank requirements.  The OpenFHE execution seam does
        // not accept either material form; they remain false for its canonical
        // compact/streamed opening.
        bool encryptedSelectorBankRequired = false;
        bool encryptedGadgetBankRequired = false;
        bool dftBankRequired = false;
        bool productionExecutionExposed = false;
        // Append-only truth for the separately typed execution material view.
        bool compactSelectorBindingRequired = false;
        bool authenticatedLeasedKskRequired = false;
        bool streamedGadgetProviderRequired = false;
        bool streamedDftProviderRequired = false;
    };

    // Fixed, copyable result of validating one ACTUAL support commitment and
    // authenticated SecurityReport against GLScheme's canonical GL-128
    // endpoint authorization gate.  `productionAuthorizationAdmitted` means
    // that metadata passed the Q7+P14/h40 policy; it cannot be promoted or
    // copied into execution admission.  ExecuteOrdinaryRefresh instead
    // recomputes authorization from its actual material/report and calls the
    // native endpoint, so this policy-only result always remains false.
    struct OrdinaryRefreshAuthorization {
        NativeRefreshAllYProductionReceipt nativeAllYProductionPreflight;
        FixedProfileBindingText profileBindingFingerprint;
        FixedProfileBindingText supportCommitment;
        FixedProfileBindingText bootstrapProfileFingerprint;
        FixedProfileBindingText estimatorTranscriptSha256;
        std::uint32_t sparseHammingWeight = 0;
        std::uint32_t foldKeyLevel = 0;
        std::uint32_t transformMaterialLevel = 0;
        std::uint32_t exposedQPrimeCount = 0;
        std::uint32_t exposedSpecialPrimeCount = 0;
        bool reducedExposureCorridor = false;
        bool profileFingerprintBound = false;
        bool supportCommitmentBound = false;
        bool securityPolicyValidated = false;
        bool productionAuthorizationAdmitted = false;
        bool productionExecutionExposed = false;
    };

    // Non-owning view of one complete native ordinary-refresh opening.  Every
    // pointer is mandatory and must outlive ExecuteOrdinaryRefresh.  KSKs and
    // DFT plaintexts are supplied only through authenticated bounded
    // providers plus independently pinned external bindings.  DFT plaintexts
    // additionally require the owner-authored immutable policy.  This seam
    // accepts no resident DFT bank.  The view carries no secret, admission bit,
    // shared ownership, or copied OrdinaryRefreshAuthorization.  The adapter
    // pins h=40, the reduced Q7+P14 corridor, fold/key level 18, transform level
    // 17, gamma=64, DFT scale 2^46, and tolerance 1e-12 internally.
    struct OrdinaryRefreshExecutionMaterialView {
        const NativeKeyProvider* keyProvider = nullptr;
        const NativeLeasedKeyBinding* keyBinding = nullptr;
        const NativeRefreshDftPlaintextProvider* dftProvider = nullptr;
        const NativeRefreshDftPlaintextBinding* dftBinding = nullptr;
        const NativeRefreshGadgetProvider* gadgetProvider = nullptr;
        const NativeRefreshGadgetBinding* gadgetBinding = nullptr;
        const NativeRefreshCompactSelectorManifest* compactSelector = nullptr;
        const NativeRefreshCompactSelectorBinding* compactSelectorBinding =
            nullptr;
        const SecurityReport* securityReport = nullptr;
    };

    // Returned only after the native endpoint completes and its canonical
    // streamed-material evidence is checked.  A thrown call returns no result;
    // the flag therefore cannot become true on validation or execution failure.
    struct OrdinaryRefreshExecutionResult {
        NativeRefreshEndpointResult nativeResult;
        NativeRefreshEndpointEvidence nativeEvidence;
        NativeRefreshAllYProductionReceipt nativeAllYProductionPreflight;
        bool productionExecutionExposed = false;
    };

    class OrdinaryRefreshPackFacade;

    // Move-only rolling state for the native ordinary-refresh coefficient
    // packer.  This type is intentionally not convertible to either a packed
    // tensor or a refreshed-xy endpoint result.  A session becomes a packed
    // tensor only through OrdinaryRefreshPackFacade::Finalize after the native
    // core validates a complete, gap-free coordinate cover.
    class OrdinaryRefreshPackSession final {
    public:
        OrdinaryRefreshPackSession(const OrdinaryRefreshPackSession&) = delete;
        OrdinaryRefreshPackSession& operator=(
            const OrdinaryRefreshPackSession&) = delete;
        OrdinaryRefreshPackSession(OrdinaryRefreshPackSession&&) noexcept =
            default;
        OrdinaryRefreshPackSession& operator=(
            OrdinaryRefreshPackSession&&) noexcept = default;
        ~OrdinaryRefreshPackSession() = default;

        std::uint64_t NextCoordinate() const noexcept;
        std::uint64_t TotalCoordinates() const noexcept;
        bool CoordinateCoverComplete() const noexcept;

    private:
        friend class OrdinaryRefreshPackFacade;
        explicit OrdinaryRefreshPackSession(
            NativeRefreshPackAccumulator accumulator);

        NativeRefreshPackAccumulator m_accumulator;
    };

    // The pack finalizer returns only the native full coefficient tensor and
    // its measured pack evidence.  It deliberately has no endpoint-complete,
    // production-exposed, ciphertext-value, or value/noise acceptance flag:
    // CtS/normalization and StC/output validation remain the responsibility of
    // the unchanged ExecuteOrdinaryRefresh endpoint, and owner decryption is a
    // separate acceptance lane.
    struct OrdinaryRefreshPackFinalizedResult {
        NativeRefreshPackResult nativeResult;
        NativeRefreshPackEvidence nativeEvidence;
    };

    // Narrow OpenFHE-facing facade over GLScheme's resumable native packer.
    // Begin executes and merges the first nonempty prefix. Advance consumes
    // the next contiguous coordinate count. SerializeCheckpoint and Resume
    // use the bounded core codec and its externally authenticated receipt.
    // Finalize consumes a complete session and cannot expose a refreshed-xy
    // result. The referenced context and every provider/config pointer must
    // outlive each synchronous call. The explicit context constructor keeps
    // small staged/toy conformance possible; canonical callers obtain the
    // facade from GLRProductionAdapter::ResumableOrdinaryRefreshPack().
    class OrdinaryRefreshPackFacade final {
    public:
        explicit OrdinaryRefreshPackFacade(const Context& context) noexcept;

        OrdinaryRefreshPackSession Begin(
            const Ciphertext& sparseCoefficientInput,
            const NativeRefreshPackParameters& parameters,
            const NativeRefreshPackConfig& config,
            std::uint64_t firstCoordinateCount) const;

        void Advance(
            OrdinaryRefreshPackSession& session,
            const Ciphertext& sparseCoefficientInput,
            const NativeRefreshPackParameters& parameters,
            const NativeRefreshPackConfig& config,
            std::uint64_t coordinateCount) const;

        NativeRefreshPackCheckpointReceipt SerializeCheckpoint(
            const OrdinaryRefreshPackSession& session,
            const NativeRefreshPackCheckpointSink& sink) const;

        OrdinaryRefreshPackSession Resume(
            const NativeRefreshPackCheckpointReceipt& authenticatedReceipt,
            const NativeRefreshPackCheckpointSource& source) const;

        OrdinaryRefreshPackFinalizedResult Finalize(
            OrdinaryRefreshPackSession&& session,
            const Ciphertext& sparseCoefficientInput,
            const NativeRefreshPackParameters& parameters,
            const NativeRefreshPackConfig& config) const;

    private:
        const Context* m_context = nullptr;
    };

    // Ordinary GL evaluation-key request.  Rotation amounts name the exact
    // native Galois keys to materialize; there is no implicit all-rotations
    // closure.  keyLevel counts dropped Q primes, just like GlrCiphertext.
    // A higher key level reduces resident bytes but can only evaluate
    // ciphertexts at that numeric level or later/deeper in the chain.
    struct EvaluationKeyRequest {
        std::vector<std::int32_t> rowRotations;
        std::vector<std::int32_t> matrixRotations;
        bool transpose = false;
        bool conjugation = false;
        bool hermitianTranspose = false;
        bool ciphertextMatMul = false;
        bool ciphertextHadamard = false;
        std::uint32_t keyLevel = 0;
    };

    struct EvaluationKeyPlanEntry {
        KeyId id;
        KeyRing ring = KeyRing::R;
        std::uint64_t residentBytes = 0;
    };

    // A public, allocation-free preflight result.  residentBytes is the exact
    // native in-memory digit payload (both key components and i-split lanes),
    // not a disk-cache estimate.  The adapter has no key serialization seam.
    struct EvaluationKeyPlan {
        std::string canonicalProfile;
        std::string parameterFingerprint;
        std::uint32_t keyLevel = 0;
        std::vector<EvaluationKeyPlanEntry> entries;
        std::uint64_t residentBytes = 0;
    };

    // Secret-free evaluator material.  Construction is only through
    // MaterializeEvaluationKeys, which validates the exact production
    // fingerprint and an explicit caller byte budget before key generation.
    class EvaluationKeys final {
    public:
        EvaluationKeys(const EvaluationKeys&) = delete;
        EvaluationKeys& operator=(const EvaluationKeys&) = delete;
        EvaluationKeys(EvaluationKeys&&) noexcept = default;
        EvaluationKeys& operator=(EvaluationKeys&&) noexcept = default;
        ~EvaluationKeys() = default;

        const EvaluationKeyPlan& GetPlan() const noexcept;
        const KeyManifest& GetManifest() const noexcept;
        const NativeKeyProvider& GetNativeProvider() const;
        bool HasKey(const KeyId& id) const noexcept;
        std::uint64_t ResidentBytes() const noexcept;

    private:
        friend class GLRProductionAdapter;
        EvaluationKeys(EvaluationKeyPlan plan, KeyManifest manifest,
                       std::unique_ptr<NativeKeyProvider> provider);

        EvaluationKeyPlan m_plan;
        KeyManifest m_manifest;
        std::unique_ptr<NativeKeyProvider> m_provider;
    };

    // Storage-bounded evaluator material produced by the canonical seeded-a
    // core path.  The object retains only the authenticated manifest/binding
    // receipt and a provider which expands one externally stored compact key
    // inside each synchronous lease.  It never owns a full key set.
    class CompactEvaluationKeys final {
    public:
        CompactEvaluationKeys(const CompactEvaluationKeys&) = delete;
        CompactEvaluationKeys& operator=(const CompactEvaluationKeys&) =
            delete;
        CompactEvaluationKeys(CompactEvaluationKeys&&) noexcept = default;
        CompactEvaluationKeys& operator=(CompactEvaluationKeys&&) noexcept =
            default;
        ~CompactEvaluationKeys() = default;

        const NativeCompactKskSetGenerationResult& GetGenerationResult()
            const noexcept;
        const NativeKeyProvider& GetNativeProvider() const;
        bool HasKey(const KeyId& id) const noexcept;

    private:
        friend class GLRProductionAdapter;
        CompactEvaluationKeys(
            NativeCompactKskSetGenerationResult generation,
            std::unique_ptr<NativeKeyProvider> provider);

        NativeCompactKskSetGenerationResult m_generation;
        std::unique_ptr<NativeKeyProvider> m_provider;
    };

    // Direct-bootstrap counterpart which cannot lose the owner-secret lineage
    // receipt while the compact provider remains live.
    class CompactDirectBootstrapKeys final {
    public:
        CompactDirectBootstrapKeys(const CompactDirectBootstrapKeys&) = delete;
        CompactDirectBootstrapKeys& operator=(
            const CompactDirectBootstrapKeys&) = delete;
        CompactDirectBootstrapKeys(CompactDirectBootstrapKeys&&) noexcept =
            default;
        CompactDirectBootstrapKeys& operator=(
            CompactDirectBootstrapKeys&&) noexcept = default;
        ~CompactDirectBootstrapKeys() = default;

        const NativeGL128DirectBootstrapKeyGenerationResult&
        GetGenerationResult() const noexcept;
        const NativeGL128DirectBootstrapKeyLineageBinding& GetLineage()
            const noexcept;
        const NativeKeyProvider& GetNativeProvider() const;
        bool HasKey(const KeyId& id) const noexcept;

    private:
        friend class GLRProductionAdapter;
        CompactDirectBootstrapKeys(
            NativeGL128DirectBootstrapKeyGenerationResult generation,
            std::unique_ptr<NativeKeyProvider> provider);

        NativeGL128DirectBootstrapKeyGenerationResult m_generation;
        std::unique_ptr<NativeKeyProvider> m_provider;
    };

    // Returns and validates the one profile this provider accepts:
    // GL-128-257-N32, physical layout 256x128x128.
    static Profile CanonicalProfile();

    // Builds native GLScheme transform tables for the canonical profile.
    static GLRProductionAdapter Create();

    GLRProductionAdapter(const GLRProductionAdapter&) = delete;
    GLRProductionAdapter& operator=(const GLRProductionAdapter&) = delete;
    GLRProductionAdapter(GLRProductionAdapter&&) noexcept = default;
    GLRProductionAdapter& operator=(GLRProductionAdapter&&) noexcept = default;
    ~GLRProductionAdapter() = default;

    const Context& GetContext() const noexcept;

    // Core-owned exact-profile receipt and complete storage-aware plans.  The
    // adapter does not reconstruct IDs, levels, or byte counts independently.
    NativeGL128ProfileReceipt GetCanonicalProfileReceipt() const;
    NativeGL128SchemeKeyPlan PlanCanonicalSchemeKeys(
        const NativeGL128SchemeWorkload& workload = {}) const;
    NativeGL128DirectBootstrapKeyPlan
    PlanCanonicalDirectBootstrapKeys() const;
    NativeValidatedDftPlaintextProviderSession OpenDftPlaintextSession(
        const NativeRefreshDftPlaintextProvider& provider,
        const NativeRefreshDftPlaintextBinding& binding) const;

    // Direct-coefficient bootstrap needs only the two forward StC records.
    // This seam emits and opens schema-v2 material without changing the
    // legacy four-record CtS/StC session API above.
    NativeDftPlaintextGenerationConfig
    GetCanonicalDirectDftGenerationConfig() const;
    NativeDftPlaintextGenerationResult GenerateForwardDftPlaintextEntries(
        double forwardScale, std::uint32_t forwardLevel,
        const NativeDftPlaintextEntrySink& sink) const;
    NativeValidatedDftPlaintextProviderSession
    OpenForwardDftPlaintextSession(
        const NativeRefreshDftPlaintextProvider& provider,
        const NativeRefreshDftPlaintextBinding& binding) const;
    NativeDftPlaintextByteCensus ModelForwardDftPlaintextStreamingBytes(
        std::uint32_t forwardLevel) const;

    // Owner-side bounded key generation and evaluator-side compact opening.
    // A zero seed requests operating-system entropy.  Persistence remains
    // caller-owned through the core sink/loader callbacks.
    NativeCompactKskSetGenerationResult GenerateCompactSchemeKeys(
        const SecretKey& primaryKey,
        const NativeGL128SchemeKeyPlan& plan,
        std::string ownerKeySeedCommitment,
        const NativeCompactKskSetSink& sink,
        std::uint64_t seed = 0) const;
    NativeGL128DirectBootstrapKeyGenerationResult
    GenerateCompactDirectBootstrapKeys(
        const SecretKey& primaryKey,
        const glscheme::rns::GlrSparseSecretKey& sparseKey,
        const NativeGL128DirectBootstrapKeyPlan& plan,
        std::string ownerKeySeedCommitment,
        const NativeCompactKskSetSink& sink,
        std::uint64_t seed = 0) const;
    CompactEvaluationKeys OpenCompactSchemeKeys(
        const NativeGL128SchemeKeyPlan& plan,
        NativeCompactKskSetGenerationResult generation,
        NativeCompactKskBlobLeaseCallbacks callbacks) const;
    CompactDirectBootstrapKeys OpenCompactDirectBootstrapKeys(
        const NativeGL128DirectBootstrapKeyPlan& plan,
        NativeGL128DirectBootstrapKeyGenerationResult generation,
        NativeCompactKskBlobLeaseCallbacks callbacks) const;

    // Canonical end-to-end owner/evaluator direct-bootstrap facade.  This is
    // the preferred production surface over manually composing the lower
    // selector methods below.  Direct preparation uses the public resident
    // Slot-to-Coeff representation conversion; the transform config is used
    // by forward StC and validated before the all-Y return transient.
    NativeGL128DirectBootstrapAuthorizationBundle AuthorizeDirectBootstrap(
        const SecretKey& primaryKey,
        const glscheme::rns::GlrSparseSecretKey& sparseKey,
        std::string ownerKeySeedCommitment,
        const SecurityReport& sparseH40SecurityReport,
        const NativeDirectVectorDensePrimarySecurityEvidence&
            densePrimarySecurity) const;
    NativeGL128PersistedSelectorBankResult GeneratePersistedDirectSelectorBank(
        const SecretKey& primaryKey,
        const glscheme::rns::GlrSparseSecretKey& sparseKey,
        const NativeGL128DirectBootstrapAuthorizationBundle& authorization,
        const NativeDirectVectorProductionSelectorGenerationSeed&
            generationSeed,
        const NativeGL128SelectorPersistenceSink& sink,
        const NativeDirectVectorProductionSelectorManifestCheckpoint*
            resumeCheckpoint = nullptr) const;
    NativeDirectVectorProductionSelectorProviderOpeningResult
    OpenPersistedDirectSelectorBank(
        const NativeGL128DirectBootstrapAuthorizationBundle& authorization,
        const NativeGL128PersistedSelectorBankResult& persisted,
        const CompactDirectBootstrapKeys& evaluationKeys,
        NativeDirectVectorProductionSelectorBlobLeaseCallbacks callbacks)
        const;
    NativeGL128DirectInputPreparationResult PrepareDirectShipInput(
        const Ciphertext& canonicalCiphertext,
        const NativeGL128DirectBootstrapAuthorizationBundle& authorization,
        const CompactDirectBootstrapKeys& evaluationKeys,
        double normalizationRelativeTolerance =
            glscheme::rns::kGl128BootstrapNormalizationRelativeTolerance) const;
    // Compatibility overload for deployments that open the directional DFT
    // bank before preparation.  The session is authenticated but inverse
    // records are not visited by the direct-coefficient preparation stage.
    NativeGL128DirectInputPreparationResult PrepareDirectShipInput(
        const Ciphertext& canonicalCiphertext,
        const NativeGL128DirectBootstrapAuthorizationBundle& authorization,
        const NativeValidatedDftPlaintextProviderSession& dftSession,
        const CompactDirectBootstrapKeys& evaluationKeys,
        const NativeCtsStcConfig& config = {},
        double normalizationRelativeTolerance =
            glscheme::rns::kGl128BootstrapNormalizationRelativeTolerance) const;
    NativeGL128BootstrapResult BootstrapDirect(
        const Ciphertext& canonicalCiphertext,
        const NativeGL128DirectBootstrapAuthorizationBundle& authorization,
        const NativeDirectVectorProductionSelectorProviderOpeningResult&
            selectorOpening,
        const NativeValidatedDftPlaintextProviderSession& dftSession,
        const CompactDirectBootstrapKeys& evaluationKeys,
        const NativeCtsStcConfig& config = {},
        double normalizationRelativeTolerance =
            glscheme::rns::kGl128BootstrapNormalizationRelativeTolerance) const;

    // Explicitly non-production code-completeness lane.  Every value and
    // receipt stays in the research-only type family: there is no adapter
    // conversion to the production authorization bundle or selector receipt.
    NativeGL128H40FreeSupportProxyResearchReceipt
    RecordH40FreeSupportProxyForResearch(
        const SecurityReport& researchProxyReport) const;
    NativeGL128ResearchOnlySession BeginResearchOnlyBootstrapSession(
        const SecretKey& primaryKey, const SparseSecretKey& sparseKey,
        std::string ownerKeySeedCommitment,
        const NativeGL128H40FreeSupportProxyResearchReceipt& proxyEvidence)
        const;
    NativeGL128ResearchPersistedSelectorBank
    GeneratePersistedResearchSelectorBank(
        const SecretKey& primaryKey, const SparseSecretKey& sparseKey,
        const NativeGL128ResearchOnlySession& session,
        const NativeGL128ResearchSelectorGenerationSeed& generationSeed,
        const NativeGL128ResearchSelectorPersistenceSink& sink) const;
    NativeGL128ResearchSelectorProviderOpeningResult
    OpenPersistedResearchSelectorProvider(
        const NativeGL128ResearchOnlySession& session,
        const NativeGL128ResearchPersistedSelectorBank& persisted,
        const CompactDirectBootstrapKeys& evaluationKeys,
        NativeGL128ResearchSelectorBlobLeaseCallbacks callbacks) const;
    NativeGL128ResearchInputPreparationResult PrepareResearchDirectShipInput(
        const Ciphertext& canonicalCiphertext,
        const NativeGL128ResearchOnlySession& session,
        const CompactDirectBootstrapKeys& evaluationKeys,
        double normalizationRelativeTolerance =
            glscheme::rns::kGl128BootstrapNormalizationRelativeTolerance) const;
    NativeGL128ResearchBootstrapResult BootstrapResearchDirect(
        const Ciphertext& canonicalCiphertext,
        const NativeGL128ResearchOnlySession& session,
        const NativeGL128ResearchSelectorProviderOpeningResult&
            selectorOpening,
        const NativeValidatedDftPlaintextProviderSession& dftSession,
        const CompactDirectBootstrapKeys& evaluationKeys,
        const NativeCtsStcConfig& config = {},
        double normalizationRelativeTolerance =
            glscheme::rns::kGl128BootstrapNormalizationRelativeTolerance) const;

    // Exact H64 research aliases and thin native composition.  The one-branch
    // call returns a primary-domain L14 root.  The all-Y call binds an
    // immutable 256-source schedule, resolves one concrete public-root
    // provider at a time, streams 128 recombined rows into authenticated
    // forward StC, and returns a distinct research-only primary L18 result.
    // No H64 type converts to production authorization or BootstrapDirect.
    NativeGL128H64ResearchProfileReceipt GetH64ResearchProfile() const;
    NativeGL128H64HiddenSelectorPlan PlanH64HiddenSelector() const;
    NativeGL128H64WActionPlan PlanH64WActionResearch() const;
    NativeGL128H64WActionResearchCapabilities
    GetH64WActionResearchCapabilities() const;
    NativeGL128H64P257OneBitCapabilities
    GetH64P257OneBitCapabilities() const;
    NativeGL128H64P257OneBitMaterial GenerateH64P257OneBitMaterial(
        const SparseSecretKey& sparseKey,
        const NativeGL128H64HiddenSelectorOwnerSeed& ownerSeed,
        std::uint64_t seed) const;
    NativeGL128H64P257OneBitResult EvaluateH64P257OneBitCpu(
        const NativeGL128H64P257OneBitMaterial& material,
        std::span<const NativeGL128H64P257OneBitRequest> requests) const;
    NativeGL128H64P257OneBitGpuResult EvaluateH64P257OneBitGpu(
        const NativeGL128H64P257OneBitMaterial& material,
        const NativeGL128H64P257OneBitRequest& request) const;
    NativeGL128H64P257PrefixSpliceCapabilities
    GetH64P257PrefixSpliceCapabilities() const;
    NativeGL128H64P257PrefixSpliceMaterial GenerateH64P257PrefixSpliceMaterial(
        const SparseSecretKey& sparseKey,
        const NativeGL128H64HiddenSelectorOwnerSeed& ownerSeed,
        std::uint64_t seed) const;
    NativeGL128H64P257PrefixSpliceResult EvaluateH64P257PrefixSpliceCpu(
        const NativeGL128H64P257PrefixSpliceMaterial& material,
        std::span<const NativeGL128H64P257OneBitRequest> requests) const;
    NativeGL128H64P257RightMuxRotCapabilities
    GetH64P257RightMuxRotCapabilities() const;
    NativeGL128H64P257RightMuxRotMaterial GenerateH64P257RightMuxRotMaterial(
        const SparseSecretKey& sparseKey,
        const NativeGL128H64HiddenSelectorOwnerSeed& ownerSeed,
        std::uint64_t seed) const;
    NativeGL128H64P257RightMuxRotResult EvaluateH64P257RightMuxRotCpu(
        const NativeGL128H64P257RightMuxRotMaterial& material,
        std::span<const NativeGL128H64P257OneBitRequest> requests) const;
    NativeGL128H64SelectedLeafFoldCapabilities
    GetH64SelectedLeafFoldCapabilities() const;
    NativeGL128H64SelectedLeafFoldResult EvaluateH64SelectedLeafFoldCpu(
        const NativeGL128H64SelectedLeafFoldBinding& inputBinding,
        const NativeGL128H64SelectedLeafProvider& selectedLeaves,
        const NativeKeyProvider& evaluationKeys,
        const NativeGL128H64SparseFoldKskBinding& sparseFoldKeys,
        const NativeGL128H64SelectedLeafFoldCheckpointVisitor& checkpoint =
            {}) const;
    NativeGL128H64SelectedLeafH4GpuCapabilities
    GetH64SelectedLeafH4GpuCapabilities() const;
    NativeGL128H64SelectedLeafGpuFrontierResult
    EvaluateH64SelectedLeafH4GpuFrontier(
        const NativeGL128H64SelectedLeafFoldBinding& inputBinding,
        const NativeGL128H64SelectedLeafProvider& selectedLeaves,
        const NativeSwitchKey& sparseRelinearizationKey,
        const NativeKskRecord& expectedRelinearizationRecord) const;
    NativeGL128H64SelectedLeaf64GpuCapabilities
    GetH64SelectedLeaf64GpuCapabilities() const;
    NativeGL128H64SelectedLeafGpuFrontierResult
    EvaluateH64SelectedLeaf64GpuTree(
        const NativeGL128H64SelectedLeafFoldBinding& inputBinding,
        const NativeGL128H64SelectedLeafProvider& selectedLeaves,
        const NativeSwitchKey& sparseRelinearizationKey,
        const NativeKskRecord& expectedRelinearizationRecord) const;
    NativeGL128H64SelectedLeaf64GpuReturnCapabilities
    GetH64SelectedLeaf64GpuReturnCapabilities() const;
    NativeGL128H64SelectedLeafGpuReturnResult
    EvaluateH64SelectedLeaf64GpuReturn(
        const NativeGL128H64SelectedLeafFoldBinding& inputBinding,
        Ciphertext sparseRoot,
        const NativeSwitchKey& conjugationToSparseKey,
        const NativeSwitchKey& sparseToPrimaryKey,
        const NativeGL128H64SparseFoldKskBinding& sparseFoldKeys) const;
    NativeGL128H64StructuredSecurityAudit
    AuditH64StructuredSecurity() const;
    NativeGL128H64StructuredSecurityCapabilities
    GetH64StructuredSecurityCapabilities() const;
    NativeGL128H64OwnerRootProductResult
    EvaluateH64OwnerRootProductOracle(
        std::uint32_t yRow,
        std::span<const glscheme::rns::GlrShipDirectGaussian> publicB,
        std::span<const glscheme::rns::GlrShipDirectGaussian> publicA,
        const SparseSecretKey& sparseKey) const;
    NativeGL128H64HiddenSelectorBinding BindH64HiddenSelectorManifest(
        const NativeGL128H64HiddenSelectorManifest& manifest) const;
    NativeGL128H64HiddenSelectorGenerationResult
    GenerateH64HiddenSelectorMaterial(
        const SparseSecretKey& sparseKey,
        const NativeGL128H64HiddenSelectorOwnerSeed& ownerSeed,
        const NativeGL128H64HiddenSelectorRecordSink& sink,
        const NativeGL128H64HiddenSelectorCheckpoint* resumeCheckpoint =
            nullptr,
        std::size_t maxRecordsThisCall = 0) const;
    NativeGL128H64HiddenSelectorOwnerCursorCapabilities
    GetH64HiddenSelectorOwnerCursorCapabilities() const;
    NativeGL128H64HiddenSelectorOwnerCursor
    CreateH64HiddenSelectorOwnerCursor(
        const SparseSecretKey& sparseKey,
        const NativeGL128H64HiddenSelectorOwnerSeed& ownerSeed) const;
    NativeGL128H64HiddenSelectorOwnerCursorEmission
    EmitNextH64HiddenSelectorOwnerCursorChunk(
        NativeGL128H64HiddenSelectorOwnerCursor& cursor,
        const SparseSecretKey& sparseKey,
        const NativeGL128H64HiddenSelectorOwnerSeed& ownerSeed,
        const NativeGL128H64HiddenSelectorOwnerCursorSink& sink,
        std::size_t recordsToEmit =
            glscheme::rns::kGl128H64ControlsPerSupport) const;
    std::unique_ptr<NativeGL128H64HiddenSelectorProvider>
    OpenH64HiddenSelectorProvider(
        NativeGL128H64HiddenSelectorManifest manifest,
        NativeGL128H64HiddenSelectorBinding binding,
        NativeGL128H64HiddenSelectorLeaseCallbacks callbacks) const;
    NativeGL128ValidatedH64HiddenSelectorSession
    OpenH64HiddenSelectorSession(
        const NativeGL128H64HiddenSelectorProvider& provider,
        const NativeGL128H64HiddenSelectorBinding& binding) const;
    NativeGL128H64PublicRootProviderBinding BindH64PublicRootManifest(
        const NativeGL128H64PublicRootProviderManifest& manifest) const;
    NativeGL128H64PublicRootSource ExtractH64PublicRootSource(
        const Ciphertext& normalizedSparseQ0, std::uint32_t yRow,
        std::uint32_t branch) const;
    NativeGL128H64PublicRootProviderManifest BuildH64PublicRootManifest(
        const NativeGL128H64PublicRootSource& source) const;
    std::unique_ptr<NativeGL128H64PublicRootCandidateProvider>
    OpenH64PublicRootProvider(
        NativeGL128H64PublicRootProviderManifest manifest,
        NativeGL128H64PublicRootProviderBinding binding,
        NativeGL128H64PublicRootProviderCallbacks callbacks) const;
    NativeGL128H64ConcretePublicRootProviderOpening
    OpenConcreteH64PublicRootProvider(
        NativeGL128H64PublicRootSource source) const;
    NativeGL128H64SparseFoldKskBinding BindH64SparseFoldKeys(
        const NativeKeyProvider& evaluationKeys,
        const std::string& expectedPrimarySecretLineageCommitment,
        const std::string& expectedSparseSecretLineageCommitment) const;
    NativeGL128H64SparseFoldResult EvaluateH64OneBranchSparseFold(
        const NativeGL128ValidatedH64HiddenSelectorSession& hiddenSelector,
        const NativeGL128H64PublicRootCandidateProvider& publicRoots,
        const NativeGL128H64PublicRootProviderBinding& publicRootBinding,
        const NativeKeyProvider& evaluationKeys,
        const NativeGL128H64SparseFoldKskBinding& sparseFoldKeys) const;
    NativeGL128H64AllYPublicSourceSchedule PlanH64AllYPublicSources(
        const Ciphertext& normalizedSparseQ0) const;
    std::string GetH64AllYPublicSourceScheduleCommitment(
        const NativeGL128H64AllYPublicSourceSchedule& schedule) const;
    NativeGL128H64AllYPublicRootProviderResolver
    MakeH64AllYPublicRootProviderResolver() const;
    NativeGL128H64ResearchAllYStcResult EvaluateH64AllYStCResearch(
        const Ciphertext& normalizedSparseQ0,
        const NativeGL128H64AllYPublicSourceSchedule& sourceSchedule,
        const NativeGL128ValidatedH64HiddenSelectorSession& hiddenSelector,
        const NativeGL128H64AllYPublicRootProviderResolver&
            rootProviderResolver,
        const NativeKeyProvider& evaluationKeys,
        const NativeGL128H64SparseFoldKskBinding& sparseFoldKeys,
        const NativeValidatedDftPlaintextProviderSession& dftSession,
        const NativeCtsStcConfig& config = {}) const;

    // Owner-side exhaustive post-bootstrap acceptance.  This is kept out of
    // BootstrapDirect so an evaluator cannot self-author a correctness/noise
    // claim.  It decrypts only after the completed result is returned and
    // checks all 4,194,304 slots plus every coefficient across active Q.
    NativeGL128BootstrapAcceptanceReceipt AcceptBootstrapDirect(
        const SecretKey& primaryKey,
        const MatrixBatch& expected,
        const NativeGL128BootstrapResult& bootstrap,
        const NativeGL128BootstrapAcceptanceLimits& limits = {}) const;

    // Owner-only exhaustive acceptance for the explicitly research-only
    // bootstrap lane.  The distinct return type cannot become a production
    // acceptance receipt even when its measured value/noise limits pass.
    NativeGL128ResearchBootstrapAcceptanceReceipt
    AcceptResearchBootstrapDirect(
        const SecretKey& primaryKey, const MatrixBatch& expected,
        const NativeGL128ResearchOnlySession& session,
        const NativeGL128ResearchBootstrapResult& bootstrap,
        const NativeGL128BootstrapAcceptanceLimits& limits = {}) const;

    // Pure projection: validates and copies already-authored native evidence;
    // it never invokes the GPU endpoint or supplies production authorization.
    ResidentQ0GpuBootstrapEvidenceProjection
    ProjectResidentQ0GpuBootstrapEvidence(
        const NativeDirectGpuBootstrapRequest& request,
        const NativeDirectGpuBootstrapEvidence& evidence) const;

    // Streaming NATIVE32 artifact codec.  Residues retain the uint64_t
    // arithmetic ABI in memory but persist as exact uint32_t words, halving
    // ciphertext payload bytes.  The trailing SHA-256 is corruption
    // detection; deployment authenticity remains caller-owned.
    NativeGL128CiphertextArtifactReceipt WriteCiphertextArtifact(
        const Ciphertext& ciphertext,
        const NativeGL128CiphertextArtifactSink& sink) const;
    NativeGL128CiphertextArtifactReadResult ReadCiphertextArtifact(
        const NativeGL128CiphertextArtifactSource& source) const;

    OrdinaryRefreshPackFacade ResumableOrdinaryRefreshPack() const noexcept;

    // Canonical direct-vector planning and authorization boundaries.  The
    // support commitment and both security certificates are caller supplied;
    // the adapter authors the exact h40 windows/key domains/levels internally
    // and delegates authorization to GLScheme.  Neither call allocates
    // selector/key/ciphertext material or executes the h40 value path.
    DirectVectorAllYReturnPreflight
    PreflightDirectVectorPrimaryAllYReturn() const;
    void ValidateDirectVectorPrimaryAllYReturnPreflight(
        const DirectVectorAllYReturnPreflight& preflight) const;
    DirectVectorPrimaryAuthorization AuthorizeDirectVectorPrimaryCandidate(
        const std::string& supportCommitment,
        const SecurityReport& sparseH40SecurityReport,
        const NativeDirectVectorDensePrimarySecurityEvidence&
            densePrimarySecurity,
        const DirectVectorOwnerKeyLineage& ownerKeyLineage) const;
    void ValidateDirectVectorPrimaryAuthorization(
        const DirectVectorPrimaryAuthorization& authorization,
        const std::string& supportCommitment,
        const SecurityReport& sparseH40SecurityReport,
        const NativeDirectVectorDensePrimarySecurityEvidence&
            densePrimarySecurity,
        const DirectVectorOwnerKeyLineage& ownerKeyLineage) const;
    DirectVectorPrimarySelectorStorageAuthorization
    AuthorizeDirectVectorPrimarySelectorStorage(
        const DirectVectorPrimaryAuthorization& authorization) const;
    void ValidateDirectVectorPrimarySelectorStorageAuthorization(
        const DirectVectorPrimarySelectorStorageAuthorization& storage,
        const DirectVectorPrimaryAuthorization& authorization) const;
    DirectVectorSelectorRecordPreflight
    PreflightDirectVectorPrimarySelectorRecord(
        const DirectVectorPrimarySelectorStorageAuthorization& storage,
        const DirectVectorPrimaryAuthorization& authorization) const;
    void ValidateDirectVectorPrimarySelectorRecordPreflight(
        const DirectVectorSelectorRecordPreflight& preflight,
        const DirectVectorPrimarySelectorStorageAuthorization& storage,
        const DirectVectorPrimaryAuthorization& authorization) const;

    // Complete owner persistence and evaluator opening surface for the exact
    // 640-record L0/h40 bank.  These calls delegate canonical record hashing,
    // checkpoint authentication, compact expansion, and KSK-lineage joins to
    // GLScheme; OpenFHE does not reinterpret selector ciphertexts.
    std::unique_ptr<NativeDirectVectorProductionSelectorGenerator>
    CreateDirectVectorPrimarySelectorGenerator(
        const SecretKey& primaryKey,
        const glscheme::rns::GlrSparseSecretKey& sparseKey,
        const DirectVectorPrimaryAuthorization& authorization,
        const DirectVectorPrimarySelectorStorageAuthorization& storage,
        const NativeDirectVectorProductionSelectorGenerationSeed&
            generationSeed) const;
    NativeDirectVectorProductionSelectorManifestCheckpoint
    BeginDirectVectorPrimarySelectorManifest(
        const DirectVectorPrimaryAuthorization& authorization,
        const DirectVectorPrimarySelectorStorageAuthorization& storage) const;
    NativeDirectVectorProductionSelectorManifestCheckpoint
    AppendDirectVectorPrimarySelectorRecord(
        const DirectVectorPrimaryAuthorization& authorization,
        const DirectVectorPrimarySelectorStorageAuthorization& storage,
        const NativeDirectVectorProductionSelectorManifestCheckpoint&
            checkpoint,
        const NativeDirectVectorSelectorRecordGenerationResult& record) const;
    NativeDirectVectorProductionSelectorManifestFinalizationResult
    FinalizeDirectVectorPrimarySelectorManifests(
        const DirectVectorPrimaryAuthorization& authorization,
        const DirectVectorPrimarySelectorStorageAuthorization& storage,
        const NativeDirectVectorProductionSelectorManifestCheckpoint&
            checkpoint) const;
    NativeDirectVectorProductionSelectorProviderOpeningResult
    OpenPersistedDirectVectorPrimarySelectorProvider(
        const DirectVectorPrimaryAuthorization& authorization,
        const DirectVectorPrimarySelectorStorageAuthorization& storage,
        const NativeDirectVectorProductionSelectorManifestCheckpoint&
            checkpoint,
        NativeDirectVectorProductionSelectorManifestFinalizationResult
            finalized,
        const CompactDirectBootstrapKeys& evaluationKeys,
        const NativeDirectVectorProductionSelectorBlobPersistenceEvidence&
            persistence,
        NativeDirectVectorProductionSelectorBlobLeaseCallbacks callbacks)
        const;
    DirectVectorProductionRowResult ExecuteDirectVectorPrimaryRowProduction(
        const NativeDirectVectorPublicSlice& input,
        const DirectVectorPrimaryAuthorization& authorization,
        const NativeDirectVectorProductionSelectorProviderOpeningResult&
            selectorOpening,
        const CompactDirectBootstrapKeys& evaluationKeys) const;
    DirectVectorProductionAllYResult ExecuteDirectVectorAllYProduction(
        const Ciphertext& q0SparseCoefficients,
        const DirectVectorPrimaryAuthorization& authorization,
        const NativeDirectVectorProductionSelectorProviderOpeningResult&
            selectorOpening,
        const CompactDirectBootstrapKeys& evaluationKeys,
        const NativeValidatedDftPlaintextProviderSession& dftSession,
        const NativeCtsStcConfig& config = {}) const;

    // Binds a completed owner-observed h=2 staging run to the exact
    // GL-128-257-N32 L4 -> L8 direct-vector evidence.  This is intentionally
    // insecure and never admits the separate h40 production candidate.
    DirectVectorH2Stride2SmokeReceipt BindInsecureDirectVectorH2Stride2Smoke(
        const NativeDirectVectorEvidence& evidence,
        std::uint64_t ownerCheckedSlots, double worstOwnerSlotError,
        double runtimeSeconds, std::uint64_t peakRssBytes,
        std::uint32_t compactSelectorMaxLive,
        std::uint32_t evaluationKeyMaxLive) const;
    void ValidateInsecureDirectVectorH2Stride2SmokeReceipt(
        const DirectVectorH2Stride2SmokeReceipt& receipt) const;

    // Calls GLScheme's allocation-free prime-p refresh census and binds it to
    // this adapter's exact GL-128-257-N32 context.  No key, ciphertext,
    // selector/gadget bank, DFT bank, or sparse secret is allocated.  The
    // validator is suitable for a copied/persisted preflight and rejects any
    // profile, fingerprint, geometry, count, key-list, or availability
    // tampering before it could be interpreted as evaluator readiness.
    OrdinaryRefreshPreflight PreflightOrdinaryRefresh() const;
    void ValidateOrdinaryRefreshPreflight(
        const OrdinaryRefreshPreflight& preflight) const;

    // Calls glr_ship_refresh_only_endpoint_authorize_gl128 with the actual
    // commitment/report.  Fold/key level 18 and transform-material level 17
    // are pinned internally; no bare authorization boolean is accepted.
    OrdinaryRefreshAuthorization AuthorizeOrdinaryRefreshProduction(
        const std::string& supportCommitment,
        const SecurityReport& securityReport,
        std::uint32_t sparseHammingWeight = 40,
        bool reducedExposureCorridor = true) const;
    void ValidateOrdinaryRefreshAuthorization(
        const OrdinaryRefreshAuthorization& authorization,
        const std::string& supportCommitment,
        const SecurityReport& securityReport,
        std::uint32_t sparseHammingWeight = 40,
        bool reducedExposureCorridor = true) const;

    // Allocation-free validation of the native endpoint's canonical stage
    // ledger and full all-Y pack census.  Material-specific provider roots are
    // checked separately by ExecuteOrdinaryRefresh; this validator never
    // promotes policy/evidence metadata into an execution claim.
    void ValidateOrdinaryRefreshExecutionEvidence(
        const NativeRefreshEndpointResult& result,
        const NativeRefreshEndpointEvidence& evidence) const;

    // Executes the genuine native canonical endpoint on caller-owned native
    // material.  It validates both external bindings, joins the compact
    // selector to the streamed gadget/KSK support, opens the externally bound
    // streamed DFT provider, and recomputes the h40 authorization from the
    // actual selector support and SecurityReport before calling
    // glr_ship_refresh_only_endpoint_prime.  This API is an execution seam, not
    // evidence that a full GL-128 material/value run has occurred.
    OrdinaryRefreshExecutionResult ExecuteOrdinaryRefresh(
        const Ciphertext& canonicalCiphertext,
        const OrdinaryRefreshExecutionMaterialView& material) const;

    // A zero seed requests operating-system entropy; nonzero seeds are
    // deterministic and intended for reproducible experiments.  Compact
    // public keys retain b plus one public 256-bit seed for exact a expansion.
    SecretKey KeyGen(std::uint64_t seed = 0) const;
    PublicKey PublicKeyGen(const SecretKey& secretKey,
                           std::uint64_t seed = 0) const;
    CompactPublicKey CompactPublicKeyGen(
        const SecretKey& secretKey, std::uint64_t seed = 0) const;
    PublicKey ExpandCompactPublicKey(
        const CompactPublicKey& compactPublicKey) const;
    std::uint64_t PublicKeyResidentBytes() const;
    std::uint64_t CompactPublicKeyMaterialBytes() const;

    Plaintext Encode(const MatrixBatch& matrices, double scale,
                     std::uint32_t level = 0,
                     bool slotDomain = false) const;
    MatrixBatch Decode(const Plaintext& plaintext) const;

    // Remark 3.13 typed transposed convention.  These values cannot be
    // silently passed to the ordinary plaintext/ciphertext API.
    NativeGL128TransposedPlaintext EncodeTransposed(
        const MatrixBatch& matrices, double scale = 0.0,
        std::uint32_t level = 0) const;
    NativeGL128TransposedDecodeResult DecodeTransposed(
        const NativeGL128TransposedPlaintext& plaintext) const;
    NativeGL128TransposedCiphertext EncryptTransposed(
        const SecretKey& secretKey,
        const NativeGL128TransposedPlaintext& plaintext,
        std::uint64_t seed = 0) const;
    NativeGL128TransposedCiphertext EncryptTransposed(
        const PublicKey& publicKey,
        const NativeGL128TransposedPlaintext& plaintext,
        std::uint64_t seed = 0) const;
    NativeGL128TransposedCiphertext EncryptTransposed(
        const CompactPublicKey& publicKey,
        const NativeGL128TransposedPlaintext& plaintext,
        std::uint64_t seed = 0) const;
    NativeGL128TransposedPlaintext DecryptTransposed(
        const SecretKey& secretKey,
        const NativeGL128TransposedCiphertext& ciphertext) const;
    NativeGL128TransposedDecodeResult DecryptDecodeTransposed(
        const SecretKey& secretKey,
        const NativeGL128TransposedCiphertext& ciphertext) const;
    NativeGL128LeftPlainMatrixMultiplyResult MatrixMultiplyPlainLeft(
        const NativeGL128TransposedPlaintext& plaintextLeft,
        const NativeGL128TransposedCiphertext& encryptedRight,
        const NativeGL128PlainProductOptions& options = {}) const;
    NativeGL128ModulusMaintenanceResult LogicalRescale(
        const Ciphertext& ciphertext) const;
    NativeGL128ModulusMaintenanceResult DropToLevel(
        const Ciphertext& ciphertext, std::uint32_t targetLevel) const;

    Ciphertext Encrypt(const SecretKey& secretKey, const Plaintext& plaintext,
                       std::uint64_t seed = 0, bool slotDomain = true) const;
    Ciphertext Encrypt(const PublicKey& publicKey, const Plaintext& plaintext,
                       std::uint64_t seed = 0,
                       bool slotDomain = true) const;
    Ciphertext Encrypt(const CompactPublicKey& publicKey,
                       const Plaintext& plaintext,
                       std::uint64_t seed = 0,
                       bool slotDomain = true) const;
    Plaintext Decrypt(const SecretKey& secretKey,
                      const Ciphertext& ciphertext) const;

    // Native GLR ciphertext addition.  This delegates directly to glr_ct_add;
    // it does not unpack matrices into OpenFHE rows.
    Ciphertext Add(const Ciphertext& lhs, const Ciphertext& rhs) const;
    Ciphertext Sub(const Ciphertext& lhs, const Ciphertext& rhs) const;
    Ciphertext Negate(const Ciphertext& ciphertext) const;

    // One native logical GL rescale.  The N32 profile represents one logical
    // scale level with two physical Q primes, so this drops exactly
    // max(1,rescale_stride) tail primes and fails closed without headroom.
    Ciphertext Rescale(const Ciphertext& ciphertext) const;

    // Native plaintext-ciphertext GL operations.  A coefficient-domain
    // plaintext is transformed to Slot domain on a private copy; inputs are
    // never reinterpreted as OpenFHE DCRT rows.
    Ciphertext MatMul(const Ciphertext& ciphertext,
                      const Plaintext& plaintext) const;
    Ciphertext Hadamard(const Ciphertext& ciphertext,
                       const Plaintext& plaintext) const;

    // Allocation-free evaluation-key planning, followed by explicitly
    // budgeted owner-side materialization.  primaryKeyCommitment is an opaque
    // nonempty public commitment supplied by the key owner; the adapter will
    // not invent one from, serialize, or expose the secret key.  A zero RNG
    // seed requests operating-system entropy.
    EvaluationKeyPlan PlanEvaluationKeys(
        const EvaluationKeyRequest& request) const;
    EvaluationKeys MaterializeEvaluationKeys(
        const SecretKey& primaryKey, const EvaluationKeyPlan& plan,
        std::string primaryKeyCommitment, std::uint64_t maxResidentBytes,
        std::uint64_t seed = 0) const;

    Ciphertext RotateRows(const Ciphertext& ciphertext, std::int32_t amount,
                          const EvaluationKeys& keys) const;
    Ciphertext RotateColumns(const Ciphertext& ciphertext,
                             std::int32_t amount) const;
    Ciphertext RotateMatrices(const Ciphertext& ciphertext,
                              std::int32_t amount,
                              const EvaluationKeys& keys) const;
    Ciphertext Transpose(const Ciphertext& ciphertext,
                         const EvaluationKeys& keys) const;
    Ciphertext Conjugate(const Ciphertext& ciphertext,
                         const EvaluationKeys& keys) const;
    Ciphertext HermitianTranspose(const Ciphertext& ciphertext,
                                  const EvaluationKeys& keys) const;

    // Ordinary §3.5/§3.6 ciphertext-ciphertext operations.  MatMul consumes
    // the Hermitian-right and product-basis keys; Hadamard consumes the
    // primary-square relinearization key.  Both perform the native logical
    // rescale (two physical Q-prime drops on the N32 profile).
    Ciphertext MatMul(const Ciphertext& lhs, const Ciphertext& rhs,
                      const EvaluationKeys& keys) const;
    // Native Theorem-3.8 A*B^H product.  Unlike MatMul(A, B), rhs is consumed
    // directly as the circledast right operand, so this exact facade consumes
    // only the two big-switch product keys and does not spend a third
    // preparation switch.
    Ciphertext MatMulAdjoint(const Ciphertext& lhs,
                            const Ciphertext& rhs,
                            const EvaluationKeys& keys) const;
    Ciphertext Hadamard(const Ciphertext& lhs, const Ciphertext& rhs,
                       const EvaluationKeys& keys) const;

    // Receipt-preserving Section-3 operations.  These are the preferred
    // production bindings: each result carries exact levels/scales, switch
    // counts, stride-two drops, trace normalization, and secret-free evidence
    // authored by the core facade.
    NativeGL128EvaluationResult EvaluateAdd(
        const Ciphertext& lhs, const Ciphertext& rhs) const;
    NativeGL128EvaluationResult EvaluateSub(
        const Ciphertext& lhs, const Ciphertext& rhs) const;
    NativeGL128EvaluationResult EvaluateMatMul(
        const Ciphertext& lhs, const Plaintext& rhs,
        const NativeGL128PlainProductOptions& options = {}) const;
    NativeGL128EvaluationResult EvaluateMatMul(
        const Ciphertext& lhs, const Ciphertext& rhs,
        const NativeKeyProvider& keys) const;
    NativeGL128EvaluationResult EvaluateMatMulAdjoint(
        const Ciphertext& lhs, const Ciphertext& rhs,
        const NativeKeyProvider& keys) const;
    NativeGL128EvaluationResult EvaluateHadamard(
        const Ciphertext& lhs, const Plaintext& rhs,
        const NativeGL128PlainProductOptions& options = {}) const;
    NativeGL128EvaluationResult EvaluateHadamard(
        const Ciphertext& lhs, const Ciphertext& rhs,
        const NativeKeyProvider& keys) const;
    NativeGL128EvaluationResult EvaluateRotateRows(
        const Ciphertext& ciphertext, std::int32_t amount,
        const NativeKeyProvider& keys) const;
    NativeGL128EvaluationResult EvaluateRotateColumns(
        const Ciphertext& ciphertext, std::int32_t amount) const;
    NativeGL128EvaluationResult EvaluateRotateMatrices(
        const Ciphertext& ciphertext, std::int32_t amount,
        const NativeKeyProvider& keys) const;
    NativeGL128EvaluationResult EvaluateTranspose(
        const Ciphertext& ciphertext,
        const NativeKeyProvider& keys) const;
    NativeGL128EvaluationResult EvaluateConjugate(
        const Ciphertext& ciphertext,
        const NativeKeyProvider& keys) const;
    NativeGL128EvaluationResult EvaluateHermitianTranspose(
        const Ciphertext& ciphertext,
        const NativeKeyProvider& keys) const;

private:
    explicit GLRProductionAdapter(Context context);

    Context m_context;
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_PKE_GLR_PRODUCTION_ADAPTER_H
