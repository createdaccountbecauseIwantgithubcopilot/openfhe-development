#include "openfhe/pke/glr-production-adapter.h"

#include <type_traits>
#include <utility>

using Adapter = lbcrypto::GLRProductionAdapter;

static_assert(Adapter::kH64AllYRows == 128);
static_assert(Adapter::kH64AllYBranchesPerRow == 2);
static_assert(Adapter::kH64AllYBranchFoldCount == 256);
static_assert(Adapter::NativeGL128H64ResearchPosture::research_only);
static_assert(
    Adapter::NativeGL128H64ResearchPosture::full_all_y_stc_composed);
static_assert(Adapter::NativeGL128H64ResearchAllYStcEvidence::research_only);
static_assert(!Adapter::NativeGL128H64ResearchAllYStcEvidence::
                  production_security_claim);
static_assert(!Adapter::NativeGL128H64ResearchAllYStcEvidence::
                  production_authorization_admitted);
static_assert(!std::is_copy_constructible_v<
              Adapter::NativeGL128H64ResearchAllYStcResult>);
static_assert(!std::is_convertible_v<
              Adapter::NativeGL128H64ResearchAllYStcResult,
              Adapter::NativeGL128BootstrapResult>);
static_assert(!std::is_constructible_v<
              Adapter::NativeGL128BootstrapResult,
              Adapter::NativeGL128H64ResearchAllYStcResult>);
static_assert(!std::is_convertible_v<
              Adapter::NativeGL128H64ResearchAllYStcResult,
              Adapter::NativeGL128DirectBootstrapAuthorizationBundle>);

using AdapterRef = const Adapter&;
using CiphertextRef = const Adapter::Ciphertext&;
using SourceScheduleRef =
    const Adapter::NativeGL128H64AllYPublicSourceSchedule&;
using HiddenSelectorRef =
    const Adapter::NativeGL128ValidatedH64HiddenSelectorSession&;
using ResolverRef =
    const Adapter::NativeGL128H64AllYPublicRootProviderResolver&;
using KeyProviderRef = const Adapter::NativeKeyProvider&;
using EvaluationKeysRef = const Adapter::EvaluationKeys&;
using FoldBindingRef =
    const Adapter::NativeGL128H64SparseFoldKskBinding&;
using DftSessionRef =
    const Adapter::NativeValidatedDftPlaintextProviderSession&;
using SelectedLeafBindingRef =
    const Adapter::NativeGL128H64SelectedLeafFoldBinding&;
using SelectedLeafProviderRef =
    const Adapter::NativeGL128H64SelectedLeafProvider&;
using SelectedLeafCheckpointRef =
    const Adapter::NativeGL128H64SelectedLeafFoldCheckpointVisitor&;
using SparseKeyRef = const Adapter::SparseSecretKey&;
using OwnerSeedRef =
    const Adapter::NativeGL128H64HiddenSelectorOwnerSeed&;
using OwnerCursorRef =
    Adapter::NativeGL128H64HiddenSelectorOwnerCursor&;
using OwnerCursorSinkRef =
    const Adapter::NativeGL128H64HiddenSelectorOwnerCursorSink&;
using OwnerCursorEmissionRef =
    const Adapter::NativeGL128H64HiddenSelectorOwnerCursorEmission&;
using SharedWKeySinkRef =
    const Adapter::NativeGL128H64P257SharedWActionKeySink&;
using SharedWKeyManifestRef =
    const Adapter::NativeGL128H64P257SharedWActionKeyManifest&;
using SharedWKeyBindingRef =
    const Adapter::NativeGL128H64P257SharedWActionKeyBinding&;
using SharedWKeySourceRef =
    const Adapter::NativeGL128H64P257SharedWActionKeySource&;
using SharedWKeyConsumerRef =
    const Adapter::NativeGL128H64P257SharedWActionKeyConsumer&;
using CompleteWMaterialRef =
    const Adapter::NativeGL128H64P257CompleteWActionMaterial&;
using CompleteWDeploymentSourceRef =
    const Adapter::NativeGL128H64P257CompleteWActionDeploymentSource&;
using CompleteWRequests =
    std::span<const Adapter::NativeGL128H64P257OneBitRequest>;
using NativeSwitchKeyRef = const Adapter::NativeSwitchKey&;
using NativeKskRecordRef = const Adapter::NativeKskRecord&;

static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>().PlanH64AllYPublicSources(
                  std::declval<CiphertextRef>())),
              Adapter::NativeGL128H64AllYPublicSourceSchedule>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .GetH64AllYPublicSourceScheduleCommitment(
                               std::declval<SourceScheduleRef>())),
              std::string>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .MakeH64AllYPublicRootProviderResolver()),
              Adapter::NativeGL128H64AllYPublicRootProviderResolver>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .PlanH64WActionResearch()),
              Adapter::NativeGL128H64WActionPlan>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .GetH64WActionResearchCapabilities()),
              Adapter::NativeGL128H64WActionResearchCapabilities>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .AuditH64StructuredSecurity()),
              Adapter::NativeGL128H64StructuredSecurityAudit>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .GetH64StructuredSecurityCapabilities()),
              Adapter::NativeGL128H64StructuredSecurityCapabilities>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .GetH64SelectedLeafFoldCapabilities()),
              Adapter::NativeGL128H64SelectedLeafFoldCapabilities>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EvaluateH64SelectedLeafFoldCpu(
                               std::declval<SelectedLeafBindingRef>(),
                               std::declval<SelectedLeafProviderRef>(),
                               std::declval<KeyProviderRef>(),
                               std::declval<FoldBindingRef>(),
                               std::declval<SelectedLeafCheckpointRef>())),
              Adapter::NativeGL128H64SelectedLeafFoldResult>);
static_assert(!std::is_convertible_v<
              Adapter::NativeGL128H64SelectedLeafFoldResult,
              Adapter::NativeGL128BootstrapResult>);
static_assert(!std::is_copy_constructible_v<
              Adapter::NativeGL128H64HiddenSelectorOwnerCursor>);
static_assert(!std::is_copy_assignable_v<
              Adapter::NativeGL128H64HiddenSelectorOwnerCursor>);
static_assert(std::is_nothrow_move_constructible_v<
              Adapter::NativeGL128H64HiddenSelectorOwnerCursor>);
static_assert(std::is_nothrow_move_assignable_v<
              Adapter::NativeGL128H64HiddenSelectorOwnerCursor>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .GetH64HiddenSelectorOwnerCursorCapabilities()),
              Adapter::NativeGL128H64HiddenSelectorOwnerCursorCapabilities>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .CreateH64HiddenSelectorOwnerCursor(
                               std::declval<SparseKeyRef>(),
                               std::declval<OwnerSeedRef>())),
              Adapter::NativeGL128H64HiddenSelectorOwnerCursor>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EmitNextH64HiddenSelectorOwnerCursorChunk(
                               std::declval<OwnerCursorRef>(),
                               std::declval<SparseKeyRef>(),
                               std::declval<OwnerSeedRef>(),
                               std::declval<OwnerCursorSinkRef>(), 10)),
              Adapter::NativeGL128H64HiddenSelectorOwnerCursorEmission>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .GetH64P257CompleteWDeploymentCapabilities()),
              Adapter::NativeGL128H64P257CompleteWDeploymentCapabilities>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .GenerateH64P257FullPrefixMaskMaterial(
                               std::declval<SparseKeyRef>(),
                               std::declval<OwnerSeedRef>(), 0, 7)),
              Adapter::NativeGL128H64P257FullPrefixMaskMaterial>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .GenerateH64P257SharedWActionKeys(
                               std::declval<SparseKeyRef>(),
                               std::declval<SharedWKeySinkRef>(), 7)),
              Adapter::NativeGL128H64P257SharedWActionKeyManifest>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .BindH64P257SharedWActionKeys(
                               std::declval<SharedWKeyManifestRef>(), 0)),
              Adapter::NativeGL128H64P257SharedWActionKeyBinding>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .ConsumeH64P257SharedWActionKeys(
                               std::declval<SharedWKeyManifestRef>(),
                               std::declval<SharedWKeyBindingRef>(),
                               std::declval<SharedWKeySourceRef>(),
                               std::declval<SharedWKeyConsumerRef>())),
              Adapter::NativeGL128H64P257SharedWActionKeyEvidence>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .BindH64P257CompleteWDeploymentMaterial(
                               std::declval<Adapter::
                                   NativeGL128H64P257FullPrefixMaskMaterial>(),
                               std::declval<OwnerCursorEmissionRef>(),
                               std::declval<SharedWKeyManifestRef>())),
              Adapter::NativeGL128H64P257CompleteWActionMaterial>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EvaluateH64P257CompleteWDeploymentCpu(
                               std::declval<CompleteWMaterialRef>(),
                               std::declval<CompleteWDeploymentSourceRef>(),
                               std::declval<CompleteWRequests>())),
              Adapter::NativeGL128H64P257CompleteWActionResult>);
static_assert(!std::is_convertible_v<
              Adapter::NativeGL128H64P257CompleteWActionResult,
              Adapter::NativeGL128BootstrapResult>);
static_assert(Adapter::NativeGL128H64P257CompleteWActionEvidence::
                  research_only);
static_assert(!Adapter::NativeGL128H64P257CompleteWActionEvidence::
                  exact_noise_evidence_present);
static_assert(!Adapter::NativeGL128H64P257CompleteWActionEvidence::
                  production_security_authorized);
static_assert(!Adapter::NativeGL128H64P257CompleteWActionEvidence::
                  bootstrap_direct_admitted);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .GetH64SelectedLeafH4GpuCapabilities()),
              Adapter::NativeGL128H64SelectedLeafH4GpuCapabilities>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EvaluateH64SelectedLeafH4GpuFrontier(
                               std::declval<SelectedLeafBindingRef>(),
                               std::declval<SelectedLeafProviderRef>(),
                               std::declval<NativeSwitchKeyRef>(),
                               std::declval<NativeKskRecordRef>())),
              Adapter::NativeGL128H64SelectedLeafGpuFrontierResult>);
static_assert(!std::is_convertible_v<
              Adapter::NativeGL128H64SelectedLeafGpuFrontierResult,
              Adapter::NativeGL128BootstrapResult>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .GetH64SelectedLeaf64GpuCapabilities()),
              Adapter::NativeGL128H64SelectedLeaf64GpuCapabilities>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EvaluateH64SelectedLeaf64GpuTree(
                               std::declval<SelectedLeafBindingRef>(),
                               std::declval<SelectedLeafProviderRef>(),
                               std::declval<NativeSwitchKeyRef>(),
                               std::declval<NativeKskRecordRef>())),
              Adapter::NativeGL128H64SelectedLeafGpuFrontierResult>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .GetH64SelectedLeaf64GpuReturnCapabilities()),
              Adapter::NativeGL128H64SelectedLeaf64GpuReturnCapabilities>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EvaluateH64SelectedLeaf64GpuReturn(
                               std::declval<SelectedLeafBindingRef>(),
                               std::declval<Adapter::Ciphertext>(),
                               std::declval<NativeSwitchKeyRef>(),
                               std::declval<NativeSwitchKeyRef>(),
                               std::declval<FoldBindingRef>())),
              Adapter::NativeGL128H64SelectedLeafGpuReturnResult>);
static_assert(!std::is_convertible_v<
              Adapter::NativeGL128H64SelectedLeafGpuReturnResult,
              Adapter::NativeGL128BootstrapResult>);
static_assert(Adapter::NativeGL128H64OwnerRootProductEvidence::owner_only);
static_assert(!Adapter::NativeGL128H64OwnerRootProductEvidence::
                  evaluator_callable);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EvaluateH64AllYStCResearch(
                               std::declval<CiphertextRef>(),
                               std::declval<SourceScheduleRef>(),
                               std::declval<HiddenSelectorRef>(),
                               std::declval<ResolverRef>(),
                               std::declval<KeyProviderRef>(),
                               std::declval<FoldBindingRef>(),
                               std::declval<DftSessionRef>())),
              Adapter::NativeGL128H64ResearchAllYStcResult>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>().MatMulAdjoint(
                  std::declval<CiphertextRef>(),
                  std::declval<CiphertextRef>(),
                  std::declval<EvaluationKeysRef>())),
              Adapter::Ciphertext>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>().EvaluateMatMulAdjoint(
                  std::declval<CiphertextRef>(),
                  std::declval<CiphertextRef>(),
                  std::declval<KeyProviderRef>())),
              Adapter::NativeGL128EvaluationResult>);

int main() {
    return Adapter::NativeGL128H64ResearchPosture::research_only &&
                   !Adapter::NativeGL128H64ResearchPosture::
                        production_security_claim &&
                   !Adapter::NativeGL128H64ResearchPosture::
                        production_authorization_admitted
               ? 0
               : 1;
}
