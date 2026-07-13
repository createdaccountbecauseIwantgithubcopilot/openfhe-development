#include "openfhe/pke/glr-production-adapter.h"

#include <string>
#include <type_traits>
#include <utility>

using Adapter = lbcrypto::GLRProductionAdapter;
using AdapterRef = const Adapter&;
using CompleteWMaterialRef =
    const Adapter::NativeGL128H64P257CompleteWActionMaterial&;
using CompleteWSourceRef =
    const Adapter::NativeGL128H64P257CompleteWActionDeploymentSource&;
using OneBitRequestRef =
    const Adapter::NativeGL128H64P257OneBitRequest&;
using HiddenMaterialRef =
    const Adapter::NativeGL128H64P257HiddenLeafMaterial&;
using HiddenSourceRef = const Adapter::NativeGL128H64P257HiddenLeafSource&;
using HiddenRequestRef =
    const Adapter::NativeGL128H64P257HiddenLeafRequest&;
using CursorEmissionRef =
    const Adapter::NativeGL128H64HiddenSelectorOwnerCursorEmission&;
using SharedKeyManifestRef =
    const Adapter::NativeGL128H64P257SharedWActionKeyManifest&;
using SelectedRequestRef =
    const Adapter::NativeGL128H64SelectedLeafRequest&;
using FoldBindingRef =
    const Adapter::NativeGL128H64SelectedLeafFoldBinding&;
using ResidentProviderRef =
    const Adapter::NativeGL128H64ResidentSelectedLeafProvider&;
using DeploymentProviderRef =
    const Adapter::NativeGL128H64P257HiddenSupportDeploymentProvider&;
using SwitchKeyRef = const Adapter::NativeSwitchKey&;
using KskRecordRef = const Adapter::NativeKskRecord&;
using PhaseSpan =
    std::span<const Adapter::NativeGL128H64P257PhaseCoefficient>;

static_assert(Adapter::NativeGL128H64P257CompleteWGpuEvidence::research_only);
static_assert(!Adapter::NativeGL128H64P257CompleteWGpuEvidence::
                  full_64_support_fold_composed);
static_assert(!Adapter::NativeGL128H64P257CompleteWGpuEvidence::
                  production_security_authorized);
static_assert(Adapter::NativeGL128H64P257HiddenLeafEvidence::research_only);
static_assert(!Adapter::NativeGL128H64P257HiddenLeafEvidence::
                  exact_noise_evidence_present);
static_assert(!Adapter::NativeGL128H64P257HiddenLeafEvidence::
                  production_security_authorized);
static_assert(!std::is_convertible_v<
              Adapter::NativeGL128H64P257CompleteWGpuResult,
              Adapter::NativeGL128BootstrapResult>);
static_assert(!std::is_convertible_v<
              Adapter::NativeGL128H64P257HiddenLeafResult,
              Adapter::NativeGL128BootstrapResult>);
static_assert(!std::is_convertible_v<
              Adapter::NativeGL128H64P257HiddenLeafStreamGpuResult,
              Adapter::NativeGL128BootstrapResult>);
static_assert(std::is_same_v<
              decltype(std::declval<Adapter::
                           NativeGL128H64P257HiddenLeafStreamGpuEvidence>()
                           .owner_seed_commitment),
              std::string>);
static_assert(std::is_same_v<
              decltype(std::declval<Adapter::
                           NativeGL128H64P257HiddenLeafStreamGpuEvidence>()
                           .one_owner_seed_commitment_bound),
              bool>);

static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .GetH64P257CompleteWGpuCapabilities()),
              Adapter::NativeGL128H64P257CompleteWGpuCapabilities>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EvaluateH64P257CompleteWDeploymentGpu(
                               std::declval<CompleteWMaterialRef>(),
                               std::declval<CompleteWSourceRef>(),
                               std::declval<OneBitRequestRef>())),
              Adapter::NativeGL128H64P257CompleteWGpuResult>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EvaluateH64P257PreparedCompleteWDeploymentGpu(
                               std::declval<CompleteWMaterialRef>(),
                               std::declval<CompleteWSourceRef>(),
                               std::declval<Adapter::Ciphertext>(),
                               std::declval<Adapter::Ciphertext>())),
              Adapter::NativeGL128H64P257CompleteWGpuResult>);

static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .GetH64P257HiddenLeafCapabilities()),
              Adapter::NativeGL128H64P257HiddenLeafCapabilities>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .BindH64P257HiddenLeafMaterial(
                               std::declval<Adapter::
                                   NativeGL128H64P257FullPrefixMaskMaterial>(),
                               std::declval<CursorEmissionRef>(),
                               std::declval<SharedKeyManifestRef>())),
              Adapter::NativeGL128H64P257HiddenLeafMaterial>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EvaluateH64P257HiddenPreWOperandsCpu(
                               std::declval<HiddenMaterialRef>(),
                               std::declval<HiddenSourceRef>(),
                               std::declval<HiddenRequestRef>())),
              Adapter::NativeGL128H64P257HiddenPreWOperandsResult>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EvaluateH64P257HiddenLeafOptimizedCpu(
                               std::declval<HiddenMaterialRef>(),
                               std::declval<HiddenSourceRef>(),
                               std::declval<HiddenRequestRef>())),
              Adapter::NativeGL128H64P257HiddenLeafResult>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .BindH64P257HiddenLeafToFoldRequest(
                               std::declval<HiddenMaterialRef>(),
                               std::declval<Adapter::
                                   NativeGL128H64P257HiddenLeafResult>(),
                               std::declval<SelectedRequestRef>())),
              Adapter::NativeGL128H64SelectedSparseLeaf>);

static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .GetH64ResidentSelectedLeafGpuCapabilities()),
              Adapter::NativeGL128H64ResidentSelectedLeafGpuCapabilities>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EvaluateH64ResidentSelectedLeafH2GpuFrontier(
                               std::declval<FoldBindingRef>(),
                               std::declval<ResidentProviderRef>(),
                               std::declval<SwitchKeyRef>(),
                               std::declval<KskRecordRef>())),
              Adapter::NativeGL128H64SelectedLeafGpuFrontierResult>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EvaluateH64ResidentSelectedLeafH4GpuFrontier(
                               std::declval<FoldBindingRef>(),
                               std::declval<ResidentProviderRef>(),
                               std::declval<SwitchKeyRef>(),
                               std::declval<KskRecordRef>())),
              Adapter::NativeGL128H64SelectedLeafGpuFrontierResult>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EvaluateH64ResidentSelectedLeaf64GpuTree(
                               std::declval<FoldBindingRef>(),
                               std::declval<ResidentProviderRef>(),
                               std::declval<SwitchKeyRef>(),
                               std::declval<KskRecordRef>())),
              Adapter::NativeGL128H64SelectedLeafGpuFrontierResult>);

static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .GetH64P257HiddenLeafStreamGpuCapabilities()),
              Adapter::NativeGL128H64P257HiddenLeafStreamGpuCapabilities>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EvaluateH64P257HiddenLeafStreamH2Gpu(
                               std::declval<FoldBindingRef>(),
                               std::declval<PhaseSpan>(), 0,
                               std::declval<DeploymentProviderRef>(),
                               std::declval<SwitchKeyRef>(),
                               std::declval<KskRecordRef>())),
              Adapter::NativeGL128H64P257HiddenLeafStreamGpuResult>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EvaluateH64P257HiddenLeafStreamH4Gpu(
                               std::declval<FoldBindingRef>(),
                               std::declval<PhaseSpan>(), 0,
                               std::declval<DeploymentProviderRef>(),
                               std::declval<SwitchKeyRef>(),
                               std::declval<KskRecordRef>())),
              Adapter::NativeGL128H64P257HiddenLeafStreamGpuResult>);
static_assert(std::is_same_v<
              decltype(std::declval<AdapterRef>()
                           .EvaluateH64P257HiddenLeafStreamFull64Gpu(
                               std::declval<FoldBindingRef>(),
                               std::declval<PhaseSpan>(), 0,
                               std::declval<DeploymentProviderRef>(),
                               std::declval<SwitchKeyRef>(),
                               std::declval<KskRecordRef>())),
              Adapter::NativeGL128H64P257HiddenLeafStreamGpuResult>);

int main() {
    return 0;
}
