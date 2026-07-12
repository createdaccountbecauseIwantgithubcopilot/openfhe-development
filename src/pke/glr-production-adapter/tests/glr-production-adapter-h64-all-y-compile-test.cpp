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
