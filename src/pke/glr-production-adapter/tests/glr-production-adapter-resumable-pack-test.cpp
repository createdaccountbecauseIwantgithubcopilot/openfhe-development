#include "openfhe/pke/glr-production-adapter.h"

#include "glscheme/cts_stc_maps.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

using Adapter = lbcrypto::GLRProductionAdapter;
using namespace glscheme::rns;

void Require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

template <typename Fn>
bool ThrowsGlr(Fn&& fn) {
    try {
        fn();
    }
    catch (const GlrError&) {
        return true;
    }
    return false;
}

template <typename T>
concept HasCiphertextValueExecutionFlag = requires(T value) {
    value.ciphertext_value_execution_performed;
};

template <typename T>
concept HasValueNoiseAcceptanceFlag = requires(T value) {
    value.value_noise_acceptance_recorded;
};

static_assert(!std::is_copy_constructible_v<
              Adapter::OrdinaryRefreshPackSession>);
static_assert(std::is_move_constructible_v<
              Adapter::OrdinaryRefreshPackSession>);
static_assert(!std::is_convertible_v<
              Adapter::OrdinaryRefreshPackSession,
              Adapter::NativeRefreshPackResult>);
static_assert(!HasCiphertextValueExecutionFlag<
              Adapter::OrdinaryRefreshPackFinalizedResult>);
static_assert(!HasValueNoiseAcceptanceFlag<
              Adapter::OrdinaryRefreshPackFinalizedResult>);

class RngHandle final {
public:
    explicit RngHandle(std::uint64_t seed) : m_rng(glr_rng_create(seed)) {
        Require(m_rng != nullptr, "failed to create GLScheme RNG");
    }
    ~RngHandle() { glr_rng_destroy(m_rng); }

    RngHandle(const RngHandle&) = delete;
    RngHandle& operator=(const RngHandle&) = delete;

    GlrRng& Get() const { return *m_rng; }

private:
    GlrRng* m_rng = nullptr;
};

bool SamePoly(const GlrPoly& lhs, const GlrPoly& rhs) {
    return lhs.ring == rhs.ring && lhs.level == rhs.level &&
           lhs.extended == rhs.extended && lhs.domain == rhs.domain &&
           lhs.data == rhs.data;
}

bool SameCiphertext(const GlrCiphertext& lhs, const GlrCiphertext& rhs) {
    return SamePoly(lhs.b, rhs.b) && SamePoly(lhs.a, rhs.a) &&
           lhs.scale == rhs.scale && lhs.level == rhs.level &&
           lhs.key_id == rhs.key_id;
}

bool HasNonzeroWords(const GlrPoly& poly) {
    return std::any_of(poly.data.begin(), poly.data.end(),
                       [](std::uint64_t word) { return word != 0U; });
}

std::int64_t ToI64(__int128 value) {
    Require(value >= std::numeric_limits<std::int64_t>::min() &&
                value <= std::numeric_limits<std::int64_t>::max(),
            "toy centered coefficient exceeded int64");
    return static_cast<std::int64_t>(value);
}

struct Fixture {
    GlrContext context;
    std::vector<GlrShipWindow> windows;
    GlrSecretKey primary;
    GlrSparseSecretKey sparse;
    GlrShipSelectorBank selectorBank;
    std::unique_ptr<GlrKskProvider> provider;
};

Fixture MakeFixture() {
    Fixture fixture;
    GlrParams params = glr_params_test(
        /*n=*/4, /*p=*/3, /*levels=*/6);
    params.rescale_stride = 2;
    params.delta = std::ldexp(1.0, 52);
    params.name += "-openfhe-resumable-pack";
    fixture.context = GlrContext::create(std::move(params));
    Require(fixture.context.n() == 4 && fixture.context.p_() == 3 &&
                fixture.context.phi() == 2 &&
                fixture.context.params.rescale_stride == 2,
            "unexpected toy context geometry");

    fixture.windows = glr_ship_make_windows(
        fixture.context.n(), fixture.context.phi(),
        /*weight=*/2, /*spacing=*/0,
        /*coarse_width=*/fixture.context.n() / 2,
        /*fine_width=*/1, /*w_width=*/fixture.context.phi());

    RngHandle rng(0x4f50454e46484531ULL);
    fixture.primary = glr_keygen_primary(fixture.context, rng.Get());
    fixture.sparse = glr_keygen_sparse(
        fixture.context, /*weight=*/2, &fixture.windows, rng.Get());
    fixture.selectorBank = glr_derive_ship_selector_bank(
        fixture.context, fixture.sparse, fixture.windows, rng.Get(),
        /*key_level=*/0);

    std::vector<GlrKskId> ids{
        {GlrKsDirection::primary_to_sparse, 0},
        {GlrKsDirection::sparse_to_primary, 0},
        {GlrKsDirection::sparse_sq_to_sparse, 0},
        {GlrKsDirection::conjugation_to_sparse, 0},
        {GlrKsDirection::primary_conjtranspose_to_primary, 0},
        {GlrKsDirection::aux_conjtranspose_to_primary, 0},
    };
    const GlrShipRefreshOnlyPackPreflight tracePlan =
        glr_ship_refresh_only_pack_preflight(
            fixture.context.n(), fixture.context.p_());
    const auto appendTraceKeys = [&](GlrKsDirection direction,
                                     std::uint32_t size,
                                     GlrShipRefreshOnlyTraceSchedule schedule) {
        if (schedule == GlrShipRefreshOnlyTraceSchedule::identity) {
            return;
        }
        if (schedule ==
            GlrShipRefreshOnlyTraceSchedule::sequential_unit) {
            ids.push_back({direction, 1});
            return;
        }
        for (std::uint32_t amount = 1; amount < size; amount *= 2) {
            ids.push_back(
                {direction, static_cast<std::int32_t>(amount)});
        }
    };
    appendTraceKeys(GlrKsDirection::row_rotation, fixture.context.n(),
                    tracePlan.x_trace_schedule);
    appendTraceKeys(GlrKsDirection::w_rotation, fixture.context.phi(),
                    tracePlan.w_trace_schedule);

    GlrOwnerKeyMaterial owner;
    owner.primary = fixture.primary;
    owner.sparse = fixture.sparse;
    owner.switch_keys.reserve(ids.size());
    for (const GlrKskId& id : ids) {
        owner.switch_keys.push_back(glr_make_ksk(
            fixture.context, id, fixture.primary, &fixture.sparse,
            /*encap=*/nullptr, rng.Get(), /*key_level=*/0));
    }
    owner.selector_bank = fixture.selectorBank;
    owner.key_seed_commitment = "openfhe-resumable-pack-toy-seed";
    GlrEvaluatorOpening opening =
        glr_open_evaluator_material(fixture.context, owner);
    fixture.provider = std::move(opening.provider);
    Require(fixture.provider != nullptr &&
                !fixture.provider->secret_material_accessed(),
            "toy evaluator provider is unavailable or secret-bearing");
    return fixture;
}

Adapter::NativeRefreshPackCheckpointSource MakeCheckpointSource(
    const std::vector<std::uint8_t>& bytes) {
    Adapter::NativeRefreshPackCheckpointSource source;
    source.secret_material_accessed = [] { return false; };
    source.encoded_size = [&bytes] {
        return static_cast<std::uint64_t>(bytes.size());
    };
    source.read_exact = [&bytes](
        std::uint64_t offset, std::span<std::uint8_t> destination) {
        if (offset > bytes.size() ||
            destination.size() > bytes.size() - offset) {
            throw GlrError("toy checkpoint source is truncated");
        }
        std::memcpy(destination.data(), bytes.data() + offset,
                    destination.size());
    };
    return source;
}

void RunResumableEndpointParity() {
    Fixture fixture = MakeFixture();
    const GlrContext& context = fixture.context;
    const std::uint32_t inputLevel = context.params.levels() - 7U;
    Require(context.active_q_primes(inputLevel) == 7U,
            "toy endpoint does not have the required seven-prime input");

    GlrShipRefreshOnlyParameters parameters;
    parameters.gamma = static_cast<double>(context.n());
    parameters.max_abs_coefficient = 1.0;

    RngHandle gadgetRng(0x4f50454e46484532ULL);
    const GlrShipGadgetBank gadget = glr_derive_ship_gadget_bank(
        context, fixture.sparse, fixture.windows, gadgetRng.Get(),
        /*fold_level=*/0);
    GlrShipConfig ship;
    ship.keys = fixture.provider.get();
    ship.bank = &fixture.selectorBank;
    ship.gadget_bank = &gadget;
    ship.production_mode = true;

    const double dftScale = std::ldexp(1.0, 60);
    const GlrDftPlaintextBank dft =
        glr_make_dft_bank(context, dftScale, /*level=*/0);

    GlrCiphertext coefficientImage;
    coefficientImage.b = GlrPoly::zero(
        context, GlrRing::Rp, /*level=*/0, /*extended=*/false,
        GlrDomain::Coeff);
    coefficientImage.a = GlrPoly::zero(
        context, GlrRing::Rp, /*level=*/0, /*extended=*/false,
        GlrDomain::Coeff);
    constexpr std::int64_t pattern[3]{-1, 0, 1};
    for (std::uint32_t x = 0; x < context.n(); ++x) {
        for (std::uint32_t y = 0; y < context.n(); ++y) {
            for (std::uint32_t w = 0; w < context.phi(); ++w) {
                const std::size_t lane =
                    (static_cast<std::size_t>(x) * context.n() + y) *
                        context.phi() +
                    w;
                glr_poly_set_gaussian(
                    context, coefficientImage.b, x, y, w,
                    static_cast<std::int64_t>(std::llround(
                        context.params.delta * pattern[(lane + x + 1) % 3])),
                    static_cast<std::int64_t>(std::llround(
                        context.params.delta *
                        pattern[(2 * lane + y + 2) % 3])));
            }
        }
    }
    coefficientImage.scale = context.params.delta;
    coefficientImage.level = 0;
    coefficientImage.key_id = "primary";

    const GlrCiphertext canonicalPublicImage = glr_stc_full(
        context, coefficientImage, dft, *fixture.provider);
    Require(!HasNonzeroWords(canonicalPublicImage.a),
            "public canonical image unexpectedly randomized");

    GlrPlaintext inputPlaintext;
    inputPlaintext.poly = GlrPoly::zero(
        context, GlrRing::Rp, inputLevel, /*extended=*/false,
        GlrDomain::Coeff);
    for (std::uint32_t x = 0; x < context.n(); ++x) {
        for (std::uint32_t y = 0; y < context.n(); ++y) {
            for (std::uint32_t w = 0; w < context.phi(); ++w) {
                __int128 real = 0;
                __int128 imag = 0;
                glr_poly_get_gaussian_centered(
                    context, canonicalPublicImage.b, x, y, w, real, imag);
                glr_poly_set_gaussian(
                    context, inputPlaintext.poly, x, y, w,
                    ToI64(real), ToI64(imag));
            }
        }
    }
    inputPlaintext.scale = canonicalPublicImage.scale;
    inputPlaintext.level = inputLevel;
    RngHandle inputRng(0x4f50454e46484533ULL);
    const GlrCiphertext canonicalInput = glr_encrypt(
        context, fixture.primary, inputPlaintext, inputRng.Get(),
        /*slot_domain=*/true);
    Require(canonicalInput.key_id == "primary" &&
                canonicalInput.b.domain == GlrDomain::Slot &&
                HasNonzeroWords(canonicalInput.a),
            "toy canonical input is not randomized slot-domain RLWE");

    GlrShipRefreshOnlyEndpointConfig endpointConfig;
    endpointConfig.ship = ship;
    endpointConfig.dft_bank = &dft;
    endpointConfig.normalization_relative_tolerance = 1.0e-12;
    endpointConfig.fold_level = 0;
    endpointConfig.transform_material_level = 0;
    GlrShipRefreshOnlyEndpointEvidence endpointEvidence;
    const GlrShipRefreshOnlyEndpointResult endpoint =
        glr_ship_refresh_only_endpoint_prime(
            context, canonicalInput, parameters, endpointConfig,
            &endpointEvidence);
    Require(endpointEvidence.ciphertext_value_execution_performed &&
                !endpointEvidence.value_noise_acceptance_recorded,
            "native toy endpoint reported the wrong execution/acceptance state");

    // Reproduce only the endpoint prefix needed by the public pack facade.
    // The unchanged endpoint above remains the byte-parity oracle.
    const GlrShipRefreshOnlyEndpointPreflight endpointPlan =
        glr_ship_refresh_only_endpoint_preflight(
            context.params, parameters, canonicalInput.scale, dft.scale,
            endpointConfig.normalization_relative_tolerance,
            endpointConfig.fold_level,
            endpointConfig.transform_material_level);
    GlrCiphertext normalized = glr_cts_full(
        context, canonicalInput, dft, *fixture.provider);
    if (normalized.b.domain == GlrDomain::Slot) {
        glr_to_coeffs(context, normalized.b);
        glr_to_coeffs(context, normalized.a);
    }
    const auto multiplier = static_cast<std::int64_t>(
        endpointPlan.normalization_multiplier);
    Require(multiplier > 0 &&
                static_cast<std::uint64_t>(multiplier) ==
                    endpointPlan.normalization_multiplier,
            "toy endpoint multiplier is not an exact positive int64");
    glr_scalar_mul_inplace(context, normalized.b, multiplier);
    glr_scalar_mul_inplace(context, normalized.a, multiplier);
    normalized.scale *= static_cast<double>(multiplier);
    for (std::uint32_t drop = 0;
         drop < endpointPlan.normalization_rescale_count; ++drop) {
        normalized = glr_rescale_ct(context, normalized);
    }
    const GlrCiphertext sparseInput = glr_ship_key_switch_to_sparse(
        context, normalized, *fixture.provider);
    Require(sparseInput.key_id == "sparse" &&
                sparseInput.b.domain == GlrDomain::Coeff &&
                context.active_q_primes(sparseInput.level) == 1U &&
                HasNonzeroWords(sparseInput.a),
            "manual endpoint prefix did not reach the q0 sparse state");

    GlrShipRefreshOnlyPackEvidence monolithicEvidence;
    const GlrShipRefreshOnlyPackedResult monolithic =
        glr_ship_refresh_only_pack_prime(
            context, sparseInput, parameters, ship, &monolithicEvidence);

    Adapter::OrdinaryRefreshPackFacade facade(context);
    const std::uint64_t total =
        glr_ship_refresh_only_pack_preflight(
            context.n(), context.p_()).centered_refreshes;
    Require(total == 8U, "unexpected toy pack coordinate count");

    auto incomplete = facade.Begin(
        sparseInput, parameters, ship, /*firstCoordinateCount=*/1);
    Require(!incomplete.CoordinateCoverComplete() &&
                incomplete.NextCoordinate() == 1U,
            "incomplete session claimed completion");
    Require(ThrowsGlr([&] {
                (void)facade.Finalize(
                    std::move(incomplete), sparseInput, parameters, ship);
            }),
            "incomplete pack finalized");
    Require(incomplete.NextCoordinate() == 1U,
            "incomplete-finalize rejection consumed the restartable session");

    // Uneven prefix [0,1), [1,5), checkpoint/resume, [5,7), [7,8).
    auto session = facade.Begin(
        sparseInput, parameters, ship, /*firstCoordinateCount=*/1);
    facade.Advance(session, sparseInput, parameters, ship,
                   /*coordinateCount=*/4);
    Require(session.NextCoordinate() == 5U &&
                session.TotalCoordinates() == total &&
                !session.CoordinateCoverComplete(),
            "uneven prefix accounting drifted");

    std::vector<std::uint8_t> checkpointBytes;
    Adapter::NativeRefreshPackCheckpointSink sink;
    sink.secret_material_accessed = [] { return false; };
    sink.write = [&checkpointBytes](std::span<const std::uint8_t> bytes) {
        checkpointBytes.insert(
            checkpointBytes.end(), bytes.begin(), bytes.end());
    };
    const Adapter::NativeRefreshPackCheckpointReceipt receipt =
        facade.SerializeCheckpoint(session, sink);
    Require(receipt.encoded_record_bytes == checkpointBytes.size() &&
                !receipt.full_record_materialized,
            "checkpoint facade did not preserve the bounded codec receipt");

    auto restored = facade.Resume(
        receipt, MakeCheckpointSource(checkpointBytes));
    Require(restored.NextCoordinate() == 5U &&
                !restored.CoordinateCoverComplete(),
            "checkpoint resume lost the merged prefix");

    GlrParams foreignParams = context.params;
    foreignParams.name += "-foreign-binding";
    const GlrContext foreignContext =
        GlrContext::create(std::move(foreignParams));
    Adapter::OrdinaryRefreshPackFacade foreignFacade(foreignContext);
    Require(ThrowsGlr([&] {
                (void)foreignFacade.Resume(
                    receipt, MakeCheckpointSource(checkpointBytes));
            }),
            "checkpoint resumed under a different context binding");

    std::vector<std::uint8_t> tamperedBytes = checkpointBytes;
    tamperedBytes.back() ^= 1U;
    Require(ThrowsGlr([&] {
                (void)facade.Resume(
                    receipt, MakeCheckpointSource(tamperedBytes));
            }),
            "tampered checkpoint payload resumed");
    auto tamperedReceipt = receipt;
    tamperedReceipt.encoded_record_commitment_sha256.back() =
        tamperedReceipt.encoded_record_commitment_sha256.back() == '0'
            ? '1'
            : '0';
    Require(ThrowsGlr([&] {
                (void)facade.Resume(
                    tamperedReceipt,
                    MakeCheckpointSource(checkpointBytes));
            }),
            "tampered checkpoint authentication receipt resumed");

    GlrCiphertext wrongInput = sparseInput;
    const std::uint64_t q0 = context.params.q_chain.front().q;
    wrongInput.b.data.front() =
        (wrongInput.b.data.front() + 1U) % q0;
    Require(ThrowsGlr([&] {
                facade.Advance(restored, wrongInput, parameters, ship,
                               /*coordinateCount=*/2);
            }),
            "resumed session accepted a different input binding");
    Require(restored.NextCoordinate() == 5U,
            "failed binding check mutated the resumed prefix");

    facade.Advance(restored, sparseInput, parameters, ship,
                   /*coordinateCount=*/2);
    facade.Advance(restored, sparseInput, parameters, ship,
                   /*coordinateCount=*/1);
    Require(restored.CoordinateCoverComplete() &&
                restored.NextCoordinate() == total,
            "uneven resumed session did not reach exact completion");
    Adapter::OrdinaryRefreshPackFinalizedResult finalized =
        facade.Finalize(
            std::move(restored), sparseInput, parameters, ship);

    Require(SameCiphertext(finalized.nativeResult.ciphertext,
                           monolithic.ciphertext) &&
                finalized.nativeResult.input_ciphertext_commitment_sha256 ==
                    monolithic.input_ciphertext_commitment_sha256 &&
                finalized.nativeResult.execution_material_commitment_sha256 ==
                    monolithic.execution_material_commitment_sha256,
            "resumed uneven pack differs from the monolithic pack endpoint");
    Require(finalized.nativeEvidence.checkpoint_chunks_merged == 4U &&
                finalized.nativeEvidence
                    .checkpoint_commitment_validated_merge_used &&
                finalized.nativeEvidence.centered_refreshes == total &&
                finalized.nativeEvidence.coefficients_packed ==
                    monolithicEvidence.coefficients_packed,
            "finalized pack evidence does not describe the real merged work");

    const GlrShipRefreshOnlyCanonicalResult resumedCanonical =
        glr_ship_refresh_only_stc_prime(
            context, finalized.nativeResult, dft, ship);
    Require(SameCiphertext(resumedCanonical.ciphertext,
                           endpoint.ciphertext) &&
                resumedCanonical.output_level == endpoint.output_level,
            "resumed pack plus StC differs from the existing "
            "ordinary-refresh endpoint");
}

}  // namespace

int main() {
    RunResumableEndpointParity();
    std::cout << "glr_production_adapter_resumable_pack_test: ALL PASS\n";
    return 0;
}
