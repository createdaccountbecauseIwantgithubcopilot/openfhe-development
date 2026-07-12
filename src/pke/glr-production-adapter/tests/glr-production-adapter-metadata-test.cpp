#include "openfhe/pke/glr-production-adapter.h"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>

namespace {

void Require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

}  // namespace

int main() {
    using Adapter = lbcrypto::GLRProductionAdapter;
    using glscheme::production::LayoutKind;

    static_assert(std::is_same_v<Adapter::Context, glscheme::rns::GlrContext>);
    static_assert(
        std::is_same_v<Adapter::Ciphertext, glscheme::rns::GlrCiphertext>);
    static_assert(!std::is_copy_constructible_v<Adapter>);

    const Adapter::Profile profile = Adapter::CanonicalProfile();
    Require(profile.layout == LayoutKind::gl128_257_n32_tensor,
            "wrong typed layout");
    Require(profile.canonical_name ==
                "GL-128-257-N32/physical-256x128x128",
            "wrong canonical name");
    Require(profile.n == 128 && profile.p == 257 && profile.phi == 256,
            "wrong GL algebra shape");
    Require(profile.has_w_axis && profile.matrix_count == 256,
            "production profile lost its W axis");
    Require(profile.physical.planes == 256 && profile.physical.rows == 128 &&
                profile.physical.columns == 128,
            "wrong physical tensor shape");
    Require(profile.payload_complex_values == 4194304ULL,
            "wrong production payload size");
    Require(profile.rlwe_ring_dimension == 65536ULL,
            "wrong RLWE dimension");

    // Context construction and primary key generation are small enough for a
    // fast smoke test.  A full R' plaintext/ciphertext allocates gigabytes at
    // this canonical geometry, so encode/encrypt/decrypt/add are compile/link
    // provider checks here and belong in the resource-qualified acceptance run.
    Adapter adapter = Adapter::Create();
    const auto& context = adapter.GetContext();
    Require(context.params.name == "GL-128-257-N32", "wrong context profile");
    Require(context.n() == 128 && context.p_() == 257 && context.phi() == 256,
            "wrong context geometry");
    Require(context.params.coeffs_Rp() == 4194304ULL,
            "context is not the production R' tensor");

    Adapter::MatrixBatch wFreeRows;
    wFreeRows.n = 4096;
    wFreeRows.count = 1;
    bool rejectedWFreeRows = false;
    try {
        (void)adapter.Encode(wFreeRows, context.params.delta);
    }
    catch (const glscheme::rns::GlrError&) {
        rejectedWFreeRows = true;
    }
    Require(rejectedWFreeRows, "W-free dense rows aliased the GLR tensor");

    Adapter::SecretKey secretKey = adapter.KeyGen(0x474c523132383235ULL);
    Require(secretKey.key_id == "primary", "wrong key domain");
    Require(secretKey.s.ring == glscheme::rns::GlrRing::R,
            "primary key is not native ring R");
    Require(secretKey.s.extended, "primary key is missing the QP basis");
    const std::uint64_t expectedKeyResidues =
        std::uint64_t{context.active_qp_primes(0)} * 2 *
        context.params.coeffs_R();
    Require(secretKey.s.data.size() == expectedKeyResidues,
            "primary key storage does not match native GLR QP geometry");
    secretKey.secure_clear();

    std::cout << "glr_production_adapter_metadata_test: ALL PASS\n";
    return 0;
}
