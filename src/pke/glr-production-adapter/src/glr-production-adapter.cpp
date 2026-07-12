#include "openfhe/pke/glr-production-adapter.h"

#include <memory>
#include <string>
#include <utility>

namespace lbcrypto {
namespace {

using glscheme::rns::GlrError;
using glscheme::rns::GlrRng;

struct GlrRngDeleter {
    void operator()(GlrRng* rng) const noexcept {
        if (rng != nullptr) {
            glscheme::rns::glr_rng_destroy(rng);
        }
    }
};

using GlrRngOwner = std::unique_ptr<GlrRng, GlrRngDeleter>;

GlrRngOwner MakeRng(std::uint64_t seed) {
    GlrRngOwner rng(glscheme::rns::glr_rng_create(seed));
    if (!rng) {
        throw GlrError("GLRProductionAdapter: GLScheme RNG creation failed");
    }
    return rng;
}

void RequireCanonicalBatch(const GLRProductionAdapter::MatrixBatch& matrices) {
    constexpr std::uint32_t kN = 128;
    constexpr std::uint32_t kPhi = 256;
    constexpr std::uint64_t kValues = 4194304;
    if (matrices.n != kN || matrices.count != kPhi ||
        matrices.values.size() != kValues) {
        throw GlrError(
            "GLRProductionAdapter: encode requires the native W-batched "
            "256x128x128 GL-128-257-N32 layout; W-free rows are not accepted");
    }
}

void RequireProductionPlaintext(
    const GLRProductionAdapter::Plaintext& plaintext) {
    if (plaintext.poly.ring != glscheme::rns::GlrRing::Rp) {
        throw GlrError(
            "GLRProductionAdapter: plaintext must remain in native GLR R' "
            "with physical shape 256x128x128");
    }
}

void RequireProductionCiphertext(
    const GLRProductionAdapter::Ciphertext& ciphertext) {
    if (ciphertext.a.ring != glscheme::rns::GlrRing::Rp ||
        ciphertext.b.ring != glscheme::rns::GlrRing::Rp) {
        throw GlrError(
            "GLRProductionAdapter: ciphertext must remain in native GLR R' "
            "with physical shape 256x128x128");
    }
}

}  // namespace

GLRProductionAdapter::Profile GLRProductionAdapter::CanonicalProfile() {
    Profile profile = glscheme::production::gl128_257_n32();
    glscheme::production::validate(profile);
    glscheme::production::validate_distinct(
        profile, glscheme::production::dense4096_wfree());
    return profile;
}

GLRProductionAdapter GLRProductionAdapter::Create() {
    const Profile profile = CanonicalProfile();
    glscheme::rns::GlrParams params =
        glscheme::rns::glr_params_gl128_257_n32();
    if (params.name != profile.parameter_source || params.n != profile.n ||
        params.p != profile.p || params.phi != profile.phi ||
        glscheme::rns::glr_parameter_fingerprint(params) !=
            profile.binding_fingerprint) {
        throw GlrError(
            "GLRProductionAdapter: canonical profile/context binding mismatch");
    }
    return GLRProductionAdapter(
        glscheme::rns::GlrContext::create(std::move(params)));
}

GLRProductionAdapter::GLRProductionAdapter(Context context)
    : m_context(std::move(context)) {}

const GLRProductionAdapter::Context& GLRProductionAdapter::GetContext() const noexcept {
    return m_context;
}

GLRProductionAdapter::SecretKey GLRProductionAdapter::KeyGen(
    std::uint64_t seed) const {
    GlrRngOwner rng = MakeRng(seed);
    return glscheme::rns::glr_keygen_primary(m_context, *rng);
}

GLRProductionAdapter::Plaintext GLRProductionAdapter::Encode(
    const MatrixBatch& matrices, double scale, std::uint32_t level) const {
    RequireCanonicalBatch(matrices);
    return glscheme::rns::glr_encode(m_context, matrices, scale, level);
}

GLRProductionAdapter::MatrixBatch GLRProductionAdapter::Decode(
    const Plaintext& plaintext) const {
    RequireProductionPlaintext(plaintext);
    return glscheme::rns::glr_decode(m_context, plaintext);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Encrypt(
    const SecretKey& secretKey, const Plaintext& plaintext, std::uint64_t seed,
    bool slotDomain) const {
    RequireProductionPlaintext(plaintext);
    GlrRngOwner rng = MakeRng(seed);
    return glscheme::rns::glr_encrypt(m_context, secretKey, plaintext, *rng,
                                      slotDomain);
}

GLRProductionAdapter::Plaintext GLRProductionAdapter::Decrypt(
    const SecretKey& secretKey, const Ciphertext& ciphertext) const {
    RequireProductionCiphertext(ciphertext);
    return glscheme::rns::glr_decrypt(m_context, secretKey, ciphertext);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Add(
    const Ciphertext& lhs, const Ciphertext& rhs) const {
    RequireProductionCiphertext(lhs);
    RequireProductionCiphertext(rhs);
    return glscheme::rns::glr_ct_add(m_context, lhs, rhs);
}

}  // namespace lbcrypto
