#ifndef LBCRYPTO_PKE_GLR_PRODUCTION_ADAPTER_H
#define LBCRYPTO_PKE_GLR_PRODUCTION_ADAPTER_H

// Optional provider for the native W-batched GL RNS engine in GLScheme.
//
// This is intentionally separate from GLSchemelet.  The canonical production
// layout is phi=256 matrices of shape 128x128 in R'[X,Y,W]; none of these types
// are OpenFHE DCRT rows, and the adapter exposes no DCRT conversion seam.

#include "glscheme/production_profiles.hpp"
#include "glscheme/rns_encode.hpp"
#include "glscheme/rns_keygen.hpp"

#include <cstdint>

namespace lbcrypto {

class GLRProductionAdapter final {
public:
    using Profile = glscheme::production::Profile;
    using Context = glscheme::rns::GlrContext;
    using SecretKey = glscheme::rns::GlrSecretKey;
    using MatrixBatch = glscheme::rns::GlrMatrixBatch;
    using Plaintext = glscheme::rns::GlrPlaintext;
    using Ciphertext = glscheme::rns::GlrCiphertext;

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

    // GLScheme's current owner-side encryption API is symmetric.  A zero seed
    // requests operating-system entropy; nonzero seeds are deterministic and
    // intended for tests/reproducible experiments.
    SecretKey KeyGen(std::uint64_t seed = 0) const;

    Plaintext Encode(const MatrixBatch& matrices, double scale,
                     std::uint32_t level = 0) const;
    MatrixBatch Decode(const Plaintext& plaintext) const;

    Ciphertext Encrypt(const SecretKey& secretKey, const Plaintext& plaintext,
                       std::uint64_t seed = 0, bool slotDomain = true) const;
    Plaintext Decrypt(const SecretKey& secretKey,
                      const Ciphertext& ciphertext) const;

    // Native GLR ciphertext addition.  This delegates directly to glr_ct_add;
    // it does not unpack matrices into OpenFHE rows.
    Ciphertext Add(const Ciphertext& lhs, const Ciphertext& rhs) const;

private:
    explicit GLRProductionAdapter(Context context);

    Context m_context;
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_PKE_GLR_PRODUCTION_ADAPTER_H
