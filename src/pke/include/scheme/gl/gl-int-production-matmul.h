//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#ifndef LBCRYPTO_PKE_SCHEME_GL_INT_PRODUCTION_MATMUL_H
#define LBCRYPTO_PKE_SCHEME_GL_INT_PRODUCTION_MATMUL_H

#include "scheme/gl/gl-int-production-rlwe.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

inline constexpr std::size_t kGLIntProductionMaxGadgetEntries = 256;

/** One encrypted Eq. (5) slot in the bounded production Slot/NTT domain. */
struct GLIntProductionSlotCiphertextValue {
    GLIntBranch branch{GLIntBranch::Plus};
    uint32_t matrix{0};
    uint32_t row{0};
    uint32_t column{0};
    uint64_t b{0};
    uint64_t a{0};
};

/**
 * Sparse-support Slot-domain view of a full GL-128-257-N32 R'_Q ciphertext.
 * Missing physical slots carry (b,a)=(0,0); records contain ciphertext only,
 * never a message shadow.  Q is the CRT product of the bounded base+level
 * N32 primes used by GLIntProductionRLWECore.
 */
class GLIntProductionSlotCiphertext final {
public:
    const GLIntWBatchedParameters& GetParameters() const noexcept;
    const std::string& GetKeyTag() const noexcept;
    uint64_t GetCompositeModulus() const noexcept;
    uint64_t GetPlaintextScale() const noexcept;
    const std::vector<GLIntProductionSlotCiphertextValue>& GetValues() const noexcept;
    void Validate() const;

private:
    friend class GLIntProductionMatMulCore;

    GLIntProductionSlotCiphertext(
        GLIntWBatchedParameters parameters, std::string keyTag,
        uint64_t compositeModulus, uint64_t plaintextScale,
        std::vector<GLIntProductionSlotCiphertextValue> values);

    GLIntWBatchedParameters m_parameters;
    std::string m_keyTag;
    uint64_t m_compositeModulus{0};
    uint64_t m_plaintextScale{1};
    std::vector<GLIntProductionSlotCiphertextValue> m_values;
};

enum class GLIntProductionGadgetDirection : uint8_t {
    RightToPrimary,
    ProductToPrimary,
    SquareToPrimary,
};

/** Secret-free base-2 gadget keys for one bounded ciphertext support. */
class GLIntProductionGadgetEvalKeys final {
public:
    const std::string& GetDestinationKeyTag() const noexcept;
    uint32_t GetDigitCount() const noexcept;
    std::size_t GetEntryCount() const noexcept;
    bool UsesTErrors() const noexcept;
    bool IsSecurityAuthorized() const noexcept;
    void Validate() const;

private:
    friend class GLIntProductionMatMulCore;

    struct Digit {
        uint64_t b{0};
        uint64_t a{0};
    };
    struct Entry {
        GLIntProductionGadgetDirection direction{
            GLIntProductionGadgetDirection::RightToPrimary};
        GLIntBranch branch{GLIntBranch::Plus};
        uint32_t matrix{0};
        uint32_t destinationRow{0};
        uint32_t sourceRow{0};
        std::vector<Digit> digits;
    };

    GLIntProductionGadgetEvalKeys(
        GLIntWBatchedParameters parameters, std::string destinationKeyTag,
        uint64_t compositeModulus, uint32_t digitCount,
        std::vector<Entry> entries);

    GLIntWBatchedParameters m_parameters;
    std::string m_destinationKeyTag;
    uint64_t m_compositeModulus{0};
    uint32_t m_digitCount{0};
    std::vector<Entry> m_entries;
};

struct GLIntProductionMatMulCapabilities {
    bool exactCompositeRnsSlotDomain{true};
    bool sparseSupportCiphertext{true};
    bool symmetricTErrEncryption{true};
    bool gadgetDigitTErrEvaluationKeys{true};
    bool switchIntSmall{true};
    bool switchIntBig{true};
    bool encryptedCrossLaneMatrixMultiply{true};
    bool encryptedHadamard{true};
    bool ordinaryProductNormalization{false};
    bool paperTraceNormalization{true};
    bool auxiliaryModulusKeySwitch{false};
    bool noiseScalingModSwitch{false};
    bool coefficientDomainBridge{false};
    bool columnRotation{true};
    bool rowRotation{false};
    bool interMatrixRotation{false};
    bool transpose{false};
    bool conjugationFamilySwap{false};
    bool auxiliaryAutomorphismSwitch{false};
    bool securityAuthorized{false};
    bool bootstrap{false};
};

/**
 * Bounded encrypted Section-4 Slot-domain evaluator.
 *
 * Secret evaluations come from the same sparse s(X,W) used by the dense
 * coefficient RLWE core, evaluated at the exact plus/minus Eq. (5) roots in
 * both N32 primes and recombined by CRT.  Encrypt forms b=-a*s+m+t*e modulo
 * Q.  Evaluation keys use complete base-2 gadget digits satisfying
 * b_i+a_i*s_dst=2^i*s_src+t*e_i.
 *
 * MatrixMultiply implements the complete four-component §4.3 cross-lane
 * tensor and two SwitchInt_big applications.  Its raw relation is the
 * ordinary cross-lane product; the ciphertext carries the exact BGV
 * plaintext scale n*scale_lhs*scale_rhs modulo t, so logical decryption is
 * the paper's n^-1 trace product.  This avoids multiplying ciphertext noise
 * by a large centered representative of n^-1.  Hadamard uses the
 * three-component tensor plus SwitchInt_small and the product of input
 * plaintext scales.
 *
 * Sparse support leaks, only a two-prime prefix is present, and these gadget
 * keys switch directly at Q rather than using the paper's auxiliary modulus
 * followed by noise-scaling ModSwitch.  Security, the coefficient-domain
 * bridge and noise-scaling modulus switching therefore remain explicitly
 * false.
 */
class GLIntProductionMatMulCore final {
public:
    explicit GLIntProductionMatMulCore(
        GLIntWBatchedParameters parameters =
            GLIntWBatchedParameters::GL128257N32());

    const GLIntWBatchedParameters& GetParameters() const noexcept;
    uint64_t GetCompositeModulus() const noexcept;
    GLIntProductionMatMulCapabilities GetCapabilities() const noexcept;

    GLIntProductionSlotCiphertext Encrypt(
        const GLIntProductionSecretKey& secretKey,
        const GLIntProductionSparsePlaintext& plaintext,
        uint64_t seed = 0) const;
    GLIntProductionSparsePlaintext Decrypt(
        const GLIntProductionSecretKey& secretKey,
        const GLIntProductionSlotCiphertext& ciphertext) const;

    GLIntProductionSlotCiphertext Add(
        const GLIntProductionSlotCiphertext& lhs,
        const GLIntProductionSlotCiphertext& rhs) const;
    GLIntProductionSlotCiphertext Subtract(
        const GLIntProductionSlotCiphertext& lhs,
        const GLIntProductionSlotCiphertext& rhs) const;
    GLIntProductionSlotCiphertext Negate(
        const GLIntProductionSlotCiphertext& ciphertext) const;
    /** Output column k reads input column k+delta modulo n. */
    GLIntProductionSlotCiphertext RotateColumns(
        const GLIntProductionSlotCiphertext& ciphertext,
        int32_t delta) const;

    GLIntProductionGadgetEvalKeys EvalKeyGen(
        const GLIntProductionSecretKey& primaryKey,
        const GLIntProductionSlotCiphertext& lhs,
        const GLIntProductionSlotCiphertext& rhs,
        uint64_t seed = 0) const;

    GLIntProductionSlotCiphertext MatrixMultiply(
        const GLIntProductionSlotCiphertext& lhs,
        const GLIntProductionSlotCiphertext& rhs,
        const GLIntProductionGadgetEvalKeys& evaluationKeys) const;
    GLIntProductionSlotCiphertext Hadamard(
        const GLIntProductionSlotCiphertext& lhs,
        const GLIntProductionSlotCiphertext& rhs,
        const GLIntProductionGadgetEvalKeys& evaluationKeys) const;

private:
    using Entry = GLIntProductionGadgetEvalKeys::Entry;
    using Digit = GLIntProductionGadgetEvalKeys::Digit;

    void ValidatePrimaryKey(const GLIntProductionSecretKey& key,
                            const char* operation) const;
    void ValidateCiphertext(const GLIntProductionSlotCiphertext& ciphertext,
                            const char* objectName) const;
    void ValidateOperands(const GLIntProductionSlotCiphertext& lhs,
                          const GLIntProductionSlotCiphertext& rhs,
                          const char* operation) const;
    void ValidateEvaluationKeys(
        const GLIntProductionGadgetEvalKeys& evaluationKeys,
        const std::string& destinationKeyTag,
        const char* operation) const;
    uint64_t EvaluateSecret(const GLIntProductionSecretKey& key,
                            GLIntBranch branch, uint32_t matrix,
                            uint32_t row) const;
    Entry MakeEntry(const GLIntProductionSecretKey& key,
                    GLIntProductionGadgetDirection direction,
                    GLIntBranch branch, uint32_t matrix,
                    uint32_t destinationRow, uint32_t sourceRow,
                    uint64_t* rngState) const;
    const Entry& RequireEntry(
        const GLIntProductionGadgetEvalKeys& keys,
        GLIntProductionGadgetDirection direction, GLIntBranch branch,
        uint32_t matrix, uint32_t destinationRow, uint32_t sourceRow,
        const char* operation) const;
    std::pair<uint64_t, uint64_t> ApplyGadget(uint64_t value,
                                              const Entry& entry) const;

    GLIntWBatchedParameters m_parameters;
    std::vector<uint32_t> m_moduli;
    std::vector<uint32_t> m_zeta;
    std::vector<uint32_t> m_eta;
    uint64_t m_compositeModulus{0};
    uint32_t m_digitCount{0};
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_PKE_SCHEME_GL_INT_PRODUCTION_MATMUL_H
