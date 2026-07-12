//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#ifndef LBCRYPTO_PKE_SCHEME_GL_INT_PRODUCTION_H
#define LBCRYPTO_PKE_SCHEME_GL_INT_PRODUCTION_H

#include "scheme/gl/gl-int.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace lbcrypto {

class GLIntProductionRLWECore;
class GLIntProductionGLRBridge;

inline constexpr std::size_t kGLIntProductionMaxLogicalValues = 64;
inline constexpr std::size_t kGLIntProductionMaxEncodedLogicalValues = 8;

/** One nonzero Eq. (5) slot in the physical 256x128x128 integer batch. */
struct GLIntProductionSlotValue {
    GLIntBranch branch{GLIntBranch::Plus};
    uint32_t matrix{0};
    uint32_t row{0};
    uint32_t column{0};
    int64_t value{0};
};

/**
 * Bounded sparse logical view of the canonical GL-128-257-N32 plaintext.
 *
 * Missing slots are exactly zero.  Construction sorts, combines duplicates
 * modulo t, removes zeros, and caps the live set.  The geometry remains the
 * full 2*phi(p)=512 matrices of shape 128x128; this is not a smaller ring.
 */
class GLIntProductionSparsePlaintext final {
public:
    GLIntProductionSparsePlaintext(GLIntWBatchedParameters parameters,
                                   std::vector<GLIntProductionSlotValue> values);

    const GLIntWBatchedParameters& GetParameters() const noexcept;
    const std::vector<GLIntProductionSlotValue>& GetValues() const noexcept;
    int64_t At(GLIntBranch branch, std::size_t matrix, std::size_t row,
               std::size_t column) const;
    void Validate() const;

private:
    GLIntWBatchedParameters m_parameters;
    std::vector<GLIntProductionSlotValue> m_values;
};

/**
 * Genuine dense coefficient tensor in
 * R'_t = Z_t[I,X,Y,W]/(I^2+1,X^128-I,Y^128-I,Phi_257(W)).
 *
 * Storage is exactly n*n*phi(p)=4,194,304 Gaussian residues (64 MiB), in
 * (X,Y,W) row-major order.  No logical-slot shadow is retained.
 */
class GLIntProductionEncodedPlaintext final {
public:
    const GLIntWBatchedParameters& GetParameters() const noexcept;
    const GLIntWBatchedCodecRoots& GetRoots() const noexcept;
    const std::vector<GLIntGaussianResidue>& GetCoefficients() const noexcept;
    const GLIntGaussianResidue& At(std::size_t x, std::size_t y,
                                   std::size_t w) const;
    void Validate() const;

private:
    friend class GLIntProductionCore;
    friend class GLIntProductionRLWECore;
    friend class GLIntProductionGLRBridge;

    GLIntProductionEncodedPlaintext(
        GLIntWBatchedParameters parameters, GLIntWBatchedCodecRoots roots,
        std::vector<GLIntGaussianResidue> coefficients);

    GLIntWBatchedParameters m_parameters;
    GLIntWBatchedCodecRoots m_roots;
    std::vector<GLIntGaussianResidue> m_coefficients;
};

struct GLIntProductionCapabilities {
    bool exactGL128257N32Geometry{true};
    bool sparseLogicalValuePath{true};
    bool denseRPrimeEncoding{true};
    bool selectedSlotDecode{true};
    bool exactIntegerTraceMatMul{true};
    bool ciphertextEncryption{false};
    bool switchIntSmall{false};
    bool switchIntBig{false};
    bool securityAuthorized{false};
    bool bootstrap{false};
};

/**
 * First production-geometry Section-4 value core.
 *
 * EncodeSparse implements the exact separable inverse of sigma_int for a
 * bounded sparse logical batch while materializing the complete production
 * R'_t coefficient tensor.  DecodeAt evaluates that tensor at any Eq. (5)
 * slot.  MatrixMultiplyTrace implements Theorem 4.1 exactly:
 *   plus  = n^-1 U_plus  * V_minus^T
 *   minus = n^-1 U_minus * V_plus^T.
 *
 * This class is plaintext/ring arithmetic only.  It makes no RLWE,
 * SwitchInt, security, or bootstrap claim.
 */
class GLIntProductionCore final {
public:
    explicit GLIntProductionCore(
        GLIntWBatchedParameters parameters =
            GLIntWBatchedParameters::GL128257N32());

    const GLIntWBatchedParameters& GetParameters() const noexcept;
    const GLIntWBatchedCodecRoots& GetRoots() const noexcept;
    GLIntProductionCapabilities GetCapabilities() const noexcept;

    GLIntProductionEncodedPlaintext EncodeSparse(
        const GLIntProductionSparsePlaintext& plaintext) const;
    int64_t DecodeAt(const GLIntProductionEncodedPlaintext& plaintext,
                     GLIntBranch branch, std::size_t matrix,
                     std::size_t row, std::size_t column) const;

    GLIntProductionSparsePlaintext Add(
        const GLIntProductionSparsePlaintext& lhs,
        const GLIntProductionSparsePlaintext& rhs) const;
    GLIntProductionSparsePlaintext Subtract(
        const GLIntProductionSparsePlaintext& lhs,
        const GLIntProductionSparsePlaintext& rhs) const;
    GLIntProductionSparsePlaintext Negate(
        const GLIntProductionSparsePlaintext& plaintext) const;
    GLIntProductionSparsePlaintext Hadamard(
        const GLIntProductionSparsePlaintext& lhs,
        const GLIntProductionSparsePlaintext& rhs) const;
    GLIntProductionSparsePlaintext MatrixMultiplyTrace(
        const GLIntProductionSparsePlaintext& lhs,
        const GLIntProductionSparsePlaintext& rhs) const;

private:
    void ValidateSparse(const GLIntProductionSparsePlaintext& plaintext,
                        const char* objectName) const;
    void ValidateEncoded(const GLIntProductionEncodedPlaintext& plaintext,
                         const char* objectName) const;

    GLIntWBatchedParameters m_parameters;
    GLIntWBatchedCodecRoots m_roots;
    uint64_t m_gaussianUnit{0};
    uint64_t m_inverseGaussianUnit{0};
    uint64_t m_inverseTwo{0};
    uint64_t m_inverseDimension{0};
    std::vector<uint64_t> m_xPlusInverse;
    std::vector<uint64_t> m_xMinusInverse;
    std::vector<uint64_t> m_wPlusInverse;
    std::vector<uint64_t> m_wMinusInverse;
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_PKE_SCHEME_GL_INT_PRODUCTION_H
