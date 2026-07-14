//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#ifndef LBCRYPTO_CRYPTO_CKKSRNS_PACO_H
#define LBCRYPTO_CRYPTO_CKKSRNS_PACO_H

#include "ciphertext.h"
#include "cryptocontext.h"
#include "key/evalkey.h"
#include "key/keypair.h"
#include "key/privatekey.h"
#include "key/publickey.h"

#include <array>
#include <complex>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace lbcrypto {

/**
 * Native OpenFHE parameters for PaCo (Bootstrapping via Partial CoeffToSlot).
 *
 * The notation follows Algorithms 1--5 of the PaCo paper.  C is the number
 * of real plaintext-polynomial coefficients refreshed by one sequential
 * invocation, so it represents C/2 ordinary complex CKKS slots.  The context
 * ring dimension N must satisfy 4*h*C <= N. Positive g0/g1 values larger than
 * their layer counts are accepted as the harmless extension "group all
 * remaining layers" (the pinned reference clamps them to the same effect).
 */
struct PaCoParameters {
    uint32_t h  = 0;
    uint32_t C  = 0;
    uint32_t g0 = 1;
    uint32_t g1 = 1;

    uint32_t CoefficientBudget(uint32_t ringDimension) const;
    uint32_t ResidueBlockCount(uint32_t ringDimension) const;
    uint32_t PartialRingSlots() const;
    uint32_t MultiplicativeDepth() const;
    void Validate(uint32_t ringDimension) const;
};

/**
 * Published proof-of-concept parameter metadata from PACO.md, Table 4.
 * These are citation/calibration values only. The native port uses direct
 * diagonal maps and full-context OpenFHE HYBRID keys, so the table's key
 * counts, modulus sizes, memory, timing, security, and precision do not carry
 * over without native measurement.
 */
struct PaCoPaperParameterSet {
    std::string name;
    uint32_t logRingDimension        = 0;
    uint32_t logBaseModulus          = 0;
    uint32_t logMessageScale         = 0;
    uint32_t logBootstrapScale       = 0;
    uint32_t h                       = 64;
    uint32_t grouping                = 3;
    uint32_t multiplicativeDepth     = 0;
    uint32_t logEvaluationKeyModulus = 0;
    uint32_t reportedPrecisionBits   = 0;
};

PaCoPaperParameterSet PaCoPaperSetI();
PaCoPaperParameterSet PaCoPaperSetII();

/**
 * Owner-side structured secret and matching OpenFHE encryption keys.
 *
 * shiftIndices and selectors are the u_v and d_v values from Algorithm 1.
 * They are secret owner material and are not needed by EvalSequential after
 * GenerateBootstrapKeys has encrypted the four sigma vectors.
 */
struct PaCoKeyMaterial {
    KeyPair<DCRTPoly> keyPair;
    uint32_t h = 0;
    std::vector<uint32_t> shiftIndices;
    std::vector<uint8_t> selectors;
};

/**
 * Evaluator-visible PaCo material. It contains no plaintext secret key.
 *
 * This is a trusted in-process handle bundle rather than a hardened wire
 * format. OpenFHE evaluation-key pointees are shared and must be treated as
 * immutable after generation/loading. LoadBootstrapKeys validates the bundle
 * boundary and privately clones its selector ciphertexts and key map.
 */
struct PaCoBootstrapKeys {
    uint32_t formatVersion = 1;
    PaCoParameters parameters;
    uint32_t ringDimension = 0;
    uint32_t totalTowers   = 0;
    std::array<Ciphertext<DCRTPoly>, 4> selectorCiphertexts;
    std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> automorphismKeys;
    EvalKey<DCRTPoly> multiplicationKey;
    /** Signed logical rotations, excluding conjugation and fused conjugate-rotate. */
    std::vector<int32_t> rotationIndices;
    /** Complete, deduplicated X -> X^j automorphism manifest used by this bundle. */
    std::vector<uint32_t> automorphismIndices;
    std::string keyTag;
};

namespace paco::detail {

/** Sparse cyclic-diagonal representation used by the PaCo D/E stages. */
struct SparseDiagonalMatrix {
    uint32_t dimension = 0;
    std::map<uint32_t, std::vector<std::complex<double>>> diagonals;

    static SparseDiagonalMatrix Identity(uint32_t dimension);
    std::vector<std::complex<double>> Apply(const std::vector<std::complex<double>>& input) const;
};

uint32_t BitReverse(uint32_t value, uint32_t bits);
uint32_t ExtendedBitReverse(uint32_t value, uint32_t blockSize);
std::vector<std::complex<double>> ExtendedBitReverseVector(const std::vector<std::complex<double>>& input,
                                                           uint32_t blockSize);

SparseDiagonalMatrix Multiply(const SparseDiagonalMatrix& left, const SparseDiagonalMatrix& right);
SparseDiagonalMatrix MakeDStage(uint32_t dimension, uint32_t logStride, bool inverse = false);
SparseDiagonalMatrix MakeEStage(uint32_t dimension, uint32_t logStride, uint32_t reversalBlock, bool inverse = false);
std::vector<SparseDiagonalMatrix> GroupStages(const std::vector<SparseDiagonalMatrix>& stages, uint32_t groupSize,
                                              bool rightToLeft);

}  // namespace paco::detail

/**
 * Independent native implementation of PaCo for CKKS-RNS.
 *
 * This class intentionally does not replace FHECKKSRNS::EvalBootstrap.  It
 * owns a separate set of four encrypted PaCo selector vectors and explicit
 * automorphism/relinearization keys.  Setup is an owner operation; evaluation
 * uses only PaCoBootstrapKeys and public ciphertext coefficients.
 *
 * This native profile requires the input at an exactly one-tower base CKKS
 * modulus, one of the context's configured CKKS scales, noise-scale degree
 * one, and scaled
 * plaintext coefficients small relative to that modulus.  PaCo itself only
 * requires a well-defined modulus q; supporting a multi-tower RNS product as
 * q would additionally require exact CRT coefficient interpolation, which is
 * not implemented here.  The CryptoContext must use 64-bit NativeInteger,
 * COMPLEX CKKS packing, FLEXIBLEAUTO, HYBRID key switching, and have at least
 * MultiplicativeDepth()+2 Q towers so that the result regains at least one
 * usable level.
 */
class PaCoCKKSRNS {
public:
    PaCoCKKSRNS(CryptoContext<DCRTPoly> context, PaCoParameters parameters);

    /**
     * Generate Algorithm 1's structured key and a matching OpenFHE public key.
     * deterministicSeed is for reproducible tests only: disclosing or reusing
     * it makes the secret key predictable.
     */
    static PaCoKeyMaterial KeyGen(CryptoContext<DCRTPoly> context, uint32_t h,
                                  std::optional<uint64_t> deterministicSeed = std::nullopt);

    /** Validate owner material and generate Algorithms 2 and the evaluation keys. */
    void GenerateBootstrapKeys(const PaCoKeyMaterial& ownerMaterial);

    /** Load an evaluator-side bundle; no private key or clear secret descriptor is required. */
    void LoadBootstrapKeys(PaCoBootstrapKeys bootstrapKeys);

    bool IsSetup() const noexcept;
    const PaCoParameters& GetParameters() const noexcept;
    /** Return an evaluator bundle with privately cloned selector ciphertexts and key map. */
    PaCoBootstrapKeys GetBootstrapKeys() const;

    /** Public part of Algorithm 3; exposed for reproducibility and testing. */
    std::vector<Plaintext> GetCoefficientEncodings(ConstCiphertext<DCRTPoly> ciphertext) const;

    /** Algorithm 4: refresh the C coefficients indexed by multiples of N/C. */
    Ciphertext<DCRTPoly> EvalSequential(ConstCiphertext<DCRTPoly> ciphertext) const;

    /**
     * Algorithm 5: refresh D coefficients using kappa independent PaCo jobs.
     * When runConcurrently is true, jobs are evaluated with bounded batches of
     * std::async workers; all key generation is complete before workers launch.
     * maxConcurrency=0 uses the host's reported hardware concurrency.
     */
    Ciphertext<DCRTPoly> EvalParallel(ConstCiphertext<DCRTPoly> ciphertext, uint32_t D, uint32_t kappa,
                                      bool runConcurrently = false, uint32_t maxConcurrency = 0) const;

private:
    CryptoContext<DCRTPoly> m_context;
    PaCoParameters m_parameters;
    uint32_t m_ringDimension      = 0;
    uint32_t m_slots              = 0;
    uint32_t m_k                  = 0;
    uint32_t m_n                  = 0;
    uint32_t m_totalTowers        = 0;
    double m_outputBootstrapScale = 0.0;

    PaCoBootstrapKeys m_bootstrapKeys;
    std::vector<paco::detail::SparseDiagonalMatrix> m_partialInverseStages;
    std::vector<paco::detail::SparseDiagonalMatrix> m_slotToCoefficientStages;

    void RequireSetup() const;
    void ValidateInput(ConstCiphertext<DCRTPoly> ciphertext) const;
    std::vector<int32_t> RequiredRotationIndices() const;
    std::vector<uint32_t> RequiredAutomorphismIndices(const std::vector<int32_t>& rotations) const;
    Ciphertext<DCRTPoly> Rotate(ConstCiphertext<DCRTPoly> ciphertext, int32_t index) const;
    Ciphertext<DCRTPoly> Conjugate(ConstCiphertext<DCRTPoly> ciphertext) const;
    Ciphertext<DCRTPoly> ConjugateRotate(ConstCiphertext<DCRTPoly> ciphertext, int32_t index) const;
    Ciphertext<DCRTPoly> Trace(Ciphertext<DCRTPoly> ciphertext, uint32_t from, uint32_t to) const;
    Ciphertext<DCRTPoly> Product(Ciphertext<DCRTPoly> ciphertext, uint32_t from, uint32_t to) const;
    Ciphertext<DCRTPoly> ApplyMatrix(Ciphertext<DCRTPoly> ciphertext,
                                     const paco::detail::SparseDiagonalMatrix& matrix) const;
    Ciphertext<DCRTPoly> MultiplyPlain(Ciphertext<DCRTPoly> ciphertext, const std::vector<std::complex<double>>& values,
                                       uint32_t activeSlots) const;
    void RescaleOneLevel(Ciphertext<DCRTPoly>& ciphertext, const char* stage) const;
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_CRYPTO_CKKSRNS_PACO_H
