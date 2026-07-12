//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

// GL_scheme.md section-4 integer (BGV-like) mode, W-free profile (p = 1):
// sigma_int codec, encrypt/decrypt, add/sub/negate, Hadamard, row/column
// rotation, conj-swap, native transpose (K3), adjoint (K1), circledast /
// matmul (K1+K2) with plaintext variants, and the Remark 3.13 transposed
// encoding.  Everything is EXACT arithmetic mod t = 257 (t = 17 as the
// n=4-only parameter pair): tests assert integer equality, never tolerance.
// n=4 pins the design-doc section-12 vector tables (anchored on the shared
// cross-port contract matrices A/B); n=8 checks every operation against a
// clear oracle recomputed in-test with plain integers.  Toy dims n=4/8 with
// HEStd_NotSet remain conformance geometry, not a security claim.  The
// separate fixed-size W-batched census validates production-sized Section-4
// geometry without claiming a p>1 value path, security, serialization, or
// integer bootstrapping.

#include "gtest/gtest.h"

#include "scheme/gl/gl-int.h"

#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace lbcrypto {
namespace {

constexpr int64_t kModulus = 257;

static_assert(!std::is_default_constructible_v<GLIntEvalKey>,
              "the GL integer key bundle cannot be publicly constructed without key material");
static_assert(!std::is_default_constructible_v<GLIntEncodedPlaintext>,
              "GL integer encoded plaintexts are produced only by the schemelet codec");
static_assert(!std::is_aggregate_v<GLIntEvalKey> && !std::is_aggregate_v<GLIntCiphertext> &&
                  !std::is_aggregate_v<GLIntEncodedPlaintext>,
              "GL integer invariants must stay behind validating constructors");
static_assert(std::is_trivially_copyable_v<GLIntWBatchedParameters> &&
                  std::is_trivially_copyable_v<GLIntOperationCensusEntry> &&
                  std::is_trivially_copyable_v<GLIntWBatchedCensus>,
              "the production/W-batched census must remain fixed-size and allocation-free");

using IntMatrix = std::vector<int64_t>;

int64_t Canonical(int64_t value, int64_t modulus = kModulus) {
    return ((value % modulus) + modulus) % modulus;
}

// ---------------------------------------------------------------------------
// Clear oracles (plain-integer triple loops; recomputed in-test, never
// hand-inlined product formulas).
// ---------------------------------------------------------------------------

IntMatrix OracleAdd(const IntMatrix& a, const IntMatrix& b) {
    IntMatrix out(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        out[i] = Canonical(a[i] + b[i]);
    }
    return out;
}

IntMatrix OracleSub(const IntMatrix& a, const IntMatrix& b) {
    IntMatrix out(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        out[i] = Canonical(a[i] - b[i]);
    }
    return out;
}

IntMatrix OracleNegate(const IntMatrix& a) {
    IntMatrix out(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        out[i] = Canonical(-a[i]);
    }
    return out;
}

IntMatrix OracleHadamard(const IntMatrix& a, const IntMatrix& b) {
    IntMatrix out(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        out[i] = Canonical(a[i] * b[i]);
    }
    return out;
}

IntMatrix OracleScale(const IntMatrix& a, int64_t factor) {
    IntMatrix out(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        out[i] = Canonical(a[i] * Canonical(factor));
    }
    return out;
}

IntMatrix OracleTranspose(const IntMatrix& a, std::size_t n) {
    IntMatrix out(n * n);
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            out[j * n + k] = a[k * n + j];
        }
    }
    return out;
}

IntMatrix OracleMatMul(const IntMatrix& a, const IntMatrix& b, std::size_t n) {
    IntMatrix out(n * n, 0);
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            int64_t accumulator = 0;
            for (std::size_t inner = 0; inner < n; ++inner) {
                accumulator = Canonical(accumulator + a[j * n + inner] * b[inner * n + k]);
            }
            out[j * n + k] = accumulator;
        }
    }
    return out;
}

IntMatrix OracleMatMulBT(const IntMatrix& a, const IntMatrix& b, std::size_t n) {  // a * b^T
    IntMatrix out(n * n, 0);
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            int64_t accumulator = 0;
            for (std::size_t inner = 0; inner < n; ++inner) {
                accumulator = Canonical(accumulator + a[j * n + inner] * b[k * n + inner]);
            }
            out[j * n + k] = accumulator;
        }
    }
    return out;
}

IntMatrix OracleRowRotate(const IntMatrix& a, std::size_t nu, std::size_t n) {
    IntMatrix out(n * n);
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            out[j * n + k] = a[((j + nu) % n) * n + k];
        }
    }
    return out;
}

IntMatrix OracleColumnRotate(const IntMatrix& a, std::size_t nu, std::size_t n) {
    IntMatrix out(n * n);
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            out[j * n + k] = a[j * n + (k + nu) % n];
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Pinned deterministic inputs (design doc section 11/12; U+ = contract A,
// V+ = contract B reduced mod 257).
// ---------------------------------------------------------------------------

IntMatrix PinnedUPlus4() {
    return {1, 2, 0, 256, 0, 1, 3, 0, 2, 0, 1, 1, 1, 256, 0, 2};
}

IntMatrix PinnedUMinus4() {
    return {1, 6, 11, 16, 2, 10, 18, 26, 5, 16, 27, 38, 10, 24, 38, 52};
}

IntMatrix PinnedVPlus4() {
    return {1, 0, 2, 1, 0, 1, 256, 2, 1, 2, 0, 0, 2, 0, 1, 1};
}

IntMatrix PinnedVMinus4() {
    return {3, 4, 7, 12, 10, 13, 18, 25, 17, 22, 29, 38, 24, 31, 40, 51};
}

// U-[j][k] = (j^2 + 3jk + 5k + 1) mod t; V-[j][k] = (2jk + 7j + k^2 + 3) mod t.
IntMatrix GeneratedUMinus(std::size_t n) {
    IntMatrix out(n * n);
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            out[j * n + k] = Canonical(static_cast<int64_t>(j * j + 3 * j * k + 5 * k + 1));
        }
    }
    return out;
}

IntMatrix GeneratedVMinus(std::size_t n) {
    IntMatrix out(n * n);
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            out[j * n + k] = Canonical(static_cast<int64_t>(2 * j * k + 7 * j + k * k + 3));
        }
    }
    return out;
}

// Integerized conventions generators (nonnegative mod semantics pinned by the
// clear reference): U+[j][k] = ((j + 2k) mod 7 - 3) mod t,
// V+[j][k] = ((3j - k) mod 5 - 2) mod t.
IntMatrix GeneratedUPlus8() {
    IntMatrix out(64);
    for (std::size_t j = 0; j < 8; ++j) {
        for (std::size_t k = 0; k < 8; ++k) {
            out[j * 8 + k] = Canonical(static_cast<int64_t>((j + 2 * k) % 7) - 3);
        }
    }
    return out;
}

IntMatrix GeneratedVPlus8() {
    IntMatrix out(64);
    for (std::size_t j = 0; j < 8; ++j) {
        for (std::size_t k = 0; k < 8; ++k) {
            const auto residue = ((static_cast<int64_t>(3 * j) - static_cast<int64_t>(k)) % 5 + 5) % 5;
            out[j * 8 + k]     = Canonical(residue - 2);
        }
    }
    return out;
}

IntMatrix RandomMatrix(std::mt19937& rng, std::size_t n) {
    IntMatrix out(n * n);
    for (auto& value : out) {
        value = static_cast<int64_t>(rng() % kModulus);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

GLIntParameters IntParameters(std::size_t dimension, uint64_t plaintextModulus = 257,
                              uint32_t multiplicativeDepth = 2) {
    GLIntParameters parameters;
    parameters.dimension           = dimension;
    parameters.plaintextModulus    = plaintextModulus;
    parameters.multiplicativeDepth = multiplicativeDepth;
    return parameters;
}

struct IntHarness {
    GLIntSchemelet scheme;
    KeyPair<DCRTPoly> keys;
    GLIntEvalKey evalKey;
};

IntHarness MakeHarness(std::size_t dimension, uint32_t multiplicativeDepth = 2) {
    GLIntSchemelet scheme(IntParameters(dimension, 257, multiplicativeDepth));
    auto keys    = scheme.KeyGen();
    auto evalKey = scheme.EvalIntKeyGen(keys.secretKey);
    return IntHarness{std::move(scheme), std::move(keys), std::move(evalKey)};
}

GLIntPlaintext MakePair(std::size_t n, IntMatrix plus, IntMatrix minus) {
    return GLIntPlaintext(GLGeometry(n), 257, std::move(plus), std::move(minus));
}

GLIntCiphertext EncryptPair(const IntHarness& harness, const GLIntPlaintext& plaintext) {
    return harness.scheme.EncryptInt(harness.keys.publicKey, harness.scheme.EncodeInt(plaintext));
}

void ExpectDecryptsTo(const IntHarness& harness, const GLIntCiphertext& ciphertext,
                      const IntMatrix& expectedPlus, const IntMatrix& expectedMinus,
                      const std::string& what) {
    const auto decrypted = harness.scheme.DecryptInt(harness.keys.secretKey, ciphertext);
    EXPECT_EQ(decrypted.GetPlusValues(), expectedPlus) << what << " (+ branch)";
    EXPECT_EQ(decrypted.GetMinusValues(), expectedMinus) << what << " (- branch)";
}

void ExpectRowMetadata(const GLIntCiphertext& ciphertext, uint32_t level, uint32_t noiseScaleDeg,
                       std::size_t towers, const std::string& what) {
    for (const auto& row : ciphertext.GetRows()) {
        EXPECT_EQ(row->GetLevel(), level) << what << " level";
        EXPECT_EQ(row->GetNoiseScaleDeg(), noiseScaleDeg) << what << " noiseScaleDeg";
        EXPECT_EQ(row->GetElements().front().GetNumOfElements(), towers) << what << " towers";
    }
}

std::vector<int64_t> CanonicalSlots(const Plaintext& row, std::size_t count) {
    const auto& packed = row->GetPackedValue();
    EXPECT_GE(packed.size(), count);
    std::vector<int64_t> out(count);
    for (std::size_t index = 0; index < count; ++index) {
        out[index] = Canonical(packed[index]);
    }
    return out;
}

// ===========================================================================
// Parameter surface
// ===========================================================================

TEST(GLInt, WBatchedProductionParameterAndOperationCensus) {
    const auto parameters = GLIntWBatchedParameters::GL128257N32();
    ASSERT_NO_THROW(parameters.Validate());
    EXPECT_TRUE(parameters.IsGL128257N32Geometry());
    EXPECT_EQ(parameters.dimension, 128u);
    EXPECT_EQ(parameters.cyclotomicPrime, 257u);
    EXPECT_EQ(parameters.wGenerator, 3u);
    // Smallest prime of the form k*(4*128*257)+1.  This is a plaintext-codec
    // choice only; it does not authorize a BGV ciphertext modulus chain.
    EXPECT_EQ(parameters.plaintextModulus, 1579009u);
    EXPECT_EQ(parameters.plaintextModulus % (4u * 128u * 257u), 1u);

    const auto census = MakeGLIntWBatchedCensus(parameters);
    EXPECT_EQ(census.phi, 256u);
    EXPECT_EQ(census.rootOrder, 131584u);
    EXPECT_EQ(census.rowRingDimension, 65536u);
    EXPECT_EQ(census.ciphertextRowCount, 128u);
    EXPECT_EQ(census.matrixCount, 512u);  // 2*phi(257), unlike CKKS's 256
    EXPECT_EQ(census.matrixCellCount, 16384u);
    EXPECT_EQ(census.aggregatePlaintextValueCount, 8388608u);
    EXPECT_EQ(census.rowRingDimension * census.ciphertextRowCount,
              census.aggregatePlaintextValueCount);
    EXPECT_EQ(census.nonIdentityRowRotations, 127u);
    EXPECT_EQ(census.nonIdentityColumnRotations, 127u);
    EXPECT_EQ(census.nonIdentityInterMatrixRotations, 255u);
    EXPECT_EQ(census.independentRowBootstrapCount, 128u);
    EXPECT_EQ(census.logicalBigSwitchFamilyCount, 3u);
    EXPECT_EQ(census.logicalSmallSwitchFamilyCount, 1u);

    // These gates are the point of the census: production-sized arithmetic
    // is not silently upgraded from a shape calculation to an execution or
    // security claim.
    EXPECT_FALSE(census.wBatchedValueExecutionImplemented);
    EXPECT_FALSE(census.securityAuthorized);
    EXPECT_FALSE(census.aggregateSerializationImplemented);
    EXPECT_FALSE(census.integerBootstrapImplemented);

    ASSERT_EQ(census.operations.size(), kGLIntOperationCensusSize);
    for (std::size_t index = 0; index < census.operations.size(); ++index) {
        EXPECT_EQ(static_cast<std::size_t>(census.operations[index].operation), index);
        EXPECT_FALSE(census.operations[index].wBatchedValuePathImplemented);
    }
    const auto& encode = census.operations[static_cast<std::size_t>(GLIntOperation::Encode)];
    EXPECT_EQ(encode.wFreeCoverage, GLIntWFreeCoverage::PublicValuePath);
    EXPECT_EQ(encode.consumedLevels, 0u);
    const auto& modSwitch = census.operations[static_cast<std::size_t>(GLIntOperation::ModSwitch)];
    EXPECT_EQ(modSwitch.wFreeCoverage, GLIntWFreeCoverage::InternalOnly);
    EXPECT_EQ(modSwitch.consumedLevels, 1u);
    const auto& interMatrix =
        census.operations[static_cast<std::size_t>(GLIntOperation::InterMatrixRotate)];
    EXPECT_EQ(interMatrix.wFreeCoverage, GLIntWFreeCoverage::NotApplicable);
    EXPECT_EQ(interMatrix.keyRequirements, GLIntKeyWAutomorphism);
    const auto& cipherMatMul =
        census.operations[static_cast<std::size_t>(GLIntOperation::MatrixMultiplyCipher)];
    EXPECT_EQ(cipherMatMul.wFreeCoverage, GLIntWFreeCoverage::PublicValuePath);
    EXPECT_EQ(cipherMatMul.consumedLevels, 1u);
    EXPECT_EQ(cipherMatMul.keyRequirements,
              GLIntKeyBigConjugateK1 | GLIntKeyBigProductK2);
    const auto& bootstrap =
        census.operations[static_cast<std::size_t>(GLIntOperation::BootstrapRows)];
    EXPECT_EQ(bootstrap.wFreeCoverage, GLIntWFreeCoverage::Missing);
    EXPECT_EQ(bootstrap.keyRequirements, GLIntKeyBootstrap);
    const auto& serialization =
        census.operations[static_cast<std::size_t>(GLIntOperation::SerializeAggregate)];
    EXPECT_FALSE(serialization.section4Required);
    EXPECT_EQ(serialization.wFreeCoverage, GLIntWFreeCoverage::Missing);
}

TEST(GLInt, WBatchedParameterCensusValidationAndHistoricalShape) {
    // The old n=256,p=17 paper geometry is representable by the metadata
    // census even though the executable W-free GLGeometry gate remains n=4/8.
    GLIntWBatchedParameters historical;
    historical.dimension           = 256;
    historical.cyclotomicPrime     = 17;
    historical.wGenerator          = 3;
    historical.plaintextModulus    = 87041;  // prime, =1 mod 4*256*17
    historical.multiplicativeDepth = 2;
    historical.nativeRnsWordBits   = 64;
    const auto historicalCensus    = MakeGLIntWBatchedCensus(historical);
    EXPECT_FALSE(historical.IsGL128257N32Geometry());
    EXPECT_EQ(historicalCensus.rootOrder, 17408u);
    EXPECT_EQ(historicalCensus.rowRingDimension, 8192u);
    EXPECT_EQ(historicalCensus.matrixCount, 32u);
    EXPECT_EQ(historicalCensus.matrixCellCount, 65536u);
    EXPECT_EQ(historicalCensus.aggregatePlaintextValueCount, 2097152u);

    auto bad = GLIntWBatchedParameters::GL128257N32(257);
    EXPECT_THROW(bad.Validate(), GLIntParameterError);  // t is not 1 mod 4np
    bad = GLIntWBatchedParameters::GL128257N32(131585);
    EXPECT_THROW(bad.Validate(), GLIntParameterError);  // composite t
    bad = GLIntWBatchedParameters::GL128257N32();
    bad.dimension = 127;
    EXPECT_THROW(bad.Validate(), GLDimensionError);
    bad = GLIntWBatchedParameters::GL128257N32();
    bad.cyclotomicPrime = 15;
    EXPECT_THROW(bad.Validate(), GLIntParameterError);
    bad = GLIntWBatchedParameters::GL128257N32();
    bad.wGenerator = 2;
    EXPECT_THROW(bad.Validate(), GLIntParameterError);
    bad = GLIntWBatchedParameters::GL128257N32();
    bad.multiplicativeDepth = 0;
    EXPECT_THROW(bad.Validate(), GLDepthError);
    bad = GLIntWBatchedParameters::GL128257N32();
    bad.nativeRnsWordBits = 31;
    EXPECT_THROW(bad.Validate(), GLIntParameterError);
}

TEST(GLInt, ParameterSurfacePins) {
    const GLIntSchemelet scheme4(IntParameters(4));
    EXPECT_EQ(scheme4.GetPlaintextModulus(), 257u);
    EXPECT_EQ(scheme4.GetZeta(), 2u);           // minimum primitive 16th root mod 257
    EXPECT_EQ(scheme4.GetGaussianUnit(), 16u);  // I = zeta^n, I^2 = -1 mod 257
    EXPECT_TRUE(scheme4.UsesExactNativeRing());
    EXPECT_EQ(scheme4.GetCryptoContext()->GetRingDimension(), 8u);
    EXPECT_EQ(scheme4.GetCryptoContext()->GetCyclotomicOrder(), 16u);
    EXPECT_EQ(scheme4.GetGeometry().GetDimension(), 4u);

    const GLIntSchemelet scheme8(IntParameters(8));
    EXPECT_EQ(scheme8.GetZeta(), 15u);          // minimum primitive 32nd root mod 257
    EXPECT_EQ(scheme8.GetGaussianUnit(), 16u);
    EXPECT_TRUE(scheme8.UsesExactNativeRing());
    EXPECT_EQ(scheme8.GetCryptoContext()->GetRingDimension(), 16u);

    // t = 17 is legal at n = 4 only (17 = 1 mod 16 but 17 != 1 mod 32); the
    // min-root rule gives zeta = 3, I = 3^4 = 13 mod 17.
    const GLIntSchemelet scheme17(IntParameters(4, 17));
    EXPECT_EQ(scheme17.GetZeta(), 3u);
    EXPECT_EQ(scheme17.GetGaussianUnit(), 13u);
    auto keys17 = scheme17.KeyGen();
    const GLIntPlaintext pair17(GLGeometry(4), 17,
                                IntMatrix{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
                                IntMatrix{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1});
    const auto roundTrip17 = scheme17.DecryptInt(
        keys17.secretKey, scheme17.EncryptInt(keys17.publicKey, scheme17.EncodeInt(pair17)));
    EXPECT_EQ(roundTrip17.GetPlusValues(), pair17.GetPlusValues());
    EXPECT_EQ(roundTrip17.GetMinusValues(), pair17.GetMinusValues());

    EXPECT_THROW((void)GLIntSchemelet(IntParameters(8, 17)), GLIntParameterError);
}

TEST(GLInt, ParameterValidationNegatives) {
    EXPECT_THROW(IntParameters(5).Validate(), GLDimensionError);
    EXPECT_THROW(IntParameters(16).Validate(), GLDimensionError);
    // Every n = 4096 request keeps failing closed.
    EXPECT_THROW(IntParameters(4096).Validate(), GLDimensionError);
    EXPECT_THROW(IntParameters(4, 257, 0).Validate(), GLDepthError);
    // Composite t.
    EXPECT_THROW(IntParameters(4, 15).Validate(), GLIntParameterError);
    // Prime t with t = 3 (mod 4n).
    EXPECT_THROW(IntParameters(4, 19).Validate(), GLIntParameterError);
    EXPECT_THROW(IntParameters(4, 2).Validate(), GLIntParameterError);
    // Out of the toy regime entirely.
    EXPECT_THROW(IntParameters(4, (uint64_t{1} << 32) + 15).Validate(), GLIntParameterError);

    // Plaintext-pair validation.
    EXPECT_THROW((void)GLIntPlaintext(GLGeometry(4), 257, IntMatrix(15, 0), IntMatrix(16, 0)),
                 GLDimensionError);
    EXPECT_THROW((void)GLIntPlaintext(GLGeometry(4), 257, IntMatrix(16, 0), IntMatrix(12, 0)),
                 GLDimensionError);
    EXPECT_THROW((void)GLIntPlaintext(GLGeometry(4), 2, IntMatrix(16, 0), IntMatrix(16, 0)),
                 GLIntParameterError);

    // Values canonicalize into [0, t).
    const GLIntPlaintext canonical(GLGeometry(4), 257, IntMatrix(16, -1), IntMatrix(16, 300));
    EXPECT_EQ(canonical.AtPlus(0, 0), 256);
    EXPECT_EQ(canonical.AtMinus(3, 3), 43);
}

// ===========================================================================
// Codec
// ===========================================================================

TEST(GLInt, EncodeDecodeRoundTripAndPins) {
    const GLIntSchemelet scheme(IntParameters(4));
    const auto pair    = MakePair(4, PinnedUPlus4(), PinnedUMinus4());
    const auto encoded = scheme.EncodeInt(pair);
    ASSERT_EQ(encoded.GetRows().size(), 4u);

    // Pinned encoder slot rows (canonical mod 257; design doc section 12).
    const std::vector<std::vector<int64_t>> pinnedSlots = {
        {129, 1, 1, 129, 137, 14, 150, 31},
        {219, 94, 227, 231, 172, 121, 70, 19},
        {0, 225, 225, 0, 247, 241, 235, 229},
        {122, 153, 120, 119, 43, 223, 146, 69},
    };
    for (std::size_t row = 0; row < 4; ++row) {
        EXPECT_EQ(CanonicalSlots(encoded.GetRows()[row], 8), pinnedSlots[row])
            << "slot row " << row;
    }

    // Pinned coefficient rows: the DCRT tower content mod t pins the whole
    // codec including OpenFHE's pack step at the pinned minimal root.
    const std::vector<std::vector<int64_t>> pinnedCoefficients = {
        {74, 129, 121, 229, 144, 25, 137, 255},
        {112, 56, 111, 74, 250, 126, 113, 228},
        {111, 85, 6, 198, 233, 15, 96, 67},
        {28, 203, 60, 132, 191, 220, 219, 40},
    };
    for (std::size_t row = 0; row < 4; ++row) {
        auto element = encoded.GetRows()[row]->GetElement<DCRTPoly>();
        element.SetFormat(Format::COEFFICIENT);
        const auto& tower = element.GetElementAtIndex(0);
        const auto q      = tower.GetModulus();
        const auto halfQ  = q >> 1;
        std::vector<int64_t> coefficients(8);
        for (std::size_t x = 0; x < 8; ++x) {
            const auto& value = tower[x];
            const int64_t centered = (value > halfQ)
                                         ? -static_cast<int64_t>((q - value).ConvertToInt())
                                         : static_cast<int64_t>(value.ConvertToInt());
            coefficients[x] = Canonical(centered);
        }
        EXPECT_EQ(coefficients, pinnedCoefficients[row]) << "coefficient row " << row;
    }

    const auto decoded = scheme.DecodeInt(encoded);
    EXPECT_EQ(decoded.GetPlusValues(), PinnedUPlus4());
    EXPECT_EQ(decoded.GetMinusValues(), PinnedUMinus4());

    // Transposed-encoding relation at the slot level:
    // EncodeIntTransposed(M) == EncodeInt(M^T per branch).
    const auto encodedT = scheme.EncodeIntTransposed(pair);
    const auto encodedManualT =
        scheme.EncodeInt(MakePair(4, OracleTranspose(PinnedUPlus4(), 4),
                                  OracleTranspose(PinnedUMinus4(), 4)));
    for (std::size_t row = 0; row < 4; ++row) {
        EXPECT_EQ(CanonicalSlots(encodedT.GetRows()[row], 8),
                  CanonicalSlots(encodedManualT.GetRows()[row], 8));
    }
    const auto decodedT = scheme.DecodeIntTransposed(encodedT);
    EXPECT_EQ(decodedT.GetPlusValues(), PinnedUPlus4());
    EXPECT_EQ(decodedT.GetMinusValues(), PinnedUMinus4());

    // n = 8 round trips: deterministic generators plus randomized cases.
    const GLIntSchemelet scheme8(IntParameters(8));
    std::mt19937 rng(20260711);
    const auto deterministic = MakePair(8, GeneratedUPlus8(), GeneratedUMinus(8));
    const auto decoded8      = scheme8.DecodeInt(scheme8.EncodeInt(deterministic));
    EXPECT_EQ(decoded8.GetPlusValues(), deterministic.GetPlusValues());
    EXPECT_EQ(decoded8.GetMinusValues(), deterministic.GetMinusValues());
    for (int trial = 0; trial < 3; ++trial) {
        const auto plus  = RandomMatrix(rng, 8);
        const auto minus = RandomMatrix(rng, 8);
        const auto out   = scheme8.DecodeInt(scheme8.EncodeInt(MakePair(8, plus, minus)));
        EXPECT_EQ(out.GetPlusValues(), plus);
        EXPECT_EQ(out.GetMinusValues(), minus);
    }
}

TEST(GLInt, EncryptDecryptExact) {
    const auto harness = MakeHarness(4);
    const auto pair    = MakePair(4, PinnedUPlus4(), PinnedUMinus4());
    const auto encoded = harness.scheme.EncodeInt(pair);

    // Public-key path; wrapper-ownership gate: n real two-component
    // encryptions under the shared tag, and no cleartext shadow exists.
    const auto ciphertext = harness.scheme.EncryptInt(harness.keys.publicKey, encoded);
    ASSERT_EQ(ciphertext.GetRows().size(), 4u);
    for (const auto& row : ciphertext.GetRows()) {
        ASSERT_TRUE(row != nullptr);
        EXPECT_EQ(row->GetElements().size(), 2u);
        EXPECT_EQ(row->GetEncodingType(), PACKED_ENCODING);
    }
    EXPECT_EQ(ciphertext.GetKeyTag(), harness.keys.publicKey->GetKeyTag());
    ExpectRowMetadata(ciphertext, 0, 1, 3, "fresh encryption");
    ExpectDecryptsTo(harness, ciphertext, PinnedUPlus4(), PinnedUMinus4(), "public round trip");

    // Secret-key path.
    const auto symmetric = harness.scheme.EncryptInt(harness.keys.secretKey, encoded);
    ExpectDecryptsTo(harness, symmetric, PinnedUPlus4(), PinnedUMinus4(), "symmetric round trip");

    // n = 8 randomized round trips.
    const auto harness8 = MakeHarness(8);
    std::mt19937 rng(20260712);
    for (int trial = 0; trial < 3; ++trial) {
        const auto plus  = RandomMatrix(rng, 8);
        const auto minus = RandomMatrix(rng, 8);
        ExpectDecryptsTo(harness8, EncryptPair(harness8, MakePair(8, plus, minus)), plus, minus,
                         "n=8 round trip");
    }
}

// ===========================================================================
// Linear operations
// ===========================================================================

TEST(GLInt, AddSubNegate) {
    const auto harness = MakeHarness(4);
    const auto ctU = EncryptPair(harness, MakePair(4, PinnedUPlus4(), PinnedUMinus4()));
    const auto ctV = EncryptPair(harness, MakePair(4, PinnedVPlus4(), PinnedVMinus4()));

    const auto sum = harness.scheme.AddInt(ctU, ctV);
    // AddInt + branch == contract A+B mod 257.
    ExpectDecryptsTo(harness, sum,
                     IntMatrix{2, 2, 2, 0, 0, 2, 2, 2, 3, 2, 1, 1, 3, 256, 1, 3},
                     IntMatrix{4, 10, 18, 28, 12, 23, 36, 51, 22, 38, 56, 76, 34, 55, 78, 103},
                     "AddInt pinned");
    ExpectRowMetadata(sum, 0, 1, 3, "AddInt");

    ExpectDecryptsTo(harness, harness.scheme.SubInt(ctU, ctV),
                     IntMatrix{0, 2, 255, 255, 0, 0, 4, 255, 1, 255, 1, 1, 256, 256, 256, 1},
                     IntMatrix{255, 2, 4, 4, 249, 254, 0, 1, 245, 251, 255, 0, 243, 250, 255, 1},
                     "SubInt pinned");
    ExpectDecryptsTo(harness, harness.scheme.NegateInt(ctU),
                     IntMatrix{256, 255, 0, 1, 0, 256, 254, 0, 255, 0, 256, 256, 256, 1, 0, 255},
                     IntMatrix{256, 251, 246, 241, 255, 247, 239, 231, 252, 241, 230, 219,
                               247, 233, 219, 205},
                     "NegateInt pinned");

    const auto harness8 = MakeHarness(8);
    std::mt19937 rng(20260713);
    for (int trial = 0; trial < 3; ++trial) {
        const auto up = RandomMatrix(rng, 8), um = RandomMatrix(rng, 8);
        const auto vp = RandomMatrix(rng, 8), vm = RandomMatrix(rng, 8);
        const auto cu = EncryptPair(harness8, MakePair(8, up, um));
        const auto cv = EncryptPair(harness8, MakePair(8, vp, vm));
        ExpectDecryptsTo(harness8, harness8.scheme.AddInt(cu, cv), OracleAdd(up, vp),
                         OracleAdd(um, vm), "n=8 AddInt oracle");
        ExpectDecryptsTo(harness8, harness8.scheme.SubInt(cu, cv), OracleSub(up, vp),
                         OracleSub(um, vm), "n=8 SubInt oracle");
        ExpectDecryptsTo(harness8, harness8.scheme.NegateInt(cu), OracleNegate(up),
                         OracleNegate(um), "n=8 NegateInt oracle");
    }
}

TEST(GLInt, HadamardExact) {
    const auto harness = MakeHarness(4);
    const auto ctU = EncryptPair(harness, MakePair(4, PinnedUPlus4(), PinnedUMinus4()));
    const auto ctV = EncryptPair(harness, MakePair(4, PinnedVPlus4(), PinnedVMinus4()));

    const auto product = harness.scheme.EvalHadamardInt(ctU, ctV);
    // + branch == contract A o B mod 257.
    ExpectDecryptsTo(harness, product,
                     IntMatrix{1, 0, 0, 256, 0, 1, 254, 0, 2, 0, 0, 0, 2, 0, 0, 2},
                     IntMatrix{3, 24, 77, 192, 20, 130, 67, 136, 85, 95, 12, 159, 240, 230, 235, 82},
                     "HadamardInt pinned");
    // Exactly one level consumed; noiseScaleDeg back to 1 after the ModReduce.
    ExpectRowMetadata(product, 1, 1, 2, "HadamardInt");

    const auto harness8 = MakeHarness(8);
    std::mt19937 rng(20260714);
    for (int trial = 0; trial < 3; ++trial) {
        const auto up = RandomMatrix(rng, 8), um = RandomMatrix(rng, 8);
        const auto vp = RandomMatrix(rng, 8), vm = RandomMatrix(rng, 8);
        const auto cu = EncryptPair(harness8, MakePair(8, up, um));
        const auto cv = EncryptPair(harness8, MakePair(8, vp, vm));
        ExpectDecryptsTo(harness8, harness8.scheme.EvalHadamardInt(cu, cv), OracleHadamard(up, vp),
                         OracleHadamard(um, vm), "n=8 HadamardInt oracle");
    }
}

TEST(GLInt, RowRotate) {
    const auto harness = MakeHarness(4);
    const auto ctU = EncryptPair(harness, MakePair(4, PinnedUPlus4(), PinnedUMinus4()));

    const auto rotated = harness.scheme.EvalRowRotateInt(ctU, 1, harness.evalKey);
    // + branch == contract RowRotate(A, 1).
    ExpectDecryptsTo(harness, rotated,
                     IntMatrix{0, 1, 3, 0, 2, 0, 1, 1, 1, 256, 0, 2, 1, 2, 0, 256},
                     IntMatrix{2, 10, 18, 26, 5, 16, 27, 38, 10, 24, 38, 52, 1, 6, 11, 16},
                     "RowRotateInt pinned nu=1");
    ExpectRowMetadata(rotated, 0, 1, 3, "RowRotateInt");
    for (std::size_t nu = 2; nu < 4; ++nu) {
        ExpectDecryptsTo(harness, harness.scheme.EvalRowRotateInt(ctU, nu, harness.evalKey),
                         OracleRowRotate(PinnedUPlus4(), nu, 4),
                         OracleRowRotate(PinnedUMinus4(), nu, 4), "RowRotateInt oracle");
    }
    // Composition: rotate by 1 then 2 equals rotate by 3.
    ExpectDecryptsTo(
        harness,
        harness.scheme.EvalRowRotateInt(harness.scheme.EvalRowRotateInt(ctU, 1, harness.evalKey), 2,
                                        harness.evalKey),
        OracleRowRotate(PinnedUPlus4(), 3, 4), OracleRowRotate(PinnedUMinus4(), 3, 4),
        "RowRotateInt composition");

    const auto harness8 = MakeHarness(8);
    std::mt19937 rng(20260715);
    for (int trial = 0; trial < 3; ++trial) {
        const auto up = RandomMatrix(rng, 8), um = RandomMatrix(rng, 8);
        const auto cu = EncryptPair(harness8, MakePair(8, up, um));
        const std::size_t nu = 1 + (rng() % 7);
        ExpectDecryptsTo(harness8, harness8.scheme.EvalRowRotateInt(cu, nu, harness8.evalKey),
                         OracleRowRotate(up, nu, 8), OracleRowRotate(um, nu, 8),
                         "n=8 RowRotateInt oracle");
    }
}

TEST(GLInt, ColumnRotateKeyless) {
    const auto harness = MakeHarness(4);
    const auto ctU = EncryptPair(harness, MakePair(4, PinnedUPlus4(), PinnedUMinus4()));

    // The signature takes no key material at all: column rotation is a row
    // permutation plus exact monomial units.
    const auto rotated = harness.scheme.EvalColumnRotateInt(ctU, 1);
    // + branch == contract ColRotate(A, 1).
    ExpectDecryptsTo(harness, rotated,
                     IntMatrix{2, 0, 256, 1, 1, 3, 0, 0, 0, 1, 1, 2, 256, 0, 2, 1},
                     IntMatrix{6, 11, 16, 1, 10, 18, 26, 2, 16, 27, 38, 5, 24, 38, 52, 10},
                     "ColumnRotateInt pinned nu=1");
    ExpectRowMetadata(rotated, 0, 1, 3, "ColumnRotateInt");
    for (std::size_t nu = 2; nu < 4; ++nu) {
        ExpectDecryptsTo(harness, harness.scheme.EvalColumnRotateInt(ctU, nu),
                         OracleColumnRotate(PinnedUPlus4(), nu, 4),
                         OracleColumnRotate(PinnedUMinus4(), nu, 4), "ColumnRotateInt oracle");
    }

    const auto harness8 = MakeHarness(8);
    std::mt19937 rng(20260716);
    for (int trial = 0; trial < 3; ++trial) {
        const auto up = RandomMatrix(rng, 8), um = RandomMatrix(rng, 8);
        const auto cu = EncryptPair(harness8, MakePair(8, up, um));
        const std::size_t nu = 1 + (rng() % 7);
        ExpectDecryptsTo(harness8, harness8.scheme.EvalColumnRotateInt(cu, nu),
                         OracleColumnRotate(up, nu, 8), OracleColumnRotate(um, nu, 8),
                         "n=8 ColumnRotateInt oracle");
    }
}

TEST(GLInt, ConjSwap) {
    const auto harness = MakeHarness(4);
    const auto ctU = EncryptPair(harness, MakePair(4, PinnedUPlus4(), PinnedUMinus4()));

    // Section 4.4 conjugation is the pure branch swap (M-, M+): entries are
    // plain Z_t scalars, so no entrywise change occurs.
    const auto swapped = harness.scheme.EvalConjSwapInt(ctU, harness.evalKey);
    ExpectDecryptsTo(harness, swapped, PinnedUMinus4(), PinnedUPlus4(), "ConjSwapInt pinned");
    ExpectRowMetadata(swapped, 0, 1, 3, "ConjSwapInt");
    ExpectDecryptsTo(harness, harness.scheme.EvalConjSwapInt(swapped, harness.evalKey),
                     PinnedUPlus4(), PinnedUMinus4(), "ConjSwapInt involution");

    const auto harness8 = MakeHarness(8);
    std::mt19937 rng(20260717);
    for (int trial = 0; trial < 3; ++trial) {
        const auto up = RandomMatrix(rng, 8), um = RandomMatrix(rng, 8);
        const auto cu = EncryptPair(harness8, MakePair(8, up, um));
        ExpectDecryptsTo(harness8, harness8.scheme.EvalConjSwapInt(cu, harness8.evalKey), um, up,
                         "n=8 ConjSwapInt oracle");
    }
}

TEST(GLInt, TransposeAndConjSwapAdjointIdentity) {
    const auto harness = MakeHarness(4);
    const auto ctU = EncryptPair(harness, MakePair(4, PinnedUPlus4(), PinnedUMinus4()));

    const auto transposed = harness.scheme.EvalTransposeInt(ctU, harness.evalKey);
    // + branch == contract Transpose(A).
    ExpectDecryptsTo(harness, transposed,
                     IntMatrix{1, 0, 2, 1, 2, 1, 0, 256, 0, 3, 1, 0, 256, 0, 1, 2},
                     IntMatrix{1, 2, 5, 10, 6, 10, 16, 24, 11, 18, 27, 38, 16, 26, 38, 52},
                     "TransposeInt pinned");
    ExpectRowMetadata(transposed, 0, 1, 3, "TransposeInt");

    // Exact memory-optimization identity (mod t, no tolerance):
    // TransposeInt == ConjSwapInt(AdjointInt(ct)).
    const auto viaAdjoint = harness.scheme.EvalConjSwapInt(
        harness.scheme.EvalAdjointInt(ctU, harness.evalKey), harness.evalKey);
    const auto left  = harness.scheme.DecryptInt(harness.keys.secretKey, transposed);
    const auto right = harness.scheme.DecryptInt(harness.keys.secretKey, viaAdjoint);
    EXPECT_EQ(left.GetPlusValues(), right.GetPlusValues());
    EXPECT_EQ(left.GetMinusValues(), right.GetMinusValues());

    const auto harness8 = MakeHarness(8);
    std::mt19937 rng(20260718);
    for (int trial = 0; trial < 3; ++trial) {
        const auto up = RandomMatrix(rng, 8), um = RandomMatrix(rng, 8);
        const auto cu = EncryptPair(harness8, MakePair(8, up, um));
        ExpectDecryptsTo(harness8, harness8.scheme.EvalTransposeInt(cu, harness8.evalKey),
                         OracleTranspose(up, 8), OracleTranspose(um, 8), "n=8 TransposeInt oracle");
        const auto id8a = harness8.scheme.DecryptInt(
            harness8.keys.secretKey, harness8.scheme.EvalTransposeInt(cu, harness8.evalKey));
        const auto id8b = harness8.scheme.DecryptInt(
            harness8.keys.secretKey,
            harness8.scheme.EvalConjSwapInt(harness8.scheme.EvalAdjointInt(cu, harness8.evalKey),
                                            harness8.evalKey));
        EXPECT_EQ(id8a.GetPlusValues(), id8b.GetPlusValues());
        EXPECT_EQ(id8a.GetMinusValues(), id8b.GetMinusValues());
    }
}

TEST(GLInt, Adjoint) {
    const auto harness = MakeHarness(4);
    const auto ctU = EncryptPair(harness, MakePair(4, PinnedUPlus4(), PinnedUMinus4()));

    // Adjoint analog decodes to the branch-swapped transposes (U-^T, U+^T).
    const auto adjoint = harness.scheme.EvalAdjointInt(ctU, harness.evalKey);
    ExpectDecryptsTo(harness, adjoint,
                     IntMatrix{1, 2, 5, 10, 6, 10, 16, 24, 11, 18, 27, 38, 16, 26, 38, 52},
                     IntMatrix{1, 0, 2, 1, 2, 1, 0, 256, 0, 3, 1, 0, 256, 0, 1, 2},
                     "AdjointInt pinned");
    ExpectRowMetadata(adjoint, 0, 1, 3, "AdjointInt");

    const auto harness8 = MakeHarness(8);
    std::mt19937 rng(20260719);
    for (int trial = 0; trial < 3; ++trial) {
        const auto up = RandomMatrix(rng, 8), um = RandomMatrix(rng, 8);
        const auto cu = EncryptPair(harness8, MakePair(8, up, um));
        ExpectDecryptsTo(harness8, harness8.scheme.EvalAdjointInt(cu, harness8.evalKey),
                         OracleTranspose(um, 8), OracleTranspose(up, 8), "n=8 AdjointInt oracle");
    }
}

// ===========================================================================
// Products
// ===========================================================================

TEST(GLInt, CircledastPlainAndCipher) {
    const auto harness = MakeHarness(4);
    const auto pairU = MakePair(4, PinnedUPlus4(), PinnedUMinus4());
    const auto pairV = MakePair(4, PinnedVPlus4(), PinnedVMinus4());
    const auto ctU = EncryptPair(harness, pairU);
    const auto ctV = EncryptPair(harness, pairV);

    // Pinned circledast tables with n^{-1} = 193 folded into the value
    // (Theorem 4.1: the trace itself represents n^{-1} P; no explicit factor).
    const IntMatrix circledastPlus{64, 67, 70, 73, 199, 81, 220, 102,
                                   199, 80, 218, 99, 70, 76, 82, 88};
    const IntMatrix circledastMinus{74, 71, 196, 200, 16, 11, 134, 12,
                                    217, 209, 202, 83, 163, 151, 143, 156};

    const auto plainTrace = harness.scheme.EvalCircledastPlainInt(ctU, pairV);
    ExpectDecryptsTo(harness, plainTrace, circledastPlus, circledastMinus,
                     "CircledastPlainInt pinned");
    ExpectRowMetadata(plainTrace, 1, 1, 2, "CircledastPlainInt");

    const auto cipherTrace = harness.scheme.EvalCircledastInt(ctU, ctV, harness.evalKey);
    ExpectDecryptsTo(harness, cipherTrace, circledastPlus, circledastMinus,
                     "CircledastInt pinned");
    ExpectRowMetadata(cipherTrace, 1, 1, 2, "CircledastInt");

    // n = 8 oracle: n^{-1} = 225; decodes to n^{-1} (U+ V-^T, U- V+^T).
    const auto harness8 = MakeHarness(8);
    std::mt19937 rng(20260720);
    for (int trial = 0; trial < 3; ++trial) {
        const auto up = RandomMatrix(rng, 8), um = RandomMatrix(rng, 8);
        const auto vp = RandomMatrix(rng, 8), vm = RandomMatrix(rng, 8);
        const auto pu = MakePair(8, up, um);
        const auto pv = MakePair(8, vp, vm);
        const auto cu = EncryptPair(harness8, pu);
        const auto cv = EncryptPair(harness8, pv);
        const auto expectedPlus  = OracleScale(OracleMatMulBT(up, vm, 8), 225);
        const auto expectedMinus = OracleScale(OracleMatMulBT(um, vp, 8), 225);
        ExpectDecryptsTo(harness8, harness8.scheme.EvalCircledastPlainInt(cu, pv), expectedPlus,
                         expectedMinus, "n=8 CircledastPlainInt oracle");
        ExpectDecryptsTo(harness8, harness8.scheme.EvalCircledastInt(cu, cv, harness8.evalKey),
                         expectedPlus, expectedMinus, "n=8 CircledastInt oracle");
    }
}

TEST(GLInt, MatMulPlainAndCipher) {
    const auto harness = MakeHarness(4);
    const auto pairU = MakePair(4, PinnedUPlus4(), PinnedUMinus4());
    const auto pairV = MakePair(4, PinnedVPlus4(), PinnedVMinus4());
    const auto ctU = EncryptPair(harness, pairU);
    const auto ctV = EncryptPair(harness, pairV);

    // Cross-framework anchor: the + branch must equal the shared contract
    // A*B table [-1 2 -1 4; 3 7 -1 2; 5 2 5 3; 5 -1 5 1] reduced mod 257.
    const IntMatrix contractProduct{256, 2, 256, 4, 3, 7, 256, 2, 5, 2, 5, 3, 5, 256, 5, 1};
    EXPECT_EQ(OracleMatMul(PinnedUPlus4(), PinnedVPlus4(), 4), contractProduct);
    const IntMatrix minusProduct{120, 49, 46, 111, 8, 55, 214, 228,
                                 4, 201, 56, 83, 108, 230, 86, 190};
    EXPECT_EQ(OracleMatMul(PinnedUMinus4(), PinnedVMinus4(), 4), minusProduct);

    const auto plainProduct = harness.scheme.EvalMatMulPlainInt(ctU, pairV);
    ExpectDecryptsTo(harness, plainProduct, contractProduct, minusProduct, "MatMulPlainInt pinned");
    ExpectRowMetadata(plainProduct, 1, 1, 2, "MatMulPlainInt");

    const auto cipherProduct = harness.scheme.EvalMatMulInt(ctU, ctV, harness.evalKey);
    ExpectDecryptsTo(harness, cipherProduct, contractProduct, minusProduct, "MatMulInt pinned");
    ExpectRowMetadata(cipherProduct, 1, 1, 2, "MatMulInt");

    // n = 8: deterministic generators and randomized cases against the
    // in-test triple-loop oracle; decodes to (U+ V+, U- V-).
    const auto harness8 = MakeHarness(8);
    const auto det8U = MakePair(8, GeneratedUPlus8(), GeneratedUMinus(8));
    const auto det8V = MakePair(8, GeneratedVPlus8(), GeneratedVMinus(8));
    const auto ct8U  = EncryptPair(harness8, det8U);
    const auto ct8V  = EncryptPair(harness8, det8V);
    ExpectDecryptsTo(harness8, harness8.scheme.EvalMatMulInt(ct8U, ct8V, harness8.evalKey),
                     OracleMatMul(GeneratedUPlus8(), GeneratedVPlus8(), 8),
                     OracleMatMul(GeneratedUMinus(8), GeneratedVMinus(8), 8),
                     "n=8 MatMulInt deterministic");
    std::mt19937 rng(20260721);
    for (int trial = 0; trial < 3; ++trial) {
        const auto up = RandomMatrix(rng, 8), um = RandomMatrix(rng, 8);
        const auto vp = RandomMatrix(rng, 8), vm = RandomMatrix(rng, 8);
        const auto cu = EncryptPair(harness8, MakePair(8, up, um));
        const auto cv = EncryptPair(harness8, MakePair(8, vp, vm));
        ExpectDecryptsTo(harness8, harness8.scheme.EvalMatMulInt(cu, cv, harness8.evalKey),
                         OracleMatMul(up, vp, 8), OracleMatMul(um, vm, 8), "n=8 MatMulInt oracle");
        ExpectDecryptsTo(harness8, harness8.scheme.EvalMatMulPlainInt(cu, MakePair(8, vp, vm)),
                         OracleMatMul(up, vp, 8), OracleMatMul(um, vm, 8),
                         "n=8 MatMulPlainInt oracle");
    }
}

TEST(GLInt, TransposedEncodingLeftProduct) {
    const auto harness = MakeHarness(4);
    const auto pairU = MakePair(4, PinnedUPlus4(), PinnedUMinus4());
    const auto pairV = MakePair(4, PinnedVPlus4(), PinnedVMinus4());

    // Remark 3.13 analog: under the transposed encoding the SAME EvalMatMulInt
    // computes the LEFT products (V+ U+, V- U-) after the transposed decode.
    const auto ctUT = harness.scheme.EncryptInt(harness.keys.publicKey,
                                                harness.scheme.EncodeIntTransposed(pairU));
    const auto ctVT = harness.scheme.EncryptInt(harness.keys.publicKey,
                                                harness.scheme.EncodeIntTransposed(pairV));
    const auto product = harness.scheme.DecryptInt(
        harness.keys.secretKey, harness.scheme.EvalMatMulInt(ctUT, ctVT, harness.evalKey));
    // DecryptInt returns the transposed-encoding view; transpose both branches
    // (the clear-side DecodeIntTransposed relation).
    const auto leftPlus  = OracleTranspose(product.GetPlusValues(), 4);
    const auto leftMinus = OracleTranspose(product.GetMinusValues(), 4);
    // Tie the library's transposed decode to the ciphertext-path result: the
    // helper applied to a standard re-encode must equal the hand transform.
    const auto viaHelper = harness.scheme.DecodeIntTransposed(harness.scheme.EncodeInt(product));
    EXPECT_EQ(viaHelper.GetPlusValues(), leftPlus);
    EXPECT_EQ(viaHelper.GetMinusValues(), leftMinus);

    // Pinned tables from the design doc.
    EXPECT_EQ(leftPlus, (IntMatrix{6, 1, 2, 3, 0, 256, 2, 3, 1, 4, 6, 256, 5, 3, 1, 1}));
    EXPECT_EQ(leftMinus, (IntMatrix{166, 201, 236, 14, 119, 50, 238, 169, 72, 156, 240, 67,
                                    25, 5, 242, 222}));
    // And the in-test triple-loop expectation (clear left products).
    EXPECT_EQ(leftPlus, OracleMatMul(PinnedVPlus4(), PinnedUPlus4(), 4));
    EXPECT_EQ(leftMinus, OracleMatMul(PinnedVMinus4(), PinnedUMinus4(), 4));

    const auto harness8 = MakeHarness(8);
    std::mt19937 rng(20260722);
    for (int trial = 0; trial < 3; ++trial) {
        const auto up = RandomMatrix(rng, 8), um = RandomMatrix(rng, 8);
        const auto vp = RandomMatrix(rng, 8), vm = RandomMatrix(rng, 8);
        const auto cu = harness8.scheme.EncryptInt(
            harness8.keys.publicKey, harness8.scheme.EncodeIntTransposed(MakePair(8, up, um)));
        const auto cv = harness8.scheme.EncryptInt(
            harness8.keys.publicKey, harness8.scheme.EncodeIntTransposed(MakePair(8, vp, vm)));
        const auto out = harness8.scheme.DecryptInt(
            harness8.keys.secretKey, harness8.scheme.EvalMatMulInt(cu, cv, harness8.evalKey));
        EXPECT_EQ(OracleTranspose(out.GetPlusValues(), 8), OracleMatMul(vp, up, 8));
        EXPECT_EQ(OracleTranspose(out.GetMinusValues(), 8), OracleMatMul(vm, um, 8));
    }
}

TEST(GLInt, HadamardMatMulDepthTwoChain) {
    const auto harness = MakeHarness(4);
    const auto ctU = EncryptPair(harness, MakePair(4, PinnedUPlus4(), PinnedUMinus4()));
    const auto ctV = EncryptPair(harness, MakePair(4, PinnedVPlus4(), PinnedVMinus4()));

    // Deepest supported chain at the default depth 2: Hadamard -> MatMul.
    // Both MatMul operands sit at identical level/degree (FIXEDMANUAL
    // performs no automatic level adjust by design).
    const auto h1 = harness.scheme.EvalHadamardInt(ctU, ctV);
    const auto h2 = harness.scheme.EvalHadamardInt(ctV, ctU);
    const auto chained = harness.scheme.EvalMatMulInt(h1, h2, harness.evalKey);

    const auto hadamardPlus  = OracleHadamard(PinnedUPlus4(), PinnedVPlus4());
    const auto hadamardMinus = OracleHadamard(PinnedUMinus4(), PinnedVMinus4());
    ExpectDecryptsTo(harness, chained, OracleMatMul(hadamardPlus, hadamardPlus, 4),
                     OracleMatMul(hadamardMinus, hadamardMinus, 4), "depth-2 chain exact");
    ExpectRowMetadata(chained, 2, 1, 1, "depth-2 chain");
}

// ===========================================================================
// Negatives
// ===========================================================================

TEST(GLInt, OperandContextAndKeyNegatives) {
    const auto harness = MakeHarness(4);
    const auto pairU = MakePair(4, PinnedUPlus4(), PinnedUMinus4());
    const auto ctU = EncryptPair(harness, pairU);

    // Cross-dimension: an n=8 object fed to the n=4 schemelet.
    const auto harness8 = MakeHarness(8);
    const auto ct8 = EncryptPair(harness8, MakePair(8, GeneratedUPlus8(), GeneratedUMinus(8)));
    EXPECT_THROW((void)harness.scheme.AddInt(ctU, ct8), GLDimensionError);
    EXPECT_THROW((void)harness.scheme.EncodeInt(MakePair(8, GeneratedUPlus8(), GeneratedUMinus(8))),
                 GLDimensionError);
    EXPECT_THROW((void)harness.scheme.EvalMatMulInt(ctU, ctU, harness8.evalKey), GLDimensionError);

    // OpenFHE's context factory DEDUPLICATES: a sibling schemelet with
    // identical BGV parameters receives the identical cached CryptoContext,
    // so its objects interoperate at the framework level and mismatched key
    // material fails closed as a KEY mismatch, not a context mismatch.
    const auto sibling = MakeHarness(4);
    ASSERT_EQ(sibling.scheme.GetCryptoContext().get(), harness.scheme.GetCryptoContext().get());
    const auto ctSibling = EncryptPair(sibling, pairU);
    EXPECT_THROW((void)harness.scheme.AddInt(ctU, ctSibling), GLKeyMismatchError);
    EXPECT_THROW((void)harness.scheme.EvalMatMulInt(ctU, ctU, sibling.evalKey),
                 GLKeyMismatchError);

    // A genuinely different CryptoContext (different multiplicative depth,
    // same geometry and t) exercises the context-mismatch paths.
    const auto other = MakeHarness(4, 3);
    ASSERT_NE(other.scheme.GetCryptoContext().get(), harness.scheme.GetCryptoContext().get());
    const auto ctOther = EncryptPair(other, pairU);
    EXPECT_THROW((void)harness.scheme.AddInt(ctU, ctOther), GLContextMismatchError);
    EXPECT_THROW((void)harness.scheme.EncryptInt(other.keys.publicKey,
                                                 harness.scheme.EncodeInt(pairU)),
                 GLKeyContextMismatchError);
    EXPECT_THROW((void)harness.scheme.DecryptInt(other.keys.secretKey, ctU),
                 GLKeyContextMismatchError);
    EXPECT_THROW((void)harness.scheme.EvalIntKeyGen(other.keys.secretKey),
                 GLKeyContextMismatchError);
    EXPECT_THROW((void)harness.scheme.EvalTransposeInt(ctU, other.evalKey),
                 GLContextMismatchError);

    // Key-tag mismatch inside one context.
    const auto secondKeys = harness.scheme.KeyGen();
    const auto ctSecond   = harness.scheme.EncryptInt(secondKeys.publicKey,
                                                      harness.scheme.EncodeInt(pairU));
    EXPECT_THROW((void)harness.scheme.AddInt(ctU, ctSecond), GLKeyMismatchError);
    EXPECT_THROW((void)harness.scheme.DecryptInt(secondKeys.secretKey, ctU), GLKeyMismatchError);
    EXPECT_THROW((void)harness.scheme.EvalMatMulInt(ctSecond, ctSecond, harness.evalKey),
                 GLKeyMismatchError);
    EXPECT_THROW((void)harness.scheme.EvalRowRotateInt(ctSecond, 1, harness.evalKey),
                 GLKeyMismatchError);

    // Hadamard without EvalIntKeyGen: the second key pair never generated the
    // ambient s^2 relinearization key, so the op fails closed.
    EXPECT_THROW((void)harness.scheme.EvalHadamardInt(ctSecond, ctSecond),
                 GLMissingEvaluationKeyError);

    // Plaintext modulus mismatch fails closed before any encoding happens.
    const GLIntPlaintext pair17(GLGeometry(4), 17, IntMatrix(16, 1), IntMatrix(16, 2));
    EXPECT_THROW((void)harness.scheme.EncodeInt(pair17), GLIntParameterError);
    EXPECT_THROW((void)harness.scheme.EvalCircledastPlainInt(ctU, pair17), GLIntParameterError);

    // Rotation amounts: nu = 0 is the accepted identity (cross-port
    // convention, matching the complex port); nu >= n is out of range;
    // both for the keyed and the keyless rotation.
    ExpectDecryptsTo(harness, harness.scheme.EvalRowRotateInt(ctU, 0, harness.evalKey),
                     PinnedUPlus4(), PinnedUMinus4(), "row-rotate nu=0 identity");
    ExpectDecryptsTo(harness, harness.scheme.EvalColumnRotateInt(ctU, 0),
                     PinnedUPlus4(), PinnedUMinus4(), "column-rotate nu=0 identity");
    EXPECT_THROW((void)harness.scheme.EvalRowRotateInt(ctU, 4, harness.evalKey), GLDimensionError);
    EXPECT_THROW((void)harness.scheme.EvalColumnRotateInt(ctU, 4), GLDimensionError);

    // Aggregate construction: missing row / extra row / foreign row.
    auto shortRows = ctU.GetRows();
    shortRows.pop_back();
    EXPECT_THROW(
        (void)GLIntCiphertext(harness.scheme.GetGeometry(), harness.scheme.GetCryptoContext(),
                              std::move(shortRows)),
        GLMissingRowError);
    auto longRows = ctU.GetRows();
    longRows.push_back(ctU.GetRows().front());
    EXPECT_THROW(
        (void)GLIntCiphertext(harness.scheme.GetGeometry(), harness.scheme.GetCryptoContext(),
                              std::move(longRows)),
        GLDimensionError);
    auto mixedRows = ctU.GetRows();
    mixedRows[1]   = ctOther.GetRows()[1];  // row from the genuinely different context
    EXPECT_THROW(
        (void)GLIntCiphertext(harness.scheme.GetGeometry(), harness.scheme.GetCryptoContext(),
                              std::move(mixedRows)),
        GLContextMismatchError);
    auto taggedRows = ctU.GetRows();
    taggedRows[2]   = ctSecond.GetRows()[2];
    EXPECT_THROW(
        (void)GLIntCiphertext(harness.scheme.GetGeometry(), harness.scheme.GetCryptoContext(),
                              std::move(taggedRows)),
        GLKeyMismatchError);
    auto nullRows = ctU.GetRows();
    nullRows[1]   = nullptr;
    EXPECT_THROW(
        (void)GLIntCiphertext(harness.scheme.GetGeometry(), harness.scheme.GetCryptoContext(),
                              std::move(nullRows)),
        GLMissingRowError);
}

TEST(GLInt, DepthAndLevelNegatives) {
    const auto harness = MakeHarness(4);
    const auto pairU = MakePair(4, PinnedUPlus4(), PinnedUMinus4());
    const auto pairV = MakePair(4, PinnedVPlus4(), PinnedVMinus4());
    const auto ctU = EncryptPair(harness, pairU);
    const auto ctV = EncryptPair(harness, pairV);

    // Exhaust the depth-2 budget: Hadamard (level 1) then MatMul (level 2,
    // one remaining tower).  Every further multiplication-class op fails
    // closed with GLDepthError.
    const auto h1 = harness.scheme.EvalHadamardInt(ctU, ctV);
    const auto h2 = harness.scheme.EvalHadamardInt(ctV, ctU);
    const auto exhausted = harness.scheme.EvalMatMulInt(h1, h2, harness.evalKey);
    ExpectRowMetadata(exhausted, 2, 1, 1, "exhausted chain");
    EXPECT_THROW((void)harness.scheme.EvalHadamardInt(exhausted, exhausted), GLDepthError);
    EXPECT_THROW((void)harness.scheme.EvalCircledastInt(exhausted, exhausted, harness.evalKey),
                 GLDepthError);
    EXPECT_THROW((void)harness.scheme.EvalMatMulInt(exhausted, exhausted, harness.evalKey),
                 GLDepthError);
    EXPECT_THROW((void)harness.scheme.EvalCircledastPlainInt(exhausted, pairV), GLDepthError);
    EXPECT_THROW((void)harness.scheme.EvalMatMulPlainInt(exhausted, pairV), GLDepthError);

    // 0-level operations still work at the exhausted point, exactly.
    ExpectDecryptsTo(harness, harness.scheme.EvalTransposeInt(exhausted, harness.evalKey),
                     OracleTranspose(OracleMatMul(OracleHadamard(PinnedUPlus4(), PinnedVPlus4()),
                                                  OracleHadamard(PinnedUPlus4(), PinnedVPlus4()), 4),
                                     4),
                     OracleTranspose(OracleMatMul(OracleHadamard(PinnedUMinus4(), PinnedVMinus4()),
                                                  OracleHadamard(PinnedUMinus4(), PinnedVMinus4()), 4),
                                     4),
                     "transpose at exhausted depth");

    // Mixed-level operands are rejected: FIXEDMANUAL performs no automatic
    // level adjust, and the strict operand-compatibility validation throws.
    EXPECT_THROW((void)harness.scheme.AddInt(ctU, h1), GLCiphertextError);
    EXPECT_THROW((void)harness.scheme.SubInt(h1, ctU), GLCiphertextError);
    EXPECT_THROW((void)harness.scheme.EvalHadamardInt(ctU, h1), GLCiphertextError);
    EXPECT_THROW((void)harness.scheme.EvalMatMulInt(ctU, h1, harness.evalKey), GLCiphertextError);

    // No transport ring exists in the integer mode: the constructor always
    // yields the exact 2n ring (there is no parameter to request otherwise).
    EXPECT_TRUE(harness.scheme.UsesExactNativeRing());
    EXPECT_EQ(harness.scheme.GetCryptoContext()->GetRingDimension(),
              harness.scheme.GetGeometry().GetNativeRingDimension());
}

}  // namespace
}  // namespace lbcrypto
