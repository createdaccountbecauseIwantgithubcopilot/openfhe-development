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

#include "scheme/ckksrns/ckksrns-paco-serialization.h"

#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "utils/prng/blake2.h"
#include "utils/serial.h"
#include "version.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <map>
#include <sstream>
#include <string_view>
#include <utility>

namespace lbcrypto {
namespace {

constexpr std::string_view kEnvelopeMagicV2     = "PACKBK02";
constexpr std::string_view kPayloadMagicV2      = "PACKPL02";
constexpr uint32_t kFlagAuthenticated           = 1U;
constexpr uint32_t kKnownFlags                  = kFlagAuthenticated;
constexpr size_t kDigestBytes                   = 32;
constexpr size_t kMinimumAuthenticationKeyBytes = 16;
constexpr size_t kMaximumAuthenticationKeyBytes = BLAKE2B_KEYBYTES;
constexpr uint32_t kMaximumTextBytes            = 4096;

[[noreturn]] void Fail(const std::string& message) {
    OPENFHE_THROW("PaCo bootstrap-key artifact: " + message);
}

void ValidateAuthenticationKey(const std::vector<uint8_t>& key) {
    if (!key.empty() && (key.size() < kMinimumAuthenticationKeyBytes || key.size() > kMaximumAuthenticationKeyBytes))
        Fail("authentication keys must contain between 16 and 64 bytes");
}

bool SameParameters(const PaCoParameters& lhs, const PaCoParameters& rhs) {
    const auto sameDoubleBits = [](double a, double b) {
        uint64_t aBits = 0;
        uint64_t bBits = 0;
        std::memcpy(&aBits, &a, sizeof(aBits));
        std::memcpy(&bBits, &b, sizeof(bBits));
        return aBits == bBits;
    };
    return lhs.h == rhs.h && lhs.C == rhs.C && lhs.g0 == rhs.g0 && lhs.g1 == rhs.g1 &&
           sameDoubleBits(lhs.numerics.maximumAbsScaledCoefficient, rhs.numerics.maximumAbsScaledCoefficient) &&
           sameDoubleBits(lhs.numerics.maximumNonSmallAngleAbsoluteError,
                          rhs.numerics.maximumNonSmallAngleAbsoluteError) &&
           lhs.numerics.minimumPrecisionBits == rhs.numerics.minimumPrecisionBits &&
           lhs.numerics.maximumActiveTowers == rhs.numerics.maximumActiveTowers;
}

class CanonicalWriter final {
public:
    void Fixed(std::string_view value) {
        m_bytes.insert(m_bytes.end(), value.begin(), value.end());
    }

    void U32(uint32_t value) {
        for (uint32_t shift = 0; shift < 32; shift += 8)
            m_bytes.push_back(static_cast<uint8_t>((value >> shift) & 0xff));
    }

    void U64(uint64_t value) {
        for (uint32_t shift = 0; shift < 64; shift += 8)
            m_bytes.push_back(static_cast<uint8_t>((value >> shift) & 0xff));
    }

    void String(std::string_view value) {
        if (value.size() > std::numeric_limits<uint32_t>::max())
            Fail("string is too large for the envelope");
        U32(static_cast<uint32_t>(value.size()));
        Fixed(value);
    }

    void Digest(const PaCoKeyDigest& digest) {
        m_bytes.insert(m_bytes.end(), digest.begin(), digest.end());
    }

    void Blob(std::string_view value) {
        U64(value.size());
        m_bytes.insert(m_bytes.end(), value.begin(), value.end());
    }

    void Blob(const std::vector<uint8_t>& value) {
        U64(value.size());
        m_bytes.insert(m_bytes.end(), value.begin(), value.end());
    }

    void PatchU64(size_t offset, uint64_t value) {
        if (offset > m_bytes.size() || m_bytes.size() - offset < sizeof(uint64_t))
            Fail("internal envelope-length offset is invalid");
        for (uint32_t shift = 0; shift < 64; shift += 8)
            m_bytes[offset + shift / 8] = static_cast<uint8_t>((value >> shift) & 0xff);
    }

    const std::vector<uint8_t>& Bytes() const noexcept {
        return m_bytes;
    }

    std::vector<uint8_t> Take() {
        return std::move(m_bytes);
    }

private:
    std::vector<uint8_t> m_bytes;
};

struct ByteRange {
    size_t offset = 0;
    size_t size   = 0;
};

class CanonicalReader final {
public:
    explicit CanonicalReader(const std::vector<uint8_t>& bytes)
        : m_bytes(bytes), m_begin(0), m_limit(bytes.size()), m_offset(0) {}

    CanonicalReader(const std::vector<uint8_t>& bytes, ByteRange range)
        : m_bytes(bytes), m_begin(range.offset), m_limit(range.offset + range.size), m_offset(range.offset) {
        if (range.offset > bytes.size() || range.size > bytes.size() - range.offset)
            Fail("reader range lies outside the artifact");
    }

    void RequireFixed(std::string_view expected) {
        Require(expected.size());
        if (!std::equal(expected.begin(), expected.end(), m_bytes.begin() + m_offset))
            Fail("magic value is invalid");
        m_offset += expected.size();
    }

    uint32_t U32() {
        Require(4);
        uint32_t value = 0;
        for (uint32_t shift = 0; shift < 32; shift += 8)
            value |= static_cast<uint32_t>(m_bytes[m_offset++]) << shift;
        return value;
    }

    uint64_t U64() {
        Require(8);
        uint64_t value = 0;
        for (uint32_t shift = 0; shift < 64; shift += 8)
            value |= static_cast<uint64_t>(m_bytes[m_offset++]) << shift;
        return value;
    }

    std::string String(uint32_t maximumBytes = kMaximumTextBytes) {
        const uint32_t length = U32();
        if (length > maximumBytes)
            Fail("string exceeds its format limit");
        Require(length);
        std::string result(reinterpret_cast<const char*>(m_bytes.data() + m_offset), length);
        m_offset += length;
        return result;
    }

    PaCoKeyDigest Digest() {
        Require(kDigestBytes);
        PaCoKeyDigest result{};
        std::copy_n(m_bytes.begin() + m_offset, result.size(), result.begin());
        m_offset += result.size();
        return result;
    }

    ByteRange BlobRange(uint64_t maximumBytes) {
        const uint64_t length = U64();
        if (length > maximumBytes || length > std::numeric_limits<size_t>::max())
            Fail("payload entry exceeds its configured limit");
        Require(static_cast<size_t>(length));
        const ByteRange result{m_offset, static_cast<size_t>(length)};
        m_offset += result.size;
        return result;
    }

    size_t Offset() const noexcept {
        return m_offset;
    }

    size_t Remaining() const noexcept {
        return m_limit - m_offset;
    }

    bool AtEnd() const noexcept {
        return m_offset == m_limit;
    }

private:
    void Require(size_t count) const {
        if (m_offset < m_begin || m_offset > m_limit || count > m_limit - m_offset)
            Fail("artifact is truncated");
    }

    const std::vector<uint8_t>& m_bytes;
    size_t m_begin;
    size_t m_limit;
    size_t m_offset;
};

PaCoKeyDigest Blake2b256(std::string_view domain, const uint8_t* bytes, size_t size,
                         const std::vector<uint8_t>& key = {}) {
    ValidateAuthenticationKey(key);
    blake2b_state state;
    const int initialized = key.empty() ? blake2b_init(&state, kDigestBytes) :
                                          blake2b_init_key(&state, kDigestBytes, key.data(), key.size());
    if (initialized != 0)
        Fail("BLAKE2b initialization failed");

    uint8_t encodedDomainSize[8]{};
    for (uint32_t shift = 0; shift < 64; shift += 8)
        encodedDomainSize[shift / 8] = static_cast<uint8_t>((domain.size() >> shift) & 0xff);
    if (blake2b_update(&state, encodedDomainSize, sizeof(encodedDomainSize)) != 0 ||
        blake2b_update(&state, domain.data(), domain.size()) != 0 ||
        (size != 0 && blake2b_update(&state, bytes, size) != 0))
        Fail("BLAKE2b update failed");

    PaCoKeyDigest result{};
    if (blake2b_final(&state, result.data(), result.size()) != 0)
        Fail("BLAKE2b finalization failed");
    return result;
}

PaCoKeyDigest Blake2b256(std::string_view domain, const std::vector<uint8_t>& bytes,
                         const std::vector<uint8_t>& key = {}) {
    return Blake2b256(domain, bytes.data(), bytes.size(), key);
}

bool ConstantTimeEqual(const PaCoKeyDigest& lhs, const PaCoKeyDigest& rhs) noexcept {
    uint8_t difference = 0;
    for (size_t i = 0; i < lhs.size(); ++i)
        difference |= lhs[i] ^ rhs[i];
    return difference == 0;
}

uint32_t FloatBits(float value) noexcept {
    static_assert(sizeof(float) == sizeof(uint32_t), "PaCo fingerprints require binary32 floats");
    uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}

uint64_t DoubleBits(double value) noexcept {
    static_assert(sizeof(double) == sizeof(uint64_t), "PaCo fingerprints require binary64 doubles");
    static_assert(std::numeric_limits<double>::is_iec559, "PaCo fingerprints require IEEE-754 doubles");
    uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}

template <typename T>
std::string SerializeOpenFHEBinary(const T& value) {
    std::ostringstream stream(std::ios::out | std::ios::binary);
    Serial::Serialize(value, stream, SerType::BINARY);
    return stream.str();
}

template <typename T>
T DeserializeOpenFHEBinary(const std::vector<uint8_t>& artifact, ByteRange range, const char* label) {
    try {
        const std::string bytes(reinterpret_cast<const char*>(artifact.data() + range.offset), range.size);
        std::istringstream stream(bytes, std::ios::in | std::ios::binary);
        T result;
        Serial::Deserialize(result, stream, SerType::BINARY);
        if (stream.peek() != std::char_traits<char>::eof())
            Fail(std::string(label) + " has trailing bytes");
        return result;
    }
    catch (const std::exception& error) {
        Fail(std::string(label) + " deserialization failed: " + error.what());
    }
}

template <typename ParamsPointer>
void AppendBasis(CanonicalWriter& writer, std::string_view label, const ParamsPointer& basis) {
    writer.String(label);
    writer.U32(basis ? 1 : 0);
    if (!basis)
        return;
    writer.U32(basis->GetCyclotomicOrder());
    writer.U32(basis->GetRingDimension());
    const auto& towers = basis->GetParams();
    if (towers.size() > std::numeric_limits<uint32_t>::max())
        Fail("context basis has too many towers");
    writer.U32(static_cast<uint32_t>(towers.size()));
    for (const auto& tower : towers) {
        if (!tower)
            Fail("context basis contains a null tower");
        writer.U32(tower->GetCyclotomicOrder());
        writer.U32(tower->GetRingDimension());
        writer.U64(tower->GetModulus().template ConvertToInt<uint64_t>());
        writer.U64(tower->GetRootOfUnity().template ConvertToInt<uint64_t>());
        writer.U64(tower->GetBigModulus().template ConvertToInt<uint64_t>());
        writer.U64(tower->GetBigRootOfUnity().template ConvertToInt<uint64_t>());
    }
}

struct ExpectedKeyBasis {
    uint32_t minimumLevel  = 0;
    uint32_t activeQTowers = 0;
    uint32_t pTowers       = 0;
    uint32_t digitCount    = 0;
    PaCoKeyDigest digest{};
};

ExpectedKeyBasis MakeExpectedKeyBasis(const CryptoContext<DCRTPoly>& context, uint32_t minimumLevel) {
    const auto parameters = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(context->GetCryptoParameters());
    if (!parameters || !parameters->GetElementParams() || !parameters->GetParamsP())
        Fail("restricted HYBRID key requires complete Q and P parameters");
    const auto& q = parameters->GetElementParams()->GetParams();
    const auto& p = parameters->GetParamsP()->GetParams();
    if (q.empty() || p.empty() || minimumLevel >= q.size())
        Fail("evaluation-key minimum level is outside the Q chain");
    if (parameters->GetNumPerPartQ() == 0 || parameters->GetNumPartQ() == 0)
        Fail("HYBRID decomposition parameters are empty");

    ExpectedKeyBasis result;
    result.minimumLevel  = minimumLevel;
    result.activeQTowers = static_cast<uint32_t>(q.size()) - minimumLevel;
    result.pTowers       = static_cast<uint32_t>(p.size());
    result.digitCount =
        std::min<uint32_t>(parameters->GetNumPartQ(), 1 + (result.activeQTowers - 1) / parameters->GetNumPerPartQ());

    CanonicalWriter writer;
    writer.U32(minimumLevel);
    writer.U32(result.activeQTowers);
    writer.U32(result.pTowers);
    writer.U32(result.digitCount);
    writer.U32(context->GetCyclotomicOrder());
    writer.U32(context->GetRingDimension());
    for (uint32_t i = 0; i < result.activeQTowers; ++i) {
        writer.U64(q[i]->GetModulus().ConvertToInt<uint64_t>());
        writer.U64(q[i]->GetRootOfUnity().ConvertToInt<uint64_t>());
    }
    for (const auto& tower : p) {
        writer.U64(tower->GetModulus().ConvertToInt<uint64_t>());
        writer.U64(tower->GetRootOfUnity().ConvertToInt<uint64_t>());
    }
    result.digest = Blake2b256("OpenFHE/PaCo/restricted-hybrid-basis/v2", writer.Bytes());
    return result;
}

void RequireDescriptorMatchesContext(const CryptoContext<DCRTPoly>& context,
                                     const PaCoEvaluationKeyManifestEntry& entry) {
    const auto expected = MakeExpectedKeyBasis(context, entry.minimumLevel);
    if (entry.activeQTowers != expected.activeQTowers || entry.pTowers != expected.pTowers ||
        entry.digitCount != expected.digitCount || !ConstantTimeEqual(entry.basisDigest, expected.digest))
        Fail("evaluation-key descriptor does not match its declared Q-prefix/P basis");
}

void RequireActualKeyMatchesDescriptor(const CryptoContext<DCRTPoly>& context, std::string_view expectedKeyTag,
                                       const EvalKey<DCRTPoly>& key, const PaCoEvaluationKeyManifestEntry& entry) {
    RequireDescriptorMatchesContext(context, entry);
    if (!key || key->GetCryptoContext() != context || key->GetKeyTag() != expectedKeyTag)
        Fail("evaluation key has the wrong context or key tag");
    const auto parameters = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(context->GetCryptoParameters());
    const auto& q         = parameters->GetElementParams()->GetParams();
    const auto& p         = parameters->GetParamsP()->GetParams();
    const auto& a         = key->GetAVector();
    const auto& b         = key->GetBVector();
    if (a.size() != entry.digitCount || b.size() != entry.digitCount || a.empty())
        Fail("evaluation-key digit count does not match its authenticated descriptor");

    const auto componentMatches = [&](const DCRTPoly& component) {
        if (component.GetFormat() != Format::EVALUATION || !component.GetParams() ||
            component.GetRingDimension() != context->GetRingDimension() ||
            component.GetCyclotomicOrder() != context->GetCyclotomicOrder() ||
            component.GetNumOfElements() != entry.activeQTowers + entry.pTowers)
            return false;
        for (uint32_t i = 0; i < entry.activeQTowers; ++i) {
            const auto& actual = component.GetElementAtIndex(i);
            if (actual.GetModulus() != q[i]->GetModulus() || actual.GetRootOfUnity() != q[i]->GetRootOfUnity())
                return false;
        }
        for (uint32_t i = 0; i < entry.pTowers; ++i) {
            const auto& actual = component.GetElementAtIndex(entry.activeQTowers + i);
            if (actual.GetModulus() != p[i]->GetModulus() || actual.GetRootOfUnity() != p[i]->GetRootOfUnity())
                return false;
        }
        return true;
    };
    if (!std::all_of(a.begin(), a.end(), componentMatches) || !std::all_of(b.begin(), b.end(), componentMatches))
        Fail("evaluation key does not use the exact authenticated Q-prefix/P basis");
}

PaCoEvaluationKeyManifestEntry MakeKeyEntry(const CryptoContext<DCRTPoly>& context, std::string_view keyTag,
                                            uint32_t automorphismIndex, uint32_t minimumLevel,
                                            const EvalKey<DCRTPoly>& key, const std::string& serialized) {
    const auto basis = MakeExpectedKeyBasis(context, minimumLevel);
    PaCoEvaluationKeyManifestEntry entry;
    entry.automorphismIndex   = automorphismIndex;
    entry.minimumLevel        = minimumLevel;
    entry.activeQTowers       = basis.activeQTowers;
    entry.pTowers             = basis.pTowers;
    entry.digitCount          = basis.digitCount;
    entry.serializedBytes     = serialized.size();
    entry.basisDigest         = basis.digest;
    entry.serializedKeyDigest = Blake2b256("OpenFHE/PaCo/evaluation-key-section/v2",
                                           reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());
    RequireActualKeyMatchesDescriptor(context, keyTag, key, entry);
    return entry;
}

void WriteKeyEntry(CanonicalWriter& writer, const PaCoEvaluationKeyManifestEntry& entry) {
    writer.U32(entry.automorphismIndex);
    writer.U32(entry.minimumLevel);
    writer.U32(entry.activeQTowers);
    writer.U32(entry.pTowers);
    writer.U32(entry.digitCount);
    writer.U64(entry.serializedBytes);
    writer.Digest(entry.basisDigest);
    writer.Digest(entry.serializedKeyDigest);
}

PaCoEvaluationKeyManifestEntry ReadKeyEntry(CanonicalReader& reader) {
    PaCoEvaluationKeyManifestEntry entry;
    entry.automorphismIndex   = reader.U32();
    entry.minimumLevel        = reader.U32();
    entry.activeQTowers       = reader.U32();
    entry.pTowers             = reader.U32();
    entry.digitCount          = reader.U32();
    entry.serializedBytes     = reader.U64();
    entry.basisDigest         = reader.Digest();
    entry.serializedKeyDigest = reader.Digest();
    return entry;
}

PaCoKeyDigest ParameterDigestV2(const PaCoKeyDigest& contextFingerprint, const PaCoParameters& parameters,
                                uint32_t ringDimension, uint32_t totalTowers, std::string_view keyTag) {
    CanonicalWriter writer;
    writer.Digest(contextFingerprint);
    writer.U32(parameters.h);
    writer.U32(parameters.C);
    writer.U32(parameters.g0);
    writer.U32(parameters.g1);
    writer.U64(DoubleBits(parameters.numerics.maximumAbsScaledCoefficient));
    writer.U64(DoubleBits(parameters.numerics.maximumNonSmallAngleAbsoluteError));
    writer.U32(parameters.numerics.minimumPrecisionBits);
    writer.U32(parameters.numerics.maximumActiveTowers);
    writer.U32(ringDimension);
    writer.U32(totalTowers);
    writer.String(keyTag);
    return Blake2b256("OpenFHE/PaCo/parameter-manifest/v2", writer.Bytes());
}

PaCoKeyDigest AutomorphismDigestV2(const PaCoBootstrapKeyManifest& manifest) {
    CanonicalWriter writer;
    writer.String(manifest.keyTag);
    writer.U32(static_cast<uint32_t>(manifest.rotationIndices.size()));
    for (const int32_t index : manifest.rotationIndices)
        writer.U32(static_cast<uint32_t>(index));
    writer.U32(static_cast<uint32_t>(manifest.automorphismIndices.size()));
    for (const uint32_t index : manifest.automorphismIndices)
        writer.U32(index);
    writer.U32(static_cast<uint32_t>(manifest.automorphismKeyEntries.size()));
    for (const auto& entry : manifest.automorphismKeyEntries)
        WriteKeyEntry(writer, entry);
    WriteKeyEntry(writer, manifest.multiplicationKeyEntry);
    return Blake2b256("OpenFHE/PaCo/automorphism-manifest/v2", writer.Bytes());
}

PaCoKeyDigest AggregateManifestDigestV2(const PaCoBootstrapKeyManifest& manifest) {
    CanonicalWriter writer;
    writer.U32(PaCoBootstrapKeySerializer::FORMAT_VERSION);
    writer.U32(PaCoBootstrapKeySerializer::PAYLOAD_FORMAT_VERSION);
    writer.String(manifest.producerOpenFHEVersion);
    writer.String(manifest.lifecycle.bundleId);
    writer.String(manifest.lifecycle.issuer);
    writer.U64(manifest.lifecycle.generation);
    writer.U64(manifest.lifecycle.createdAtUnixSeconds);
    writer.U64(manifest.lifecycle.expiresAtUnixSeconds);
    writer.Digest(manifest.contextFingerprint);
    writer.Digest(manifest.parameterDigest);
    writer.Digest(manifest.automorphismDigest);
    writer.Digest(manifest.payloadDigest);
    return Blake2b256("OpenFHE/PaCo/aggregate-manifest/v2", writer.Bytes());
}

void ValidateLifecycle(const PaCoBootstrapKeyLifecycle& lifecycle) {
    if (lifecycle.bundleId.empty() || lifecycle.bundleId.size() > kMaximumTextBytes)
        Fail("bundleId must contain between 1 and 4096 bytes");
    if (lifecycle.issuer.size() > kMaximumTextBytes)
        Fail("issuer exceeds 4096 bytes");
    if (lifecycle.generation == 0)
        Fail("generation must be positive");
    if (lifecycle.expiresAtUnixSeconds != 0 && lifecycle.createdAtUnixSeconds == 0)
        Fail("an expiry requires a creation timestamp");
    if (lifecycle.expiresAtUnixSeconds != 0 && lifecycle.expiresAtUnixSeconds <= lifecycle.createdAtUnixSeconds)
        Fail("expiry must be later than creation");
}

void ValidateImportOptions(const PaCoBootstrapKeyImportOptions& options) {
    if (options.expectedBundleId.empty() || options.expectedBundleId.size() > kMaximumTextBytes)
        Fail("expectedBundleId is mandatory and must not exceed 4096 bytes");
    if (options.expectedIssuer.size() > kMaximumTextBytes)
        Fail("expectedIssuer exceeds 4096 bytes");
    if (options.expectedKeyTag.empty() || options.expectedKeyTag.size() > kMaximumTextBytes)
        Fail("expectedKeyTag is mandatory and must not exceed 4096 bytes");
    if (options.minimumGeneration == 0)
        Fail("minimumGeneration must be positive");
    if (options.maxArtifactBytes == 0 || options.maxEntryBytes == 0 || options.maxEvaluationKeyEntries == 0)
        Fail("artifact, entry, and key-count limits must be positive");
    ValidateAuthenticationKey(options.authenticationKey);
    if (options.authenticationKey.empty())
        Fail("version-2 import requires an authentication key");
}

void ValidateTrustAnchors(const PaCoBootstrapKeyManifest& manifest, const PaCoParameters& expectedParameters,
                          const PaCoBootstrapKeyImportOptions& options) {
    ValidateLifecycle(manifest.lifecycle);
    if (manifest.lifecycle.bundleId != options.expectedBundleId)
        Fail("bundleId does not match the external trust anchor");
    if (!options.expectedIssuer.empty() && manifest.lifecycle.issuer != options.expectedIssuer)
        Fail("issuer does not match the external trust anchor");
    if (manifest.lifecycle.generation < options.minimumGeneration)
        Fail("bundle generation violates rollback policy");
    if (manifest.lifecycle.createdAtUnixSeconds != 0 || manifest.lifecycle.expiresAtUnixSeconds != 0) {
        if (options.currentTimeUnixSeconds == 0)
            Fail("currentTimeUnixSeconds is required for timestamped material");
        if (manifest.lifecycle.createdAtUnixSeconds != 0 &&
            options.currentTimeUnixSeconds < manifest.lifecycle.createdAtUnixSeconds)
            Fail("bundle is not yet valid");
        if (manifest.lifecycle.expiresAtUnixSeconds != 0 &&
            options.currentTimeUnixSeconds >= manifest.lifecycle.expiresAtUnixSeconds)
            Fail("bundle has expired");
    }
    if (manifest.keyTag != options.expectedKeyTag)
        Fail("key tag does not match the external trust anchor");
    if (!SameParameters(manifest.parameters, expectedParameters))
        Fail("PaCo parameters do not match the expected deployment profile");
}

void WriteCommonManifestV2(CanonicalWriter& writer, const PaCoBootstrapKeyManifest& manifest) {
    writer.String(manifest.producerOpenFHEVersion);
    writer.String(manifest.lifecycle.bundleId);
    writer.String(manifest.lifecycle.issuer);
    writer.U64(manifest.lifecycle.generation);
    writer.U64(manifest.lifecycle.createdAtUnixSeconds);
    writer.U64(manifest.lifecycle.expiresAtUnixSeconds);
    writer.U32(manifest.parameters.h);
    writer.U32(manifest.parameters.C);
    writer.U32(manifest.parameters.g0);
    writer.U32(manifest.parameters.g1);
    writer.U64(DoubleBits(manifest.parameters.numerics.maximumAbsScaledCoefficient));
    writer.U64(DoubleBits(manifest.parameters.numerics.maximumNonSmallAngleAbsoluteError));
    writer.U32(manifest.parameters.numerics.minimumPrecisionBits);
    writer.U32(manifest.parameters.numerics.maximumActiveTowers);
    writer.U32(manifest.ringDimension);
    writer.U32(manifest.totalTowers);
    writer.String(manifest.keyTag);
    writer.U32(static_cast<uint32_t>(manifest.rotationIndices.size()));
    for (const int32_t index : manifest.rotationIndices)
        writer.U32(static_cast<uint32_t>(index));
    writer.U32(static_cast<uint32_t>(manifest.automorphismIndices.size()));
    for (const uint32_t index : manifest.automorphismIndices)
        writer.U32(index);
}

void ReadScheduleManifest(CanonicalReader& reader, const CryptoContext<DCRTPoly>& context,
                          const PaCoBootstrapKeyImportOptions& options, PaCoBootstrapKeyManifest& manifest) {
    const uint64_t scheduleLimit = std::min<uint64_t>(options.maxEvaluationKeyEntries,
                                                      uint64_t{4} * std::max<uint32_t>(context->GetRingDimension(), 1));
    const uint32_t rotationCount = reader.U32();
    if (rotationCount > scheduleLimit || rotationCount > reader.Remaining() / sizeof(uint32_t))
        Fail("rotation manifest is implausibly large for the context or artifact");
    manifest.rotationIndices.reserve(rotationCount);
    for (uint32_t i = 0; i < rotationCount; ++i)
        manifest.rotationIndices.push_back(static_cast<int32_t>(reader.U32()));

    const uint32_t automorphismCount = reader.U32();
    if (automorphismCount > scheduleLimit || automorphismCount > reader.Remaining() / sizeof(uint32_t))
        Fail("automorphism manifest is implausibly large for the context or artifact");
    manifest.automorphismIndices.reserve(automorphismCount);
    for (uint32_t i = 0; i < automorphismCount; ++i)
        manifest.automorphismIndices.push_back(reader.U32());
}

void ReadCommonManifestV2(CanonicalReader& reader, const CryptoContext<DCRTPoly>& context,
                          const PaCoBootstrapKeyImportOptions& options, PaCoBootstrapKeyManifest& manifest) {
    manifest.producerOpenFHEVersion         = reader.String(128);
    manifest.lifecycle.bundleId             = reader.String();
    manifest.lifecycle.issuer               = reader.String();
    manifest.lifecycle.generation           = reader.U64();
    manifest.lifecycle.createdAtUnixSeconds = reader.U64();
    manifest.lifecycle.expiresAtUnixSeconds = reader.U64();
    manifest.parameters.h                   = reader.U32();
    manifest.parameters.C                   = reader.U32();
    manifest.parameters.g0                  = reader.U32();
    manifest.parameters.g1                  = reader.U32();
    const uint64_t maxCoefficientBits       = reader.U64();
    const uint64_t maxErrorBits             = reader.U64();
    std::memcpy(&manifest.parameters.numerics.maximumAbsScaledCoefficient, &maxCoefficientBits,
                sizeof(maxCoefficientBits));
    std::memcpy(&manifest.parameters.numerics.maximumNonSmallAngleAbsoluteError, &maxErrorBits, sizeof(maxErrorBits));
    manifest.parameters.numerics.minimumPrecisionBits = reader.U32();
    manifest.parameters.numerics.maximumActiveTowers  = reader.U32();
    manifest.ringDimension                            = reader.U32();
    manifest.totalTowers                              = reader.U32();
    manifest.keyTag                                   = reader.String();
    ReadScheduleManifest(reader, context, options, manifest);
}

struct ParsedTrailer {
    ByteRange payload;
    size_t integrityOffset = 0;
    PaCoKeyDigest integrity{};
    size_t authenticationOffset = 0;
    PaCoKeyDigest authentication{};
};

ParsedTrailer ReadTrailer(CanonicalReader& reader, uint64_t maximumPayloadBytes, bool authenticated) {
    ParsedTrailer result;
    result.payload              = reader.BlobRange(maximumPayloadBytes);
    result.integrityOffset      = reader.Offset();
    result.integrity            = reader.Digest();
    result.authenticationOffset = reader.Offset();
    if (authenticated)
        result.authentication = reader.Digest();
    if (!reader.AtEnd())
        Fail("artifact has trailing bytes");
    return result;
}

void VerifyTrailer(const std::vector<uint8_t>& artifact, const ParsedTrailer& trailer, bool authenticated,
                   bool requireAuthentication, const std::vector<uint8_t>& authenticationKey,
                   std::string_view integrityDomain, std::string_view authenticationDomain) {
    const auto computedIntegrity = Blake2b256(integrityDomain, artifact.data(), trailer.integrityOffset);
    if (!ConstantTimeEqual(trailer.integrity, computedIntegrity))
        Fail("integrity digest mismatch");
    if (requireAuthentication && !authenticated)
        Fail("authenticated envelope is required by this format");
    if (authenticated) {
        if (authenticationKey.empty())
            Fail("artifact is authenticated but no authentication key was supplied");
        const auto computedAuthentication =
            Blake2b256(authenticationDomain, artifact.data(), trailer.authenticationOffset, authenticationKey);
        if (!ConstantTimeEqual(trailer.authentication, computedAuthentication))
            Fail("authentication tag mismatch");
    }
}

void FinishEnvelope(CanonicalWriter& writer, size_t totalLengthOffset, const std::vector<uint8_t>& authenticationKey,
                    std::string_view integrityDomain, std::string_view authenticationDomain) {
    const bool authenticated     = !authenticationKey.empty();
    const uint64_t trailingBytes = kDigestBytes + (authenticated ? kDigestBytes : 0);
    if (writer.Bytes().size() > std::numeric_limits<uint64_t>::max() - trailingBytes)
        Fail("artifact length overflows the envelope");
    writer.PatchU64(totalLengthOffset, writer.Bytes().size() + trailingBytes);
    writer.Digest(Blake2b256(integrityDomain, writer.Bytes()));
    if (authenticated)
        writer.Digest(Blake2b256(authenticationDomain, writer.Bytes(), authenticationKey));
}

void RequireContextAndParameterManifest(const CryptoContext<DCRTPoly>& context,
                                        const PaCoBootstrapKeyManifest& manifest) {
    const auto cryptoParameters = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(context->GetCryptoParameters());
    if (!cryptoParameters || !cryptoParameters->GetElementParams())
        Fail("target context is not CKKS-RNS");
    if (manifest.ringDimension != context->GetRingDimension() ||
        manifest.totalTowers != cryptoParameters->GetElementParams()->GetParams().size())
        Fail("ring dimension or Q-tower count does not match the target context");
    const auto expectedContext = PaCoBootstrapKeySerializer::ContextFingerprint(context);
    if (!ConstantTimeEqual(manifest.contextFingerprint, expectedContext))
        Fail("context fingerprint mismatch");
    const auto expectedParameters = ParameterDigestV2(manifest.contextFingerprint, manifest.parameters,
                                                      manifest.ringDimension, manifest.totalTowers, manifest.keyTag);
    if (!ConstantTimeEqual(manifest.parameterDigest, expectedParameters))
        Fail("parameter-manifest digest mismatch");
}

void ValidateKeyEntryStatic(const CryptoContext<DCRTPoly>& context, const PaCoEvaluationKeyManifestEntry& entry,
                            uint64_t maxEntryBytes) {
    if (entry.serializedBytes == 0 || entry.serializedBytes > maxEntryBytes)
        Fail("evaluation-key serialized length violates import policy");
    RequireDescriptorMatchesContext(context, entry);
}

struct PayloadV2Ranges {
    std::array<ByteRange, 4> selectors;
    std::map<uint32_t, ByteRange> automorphismKeys;
    ByteRange multiplicationKey;
};

PayloadV2Ranges ParsePayloadV2Framing(const std::vector<uint8_t>& artifact, ByteRange payload,
                                      const PaCoBootstrapKeyManifest& manifest,
                                      const PaCoBootstrapKeyImportOptions& options) {
    CanonicalReader reader(artifact, payload);
    reader.RequireFixed(kPayloadMagicV2);
    if (reader.U32() != PaCoBootstrapKeySerializer::PAYLOAD_FORMAT_VERSION)
        Fail("inner portable payload version is unsupported");
    if (reader.U32() != 4)
        Fail("portable payload does not contain exactly four selector ciphertexts");

    PayloadV2Ranges result;
    for (auto& selector : result.selectors)
        selector = reader.BlobRange(options.maxEntryBytes);

    const uint32_t count = reader.U32();
    if (count != manifest.automorphismKeyEntries.size() || count > options.maxEvaluationKeyEntries)
        Fail("portable payload evaluation-key count mismatches its manifest");
    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t index  = reader.U32();
        const uint32_t level  = reader.U32();
        const ByteRange range = reader.BlobRange(options.maxEntryBytes);
        const auto& entry     = manifest.automorphismKeyEntries[i];
        if (index != entry.automorphismIndex || level != entry.minimumLevel || range.size != entry.serializedBytes)
            Fail("portable automorphism-key framing mismatches its authenticated descriptor");
        const auto digest =
            Blake2b256("OpenFHE/PaCo/evaluation-key-section/v2", artifact.data() + range.offset, range.size);
        if (!ConstantTimeEqual(digest, entry.serializedKeyDigest))
            Fail("portable automorphism-key section digest mismatch");
        if (!result.automorphismKeys.emplace(index, range).second)
            Fail("portable payload contains a duplicate automorphism key");
    }

    const uint32_t multiplicationLevel = reader.U32();
    result.multiplicationKey           = reader.BlobRange(options.maxEntryBytes);
    if (multiplicationLevel != manifest.multiplicationKeyEntry.minimumLevel ||
        result.multiplicationKey.size != manifest.multiplicationKeyEntry.serializedBytes)
        Fail("portable multiplication-key framing mismatches its authenticated descriptor");
    const auto multiplicationDigest =
        Blake2b256("OpenFHE/PaCo/evaluation-key-section/v2", artifact.data() + result.multiplicationKey.offset,
                   result.multiplicationKey.size);
    if (!ConstantTimeEqual(multiplicationDigest, manifest.multiplicationKeyEntry.serializedKeyDigest))
        Fail("portable multiplication-key section digest mismatch");
    if (!reader.AtEnd())
        Fail("portable payload has trailing bytes");
    return result;
}

}  // namespace

PaCoKeyDigest PaCoBootstrapKeySerializer::ContextFingerprint(const CryptoContext<DCRTPoly>& context) {
    if (!context)
        Fail("cannot fingerprint a null CryptoContext");
    const auto parameters = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(context->GetCryptoParameters());
    if (!parameters || !parameters->GetElementParams())
        Fail("context does not contain CKKS-RNS crypto parameters");

    CanonicalWriter writer;
    writer.U32(static_cast<uint32_t>(context->getSchemeId()));
    writer.U32(context->GetRingDimension());
    writer.U32(context->GetCyclotomicOrder());
    writer.U32(parameters->GetBatchSize());
    writer.U32(FloatBits(parameters->GetDistributionParameter()));
    writer.U64(DoubleBits(parameters->GetFloodingDistributionParameter()));
    writer.U32(FloatBits(parameters->GetAssuranceMeasure()));
    writer.U64(parameters->GetNoiseScale());
    writer.U32(parameters->GetDigitSize());
    writer.U64(DoubleBits(parameters->GetNoiseEstimate()));
    writer.U32(parameters->GetMultiplicativeDepth());
    writer.U32(parameters->GetMaxRelinSkDeg());
    writer.U32(static_cast<uint32_t>(parameters->GetSecretKeyDist()));
    writer.U32(static_cast<uint32_t>(parameters->GetPREMode()));
    writer.U32(static_cast<uint32_t>(parameters->GetMultipartyMode()));
    writer.U32(static_cast<uint32_t>(parameters->GetExecutionMode()));
    writer.U32(static_cast<uint32_t>(parameters->GetDecryptionNoiseMode()));
    writer.U32(static_cast<uint32_t>(parameters->GetStdLevel()));
    writer.U64(DoubleBits(parameters->GetStatisticalSecurity()));
    writer.U64(DoubleBits(parameters->GetNumAdversarialQueries()));
    writer.U32(parameters->GetThresholdNumOfParties());
    writer.U32(static_cast<uint32_t>(parameters->GetKeySwitchTechnique()));
    writer.U32(static_cast<uint32_t>(parameters->GetScalingTechnique()));
    writer.U32(static_cast<uint32_t>(parameters->GetEncryptionTechnique()));
    writer.U32(static_cast<uint32_t>(parameters->GetMultiplicationTechnique()));
    writer.U32(parameters->GetNumPartQ());
    writer.U32(parameters->GetAuxBits());
    writer.U32(parameters->GetExtraBits());
    writer.U32(parameters->GetCompositeDegree());
    writer.U32(parameters->GetRegisterWordSize());
    writer.U32(static_cast<uint32_t>(parameters->GetMPIntBootCiphertextCompressionLevel()));
    writer.U32(static_cast<uint32_t>(parameters->GetCKKSDataType()));

    AppendBasis(writer, "Q", parameters->GetElementParams());
    AppendBasis(writer, "P", parameters->GetParamsP());
    AppendBasis(writer, "QP", parameters->GetParamsQP());
    AppendBasis(writer, "PK", parameters->GetParamsPK());
    writer.Blob(SerializeOpenFHEBinary(*parameters));
    return Blake2b256("OpenFHE/PaCo/context-fingerprint/v1", writer.Bytes());
}

std::string PaCoBootstrapKeySerializer::DigestHex(const PaCoKeyDigest& digest) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string result(digest.size() * 2, '0');
    for (size_t i = 0; i < digest.size(); ++i) {
        result[2 * i]     = alphabet[digest[i] >> 4];
        result[2 * i + 1] = alphabet[digest[i] & 0x0f];
    }
    return result;
}

namespace {

std::vector<uint8_t> SerializeV2(const CryptoContext<DCRTPoly>& context, const PaCoBootstrapKeys& keys,
                                 const PaCoBootstrapKeyExportOptions& options) {
    if (!context)
        Fail("cannot export from a null CryptoContext");
    ValidateLifecycle(options.lifecycle);
    ValidateAuthenticationKey(options.authenticationKey);
    if (options.authenticationKey.empty())
        Fail("version-2 export requires an authentication key");

    PaCoCKKSRNS verifier(context, keys.parameters);
    verifier.LoadBootstrapKeys(keys);
    const PaCoBootstrapKeys normalized = verifier.GetBootstrapKeys();
    if (normalized.keyTag.size() > kMaximumTextBytes)
        Fail("key tag exceeds 4096 bytes");
    if (normalized.rotationIndices.size() > std::numeric_limits<uint32_t>::max() ||
        normalized.automorphismIndices.size() > std::numeric_limits<uint32_t>::max())
        Fail("automorphism manifest exceeds the version-2 count limit");

    std::array<std::string, 4> selectors;
    for (size_t i = 0; i < selectors.size(); ++i)
        selectors[i] = SerializeOpenFHEBinary(normalized.selectorCiphertexts[i]);

    PaCoBootstrapKeyManifest manifest;
    manifest.formatVersion          = PaCoBootstrapKeySerializer::FORMAT_VERSION;
    manifest.payloadFormatVersion   = PaCoBootstrapKeySerializer::PAYLOAD_FORMAT_VERSION;
    manifest.producerOpenFHEVersion = GetOPENFHEVersion();
    manifest.lifecycle              = options.lifecycle;
    manifest.parameters             = normalized.parameters;
    manifest.ringDimension          = normalized.ringDimension;
    manifest.totalTowers            = normalized.totalTowers;
    manifest.keyTag                 = normalized.keyTag;
    manifest.rotationIndices        = normalized.rotationIndices;
    manifest.automorphismIndices    = normalized.automorphismIndices;
    manifest.automorphismKeyLevels  = normalized.automorphismKeyLevels;
    manifest.multiplicationKeyLevel = normalized.multiplicationKeyLevel;

    std::map<uint32_t, std::string> serializedAutomorphisms;
    manifest.automorphismKeyEntries.reserve(normalized.automorphismIndices.size());
    for (const uint32_t index : normalized.automorphismIndices) {
        const auto keyIt   = normalized.automorphismKeys->find(index);
        const auto levelIt = normalized.automorphismKeyLevels.find(index);
        if (keyIt == normalized.automorphismKeys->end() || levelIt == normalized.automorphismKeyLevels.end())
            Fail("normalized bundle is missing an automorphism key or level");
        auto serialized = SerializeOpenFHEBinary(keyIt->second);
        manifest.automorphismKeyEntries.push_back(
            MakeKeyEntry(context, normalized.keyTag, index, levelIt->second, keyIt->second, serialized));
        serializedAutomorphisms.emplace(index, std::move(serialized));
    }
    const std::string serializedMultiplication = SerializeOpenFHEBinary(normalized.multiplicationKey);
    manifest.multiplicationKeyEntry = MakeKeyEntry(context, normalized.keyTag, 0, normalized.multiplicationKeyLevel,
                                                   normalized.multiplicationKey, serializedMultiplication);

    CanonicalWriter payload;
    payload.Fixed(kPayloadMagicV2);
    payload.U32(PaCoBootstrapKeySerializer::PAYLOAD_FORMAT_VERSION);
    payload.U32(static_cast<uint32_t>(selectors.size()));
    for (const auto& selector : selectors)
        payload.Blob(selector);
    payload.U32(static_cast<uint32_t>(manifest.automorphismKeyEntries.size()));
    for (const auto& entry : manifest.automorphismKeyEntries) {
        payload.U32(entry.automorphismIndex);
        payload.U32(entry.minimumLevel);
        payload.Blob(serializedAutomorphisms.at(entry.automorphismIndex));
    }
    payload.U32(manifest.multiplicationKeyEntry.minimumLevel);
    payload.Blob(serializedMultiplication);

    manifest.contextFingerprint = PaCoBootstrapKeySerializer::ContextFingerprint(context);
    manifest.parameterDigest    = ParameterDigestV2(manifest.contextFingerprint, manifest.parameters,
                                                 manifest.ringDimension, manifest.totalTowers, manifest.keyTag);
    manifest.automorphismDigest = AutomorphismDigestV2(manifest);
    manifest.payloadDigest      = Blake2b256("OpenFHE/PaCo/portable-key-payload/v2", payload.Bytes());
    manifest.manifestDigest     = AggregateManifestDigestV2(manifest);

    CanonicalWriter writer;
    writer.Fixed(kEnvelopeMagicV2);
    writer.U32(PaCoBootstrapKeySerializer::FORMAT_VERSION);
    writer.U32(PaCoBootstrapKeySerializer::PAYLOAD_FORMAT_VERSION);
    writer.U32(kFlagAuthenticated);
    const size_t totalLengthOffset = writer.Bytes().size();
    writer.U64(0);
    WriteCommonManifestV2(writer, manifest);
    writer.U32(static_cast<uint32_t>(manifest.automorphismKeyEntries.size()));
    for (const auto& entry : manifest.automorphismKeyEntries)
        WriteKeyEntry(writer, entry);
    WriteKeyEntry(writer, manifest.multiplicationKeyEntry);
    writer.Digest(manifest.contextFingerprint);
    writer.Digest(manifest.parameterDigest);
    writer.Digest(manifest.automorphismDigest);
    writer.Digest(manifest.payloadDigest);
    writer.Digest(manifest.manifestDigest);
    writer.Blob(payload.Bytes());
    FinishEnvelope(writer, totalLengthOffset, options.authenticationKey, "OpenFHE/PaCo/envelope-integrity/v2",
                   "OpenFHE/PaCo/envelope-authentication/v2");
    return writer.Take();
}

PaCoBootstrapKeyImportResult DeserializeV2(const CryptoContext<DCRTPoly>& context,
                                           const PaCoParameters& expectedParameters,
                                           const std::vector<uint8_t>& artifact,
                                           const PaCoBootstrapKeyImportOptions& options) {
    CanonicalReader reader(artifact);
    reader.RequireFixed(kEnvelopeMagicV2);
    PaCoBootstrapKeyManifest manifest;
    manifest.formatVersion = reader.U32();
    if (manifest.formatVersion != PaCoBootstrapKeySerializer::FORMAT_VERSION)
        Fail("version-2 envelope version is unsupported");
    manifest.payloadFormatVersion = reader.U32();
    if (manifest.payloadFormatVersion != PaCoBootstrapKeySerializer::PAYLOAD_FORMAT_VERSION)
        Fail("version-2 portable payload version is unsupported");
    const uint32_t flags = reader.U32();
    if ((flags & ~kKnownFlags) != 0)
        Fail("envelope contains unknown flags");
    const bool authenticated = (flags & kFlagAuthenticated) != 0;
    if (!authenticated)
        Fail("version-2 artifacts must be authenticated");
    if (reader.U64() != artifact.size())
        Fail("declared artifact length does not match the input");
    ReadCommonManifestV2(reader, context, options, manifest);

    const uint32_t entryCount = reader.U32();
    if (entryCount != manifest.automorphismIndices.size() || entryCount > options.maxEvaluationKeyEntries ||
        entryCount > reader.Remaining() / (5 * sizeof(uint32_t) + sizeof(uint64_t) + 2 * kDigestBytes))
        Fail("evaluation-key descriptor count mismatches the automorphism manifest");
    manifest.automorphismKeyEntries.reserve(entryCount);
    for (uint32_t i = 0; i < entryCount; ++i) {
        auto entry = ReadKeyEntry(reader);
        if (entry.automorphismIndex == 0 || entry.automorphismIndex != manifest.automorphismIndices[i] ||
            !manifest.automorphismKeyLevels.emplace(entry.automorphismIndex, entry.minimumLevel).second)
            Fail("evaluation-key descriptors are unordered, duplicated, or mismatch the automorphism manifest");
        manifest.automorphismKeyEntries.push_back(std::move(entry));
    }
    manifest.multiplicationKeyEntry = ReadKeyEntry(reader);
    if (manifest.multiplicationKeyEntry.automorphismIndex != 0)
        Fail("multiplication-key descriptor has a nonzero automorphism index");
    manifest.multiplicationKeyLevel = manifest.multiplicationKeyEntry.minimumLevel;

    manifest.contextFingerprint = reader.Digest();
    manifest.parameterDigest    = reader.Digest();
    manifest.automorphismDigest = reader.Digest();
    manifest.payloadDigest      = reader.Digest();
    manifest.manifestDigest     = reader.Digest();
    const ParsedTrailer trailer = ReadTrailer(reader, options.maxArtifactBytes, authenticated);

    // Authentication precedes any OpenFHE object decoding. The fields parsed
    // above are only bounded integers, small strings, and fixed-size digests.
    VerifyTrailer(artifact, trailer, authenticated, true, options.authenticationKey,
                  "OpenFHE/PaCo/envelope-integrity/v2", "OpenFHE/PaCo/envelope-authentication/v2");
    manifest.authenticityVerified = true;
    ValidateTrustAnchors(manifest, expectedParameters, options);
    RequireContextAndParameterManifest(context, manifest);

    for (const auto& entry : manifest.automorphismKeyEntries)
        ValidateKeyEntryStatic(context, entry, options.maxEntryBytes);
    ValidateKeyEntryStatic(context, manifest.multiplicationKeyEntry, options.maxEntryBytes);
    const auto expectedAutomorphism = AutomorphismDigestV2(manifest);
    if (!ConstantTimeEqual(manifest.automorphismDigest, expectedAutomorphism))
        Fail("version-2 automorphism-manifest digest mismatch");
    const auto expectedPayload = Blake2b256("OpenFHE/PaCo/portable-key-payload/v2",
                                            artifact.data() + trailer.payload.offset, trailer.payload.size);
    if (!ConstantTimeEqual(manifest.payloadDigest, expectedPayload))
        Fail("version-2 portable payload digest mismatch");
    const auto expectedAggregate = AggregateManifestDigestV2(manifest);
    if (!ConstantTimeEqual(manifest.manifestDigest, expectedAggregate))
        Fail("version-2 aggregate-manifest digest mismatch");

    const PayloadV2Ranges ranges = ParsePayloadV2Framing(artifact, trailer.payload, manifest, options);

    PaCoBootstrapKeys imported;
    imported.formatVersion          = 1;
    imported.parameters             = manifest.parameters;
    imported.ringDimension          = manifest.ringDimension;
    imported.totalTowers            = manifest.totalTowers;
    imported.rotationIndices        = manifest.rotationIndices;
    imported.automorphismIndices    = manifest.automorphismIndices;
    imported.automorphismKeyLevels  = manifest.automorphismKeyLevels;
    imported.multiplicationKeyLevel = manifest.multiplicationKeyLevel;
    imported.keyTag                 = manifest.keyTag;
    for (size_t i = 0; i < ranges.selectors.size(); ++i)
        imported.selectorCiphertexts[i] =
            DeserializeOpenFHEBinary<Ciphertext<DCRTPoly>>(artifact, ranges.selectors[i], "selector ciphertext");

    imported.automorphismKeys = std::make_shared<std::map<uint32_t, EvalKey<DCRTPoly>>>();
    for (size_t i = 0; i < manifest.automorphismKeyEntries.size(); ++i) {
        const auto& entry = manifest.automorphismKeyEntries[i];
        auto key          = DeserializeOpenFHEBinary<EvalKey<DCRTPoly>>(
            artifact, ranges.automorphismKeys.at(entry.automorphismIndex), "automorphism key");
        RequireActualKeyMatchesDescriptor(context, manifest.keyTag, key, entry);
        imported.automorphismKeys->emplace(entry.automorphismIndex, std::move(key));
    }
    imported.multiplicationKey =
        DeserializeOpenFHEBinary<EvalKey<DCRTPoly>>(artifact, ranges.multiplicationKey, "multiplication key");
    RequireActualKeyMatchesDescriptor(context, manifest.keyTag, imported.multiplicationKey,
                                      manifest.multiplicationKeyEntry);

    PaCoCKKSRNS verifier(context, expectedParameters);
    verifier.LoadBootstrapKeys(std::move(imported));
    PaCoBootstrapKeyImportResult result;
    result.keys     = verifier.GetBootstrapKeys();
    result.manifest = std::move(manifest);
    return result;
}

}  // namespace

std::vector<uint8_t> PaCoBootstrapKeySerializer::Serialize(const CryptoContext<DCRTPoly>& context,
                                                           const PaCoBootstrapKeys& keys,
                                                           const PaCoBootstrapKeyExportOptions& options) {
    return SerializeV2(context, keys, options);
}

PaCoBootstrapKeyImportResult PaCoBootstrapKeySerializer::Deserialize(const CryptoContext<DCRTPoly>& context,
                                                                     const PaCoParameters& expectedParameters,
                                                                     const std::vector<uint8_t>& artifact,
                                                                     const PaCoBootstrapKeyImportOptions& options) {
    if (!context)
        Fail("cannot import into a null CryptoContext");
    ValidateImportOptions(options);
    if (artifact.size() < kEnvelopeMagicV2.size() || artifact.size() > options.maxArtifactBytes)
        Fail("artifact is empty, truncated, or exceeds maxArtifactBytes");
    if (std::equal(kEnvelopeMagicV2.begin(), kEnvelopeMagicV2.end(), artifact.begin()))
        return DeserializeV2(context, expectedParameters, artifact, options);
    Fail("envelope magic value is unsupported");
}

}  // namespace lbcrypto
