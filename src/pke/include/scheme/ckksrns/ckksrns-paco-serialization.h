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

#ifndef LBCRYPTO_CRYPTO_CKKSRNS_PACO_SERIALIZATION_H
#define LBCRYPTO_CRYPTO_CKKSRNS_PACO_SERIALIZATION_H

#include "scheme/ckksrns/ckksrns-paco.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace lbcrypto {

using PaCoKeyDigest = std::array<uint8_t, 32>;

/**
 * Caller-owned lifecycle metadata bound into an authenticated PaCo key
 * manifest. bundleId is a deployment-stable identifier, while generation is
 * monotonically increased when the material is replaced. Timestamps are Unix
 * seconds; zero means "not specified". An expiry requires a creation time.
 */
struct PaCoBootstrapKeyLifecycle {
    std::string bundleId;
    std::string issuer;
    uint64_t generation           = 0;
    uint64_t createdAtUnixSeconds = 0;
    uint64_t expiresAtUnixSeconds = 0;
};

/**
 * Export policy. authenticationKey is never serialized. Version-2 export
 * requires 16 through 64 bytes and emits a 256-bit keyed-BLAKE2b tag over the
 * complete envelope and integrity digest.
 */
struct PaCoBootstrapKeyExportOptions {
    PaCoBootstrapKeyLifecycle lifecycle;
    std::vector<uint8_t> authenticationKey;
};

/**
 * Fail-closed import policy. Version 2 always requires authentication.
 * expectedBundleId and expectedKeyTag are mandatory external trust anchors;
 * minimumGeneration provides rollback protection. Timestamped artifacts
 * require a trusted clock. No legacy or unauthenticated format is accepted.
 */
struct PaCoBootstrapKeyImportOptions {
    std::string expectedBundleId;
    std::string expectedIssuer;
    std::string expectedKeyTag;
    uint64_t minimumGeneration      = 1;
    uint64_t currentTimeUnixSeconds = 0;
    std::vector<uint8_t> authenticationKey;
    uint64_t maxArtifactBytes        = uint64_t{64} * 1024 * 1024 * 1024;
    uint64_t maxEntryBytes           = uint64_t{32} * 1024 * 1024 * 1024;
    uint32_t maxEvaluationKeyEntries = 1U << 20;
};

/** Authenticated v2 descriptor for one restricted HYBRID evaluation key. */
struct PaCoEvaluationKeyManifestEntry {
    uint32_t automorphismIndex = 0;  // zero denotes the multiplication key
    uint32_t minimumLevel      = 0;
    uint32_t activeQTowers     = 0;
    uint32_t pTowers           = 0;
    uint32_t digitCount        = 0;
    uint64_t serializedBytes   = 0;
    PaCoKeyDigest basisDigest{};
    PaCoKeyDigest serializedKeyDigest{};
};

/** Stable manifest returned only after every digest, policy, and key check succeeds. */
struct PaCoBootstrapKeyManifest {
    uint32_t formatVersion        = 0;
    uint32_t payloadFormatVersion = 0;
    std::string producerOpenFHEVersion;
    PaCoBootstrapKeyLifecycle lifecycle;
    PaCoParameters parameters;
    uint32_t ringDimension = 0;
    uint32_t totalTowers   = 0;
    std::string keyTag;
    std::vector<int32_t> rotationIndices;
    std::vector<uint32_t> automorphismIndices;
    std::map<uint32_t, uint32_t> automorphismKeyLevels;
    uint32_t multiplicationKeyLevel = 0;
    std::vector<PaCoEvaluationKeyManifestEntry> automorphismKeyEntries;
    PaCoEvaluationKeyManifestEntry multiplicationKeyEntry;
    PaCoKeyDigest contextFingerprint{};
    PaCoKeyDigest parameterDigest{};
    PaCoKeyDigest automorphismDigest{};
    PaCoKeyDigest payloadDigest{};
    PaCoKeyDigest manifestDigest{};
    bool authenticityVerified = false;
};

struct PaCoBootstrapKeyImportResult {
    PaCoBootstrapKeys keys;
    PaCoBootstrapKeyManifest manifest;
};

/**
 * Versioned PaCo bootstrap-key wire codec.
 *
 * Envelope version 2 is a canonical little-endian format. Every selector
 * ciphertext and evaluation key has a separately bounded OpenFHE
 * portable-binary section. Every restricted HYBRID key has an authenticated
 * descriptor binding its earliest usable ciphertext level, exact Q prefix,
 * complete P basis, digit count, serialized length, and serialized digest.
 * The envelope is stable and independently versioned; compatibility of opaque
 * objects follows OpenFHE's normal serialized-object version rules.
 *
 * The context fingerprint commits to the complete serialized CKKS-RNS crypto
 * parameters and, redundantly, to public security/RNS settings and every Q,
 * P, QP, and public-key-basis tower modulus and root of unity. It deliberately
 * excludes mutable global evaluation-key caches.
 */
class PaCoBootstrapKeySerializer final {
public:
    static constexpr uint32_t FORMAT_VERSION         = 2;
    static constexpr uint32_t PAYLOAD_FORMAT_VERSION = 2;

    static std::vector<uint8_t> Serialize(const CryptoContext<DCRTPoly>& context, const PaCoBootstrapKeys& keys,
                                          const PaCoBootstrapKeyExportOptions& options);

    static PaCoBootstrapKeyImportResult Deserialize(const CryptoContext<DCRTPoly>& context,
                                                    const PaCoParameters& expectedParameters,
                                                    const std::vector<uint8_t>& artifact,
                                                    const PaCoBootstrapKeyImportOptions& options);

    static PaCoKeyDigest ContextFingerprint(const CryptoContext<DCRTPoly>& context);
    static std::string DigestHex(const PaCoKeyDigest& digest);
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_CRYPTO_CKKSRNS_PACO_SERIALIZATION_H
