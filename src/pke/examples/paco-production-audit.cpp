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

// Fail-closed resource and numerical audit for the frozen native PaCo profile.
// Production key generation/evaluation is intentionally impossible without the
// explicit --acknowledge-large-run command-line acknowledgement.  Key generation
// always uses OpenFHE's production PRNG; only the public message fixture is
// deterministic.

#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-paco-numerics.h"
#include "scheme/ckksrns/ckksrns-paco-serialization.h"
#include "scheme/ckksrns/ckksrns-paco.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "utils/parallel.h"
#include "version.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <complex>
#include <cstdlib>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
    #include <sys/resource.h>
#endif

using namespace lbcrypto;

namespace {

constexpr uint32_t kOpenFHE128TernaryMaximumLogQ = 1747;

struct AuditProfile {
    std::string name;
    bool production                                = false;
    uint32_t N                                     = 0;
    uint32_t h                                     = 0;
    uint32_t C                                     = 0;
    uint32_t g0                                    = 0;
    uint32_t g1                                    = 0;
    uint32_t firstModSize                          = 0;
    uint32_t scalingModSize                        = 0;
    uint32_t numLargeDigits                        = 0;
    uint32_t expectedAlpha                         = 0;
    uint32_t expectedQBits                         = 0;
    uint32_t expectedPBits                         = 0;
    uint32_t expectedQPBits                        = 0;
    uint32_t parallelD                             = 0;
    uint32_t parallelKappa                         = 0;
    uint32_t requiredConditionalPrecisionBits      = 0;
    long double admittedNonSmallAngleAbsoluteError = 0.0L;
    double fixtureAmplitude                        = 1.0;
    std::vector<uint64_t> qPrimes;
    std::vector<uint64_t> pPrimes;
};

AuditProfile ProductionProfile() {
    AuditProfile profile{
        "PACO-P128-65536-v1",
        true,
        65536,
        128,
        128,
        3,
        3,
        59,
        50,
        3,
        6,
        910,
        360,
        1270,
        256,
        2,
        14,
        static_cast<long double>(uint64_t{1} << 34),
        512.0,
        {576460752300015617ULL, 1125899935547393ULL, 1125899927027713ULL, 1125899935285249ULL, 1125899930959873ULL,
         1125899941445633ULL, 1125899887312897ULL, 1125899926110209ULL, 1125899911168001ULL, 1125899924275201ULL,
         1125899915231233ULL, 1125899922702337ULL, 1125899915886593ULL, 1125899921391617ULL, 1125899902124033ULL,
         1125899913527297ULL, 1125899903827969ULL, 1125899908022273ULL},
        {1152921504606584833ULL, 1152921504598720513ULL, 1152921504597016577ULL, 1152921504595968001ULL,
         1152921504592822273ULL, 1152921504592429057ULL},
    };
    return profile;
}

AuditProfile SmokeProfile() {
    return {
        "PACO-SMOKE-64-v1",
        false,
        64,
        2,
        4,
        2,
        1,
        45,
        35,
        2,
        5,
        361,
        240,
        601,
        8,
        2,
        12,
        static_cast<long double>(uint64_t{1} << 20),
        1.0,
        {35184372088321ULL, 34359751553ULL, 34359735937ULL, 34359749761ULL, 34359736193ULL, 34359748481ULL,
         34359742337ULL, 34359746689ULL, 34359736577ULL, 34359740801ULL},
        {1152921504606844417ULL, 1152921504606844289ULL, 1152921504606842753ULL, 1152921504606837377ULL},
    };
}

struct Options {
    AuditProfile profile                   = SmokeProfile();
    std::string phase                      = "all";
    bool acknowledgedLargeRun              = false;
    bool measureAuthenticatedSerialization = false;
    uint32_t maxConcurrency                = 2;
    uint32_t openfheThreads                = 0;
};

struct PhaseMeasurement {
    double wallSeconds         = 0.0;
    double cpuSeconds          = 0.0;
    uint64_t peakRssBytesAfter = 0;
};

struct BasisStats {
    uint32_t qTowers  = 0;
    uint32_t pTowers  = 0;
    uint32_t qpTowers = 0;
    uint32_t qBits    = 0;
    uint32_t pBits    = 0;
    uint32_t qpBits   = 0;
    std::vector<uint64_t> qPrimes;
    std::vector<uint64_t> pPrimes;
};

struct StorageStats {
    uint64_t dcrtPolynomials       = 0;
    uint64_t residueCoefficients   = 0;
    uint64_t coefficientBytes64Bit = 0;
    uint32_t minTotalTowers        = std::numeric_limits<uint32_t>::max();
    uint32_t maxTotalTowers        = 0;
    uint32_t minQTowers            = std::numeric_limits<uint32_t>::max();
    uint32_t maxQTowers            = 0;
    uint32_t minPTowers            = std::numeric_limits<uint32_t>::max();
    uint32_t maxPTowers            = 0;

    void NormalizeEmpty() {
        if (dcrtPolynomials == 0) {
            minTotalTowers = 0;
            minQTowers     = 0;
            minPTowers     = 0;
        }
    }
};

struct ErrorStats {
    double maximum               = 0.0;
    double mean                  = 0.0;
    double absolutePrecisionBits = std::numeric_limits<double>::infinity();
};

struct CoefficientObservation {
    bool ran                                   = false;
    long double maximumAbsEncodedCoefficient   = 0.0L;
    long double maximumAbsDecryptedCoefficient = 0.0L;
    long double maximumAbsPolynomialError      = 0.0L;
    bool boundPassed                           = false;
};

struct EvalReport {
    bool ran = false;
    ErrorStats versusPrebootstrap;
    ErrorStats versusFixture;
    uint32_t outputLevel  = 0;
    uint32_t outputTowers = 0;
    double outputScale    = 0.0;
    std::vector<std::complex<double>> decodedSample;
};

struct ParallelReport {
    bool ran = false;
    ErrorStats serialBranchesVersusPrebootstrap;
    ErrorStats concurrentBranchesVersusPrebootstrap;
    ErrorStats serialVersusConcurrent;
    double wallSpeedup = 0.0;
    uint32_t D         = 0;
    uint32_t kappa     = 0;
};

struct SerializationReport {
    bool requested            = false;
    bool authenticityVerified = false;
    uint64_t artifactBytes    = 0;
    std::string contextFingerprint;
    std::string manifestDigest;
    std::string payloadDigest;
};

struct AuditReport {
    std::string status = "failed";
    std::string error;
    Options options;
    bool profileDriftGatePassed                = false;
    bool ordinarySecurityEnvelopePassed        = false;
    bool conditionalNumericalImplicationPassed = false;
    paco::detail::PaCoNumericalBudget numericalBudget;
    BasisStats basis;
    std::map<std::string, PhaseMeasurement> phases;
    bool keyMaterialMeasured          = false;
    uint32_t rotations                = 0;
    uint32_t automorphisms            = 0;
    uint32_t automorphismLevelEntries = 0;
    uint32_t multiplicationKeyLevel   = 0;
    StorageStats selectorStorage;
    StorageStats automorphismStorage;
    StorageStats multiplicationStorage;
    StorageStats totalEvaluatorStorage;
    SerializationReport serialization;
    CoefficientObservation sequentialInput;
    CoefficientObservation sequentialOutput;
    CoefficientObservation parallelInput;
    CoefficientObservation parallelSerialOutput;
    CoefficientObservation parallelConcurrentOutput;
    EvalReport sequential;
    ParallelReport parallel;
    uint64_t finalPeakRssBytes = 0;
};

uint64_t PeakRssBytes() {
#if defined(__linux__)
    // getrusage(2)'s ru_maxrss survives execve on Linux and can therefore be
    // contaminated by a heavy launcher. /proc reports this process image's
    // memory high-water mark and is stable under direct or wrapped execution.
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("VmHWM:", 0) != 0)
            continue;
        std::istringstream value(line.substr(6));
        uint64_t kibibytes = 0;
        std::string unit;
        if (value >> kibibytes >> unit && unit == "kB")
            return kibibytes * 1024;
        return 0;
    }
    return 0;
#elif defined(__APPLE__)
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) != 0)
        return 0;
    return static_cast<uint64_t>(usage.ru_maxrss);
#else
    return 0;
#endif
}

template <typename Function>
void Measure(AuditReport& report, const std::string& name, Function&& function) {
    std::cerr << "PaCo audit phase: " << name << "\n";
    const auto wallStart        = std::chrono::steady_clock::now();
    const std::clock_t cpuStart = std::clock();
    function();
    const std::clock_t cpuEnd = std::clock();
    const auto wallEnd        = std::chrono::steady_clock::now();
    report.phases[name]       = {
        std::chrono::duration<double>(wallEnd - wallStart).count(),
        static_cast<double>(cpuEnd - cpuStart) / CLOCKS_PER_SEC,
        PeakRssBytes(),
    };
}

std::string JsonEscape(const std::string& value) {
    std::ostringstream output;
    for (const unsigned char byte : value) {
        switch (byte) {
            case '"':
                output << "\\\"";
                break;
            case '\\':
                output << "\\\\";
                break;
            case '\b':
                output << "\\b";
                break;
            case '\f':
                output << "\\f";
                break;
            case '\n':
                output << "\\n";
                break;
            case '\r':
                output << "\\r";
                break;
            case '\t':
                output << "\\t";
                break;
            default:
                if (byte < 0x20)
                    output << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(byte)
                           << std::dec;
                else
                    output << static_cast<char>(byte);
        }
    }
    return output.str();
}

std::string JsonNumber(double value) {
    if (!std::isfinite(value))
        return "null";
    std::ostringstream output;
    output << std::setprecision(17) << value;
    return output.str();
}

uint32_t ParsePositiveU32(const std::string& text, const char* label) {
    size_t consumed            = 0;
    const unsigned long parsed = std::stoul(text, &consumed, 10);
    if (consumed != text.size() || parsed == 0 || parsed > std::numeric_limits<uint32_t>::max())
        throw std::invalid_argument(std::string(label) + " must be a positive uint32");
    return static_cast<uint32_t>(parsed);
}

void PrintUsage() {
    std::cerr << "Usage: paco-production-audit [--profile=smoke|production] "
                 "[--phase=context|keys|sequential|parallel|all]\n"
              << "       [--max-concurrency=N] [--openfhe-threads=N] "
                 "[--measure-authenticated-serialization] [--acknowledge-large-run]\n";
}

void ParseOptions(int argc, char** argv, Options& options) {
    for (int i = 1; i < argc; ++i) {
        const std::string argument(argv[i]);
        if (argument == "--help" || argument == "-h") {
            PrintUsage();
            std::exit(0);
        }
        if (argument == "--acknowledge-large-run") {
            options.acknowledgedLargeRun = true;
            continue;
        }
        if (argument == "--measure-authenticated-serialization") {
            options.measureAuthenticatedSerialization = true;
            continue;
        }
        if (argument.rfind("--profile=", 0) == 0) {
            const auto value = argument.substr(std::string("--profile=").size());
            if (value == "smoke")
                options.profile = SmokeProfile();
            else if (value == "production")
                options.profile = ProductionProfile();
            else
                throw std::invalid_argument("--profile must be smoke or production");
            continue;
        }
        if (argument.rfind("--phase=", 0) == 0) {
            options.phase = argument.substr(std::string("--phase=").size());
            if (options.phase != "context" && options.phase != "keys" && options.phase != "sequential" &&
                options.phase != "parallel" && options.phase != "all")
                throw std::invalid_argument("unsupported --phase value");
            continue;
        }
        if (argument.rfind("--max-concurrency=", 0) == 0) {
            options.maxConcurrency =
                ParsePositiveU32(argument.substr(std::string("--max-concurrency=").size()), "--max-concurrency");
            continue;
        }
        if (argument.rfind("--openfhe-threads=", 0) == 0) {
            options.openfheThreads =
                ParsePositiveU32(argument.substr(std::string("--openfhe-threads=").size()), "--openfhe-threads");
            continue;
        }
        throw std::invalid_argument("unknown argument: " + argument);
    }
    if (options.maxConcurrency > options.profile.parallelKappa)
        throw std::invalid_argument("--max-concurrency exceeds the frozen parallel kappa");
    if (options.openfheThreads > 256)
        throw std::invalid_argument("--openfhe-threads exceeds the audit hard limit of 256");
    if (options.profile.production && options.phase != "context" && !options.acknowledgedLargeRun)
        throw std::invalid_argument(
            "production key generation/evaluation requires --acknowledge-large-run; context-only does not");
    if (options.measureAuthenticatedSerialization && options.phase == "context")
        throw std::invalid_argument("authenticated serialization requires a key-producing phase");
}

bool NeedsKeys(const Options& options) {
    return options.phase != "context";
}

bool NeedsSequential(const Options& options) {
    return options.phase == "sequential" || options.phase == "all";
}

bool NeedsParallel(const Options& options) {
    return options.phase == "parallel" || options.phase == "all";
}

CryptoContext<DCRTPoly> MakeContext(const AuditProfile& profile) {
    const PaCoParameters paco{profile.h, profile.C, profile.g0, profile.g1};
    paco.Validate(profile.N);

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(profile.production ? HEStd_128_classic : HEStd_NotSet);
    parameters.SetRingDim(profile.N);
    parameters.SetBatchSize(profile.N / 2);
    parameters.SetSecretKeyDist(UNIFORM_TERNARY);
    parameters.SetStandardDeviation(3.19F);
    parameters.SetCKKSDataType(COMPLEX);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
    parameters.SetScalingModSize(profile.scalingModSize);
    parameters.SetFirstModSize(profile.firstModSize);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetNumLargeDigits(profile.numLargeDigits);
    parameters.SetMultiplicativeDepth(paco.MultiplicativeDepth() + 2);

    auto context = GenCryptoContext(parameters);
    context->Enable(PKE);
    context->Enable(KEYSWITCH);
    context->Enable(LEVELEDSHE);
    context->Enable(ADVANCEDSHE);
    context->Enable(FHE);
    return context;
}

PaCoParameters MakeEvaluatorParameters(const AuditProfile& profile, const CryptoContext<DCRTPoly>& context) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(context->GetCryptoParameters());
    if (!cryptoParams)
        throw std::runtime_error("cannot derive PaCo numerical policy from a non-CKKS-RNS context");
    PaCoParameters parameters{profile.h, profile.C, profile.g0, profile.g1};
    parameters.numerics = {cryptoParams->GetScalingFactorReal(0),
                           static_cast<double>(profile.admittedNonSmallAngleAbsoluteError),
                           profile.requiredConditionalPrecisionBits,
                           /*maximumActiveTowers=*/1};
    parameters.Validate(profile.N);
    return parameters;
}

std::vector<uint64_t> PrimeVector(const std::shared_ptr<ILDCRTParams<BigInteger>>& params) {
    if (!params)
        throw std::runtime_error("missing DCRT basis");
    std::vector<uint64_t> result;
    result.reserve(params->GetParams().size());
    for (const auto& tower : params->GetParams())
        result.push_back(tower->GetModulus().ConvertToInt());
    return result;
}

void ValidateFrozenContext(AuditReport& report, const CryptoContext<DCRTPoly>& context) {
    const auto& profile     = report.options.profile;
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(context->GetCryptoParameters());
    if (!cryptoParams)
        throw std::runtime_error("context is not CKKS-RNS");
    const auto qParams  = cryptoParams->GetElementParams();
    const auto pParams  = cryptoParams->GetParamsP();
    const auto qpParams = cryptoParams->GetParamsQP();
    if (context->GetRingDimension() != profile.N || PrimeVector(qParams) != profile.qPrimes ||
        PrimeVector(pParams) != profile.pPrimes || qParams->GetModulus().GetMSB() != profile.expectedQBits ||
        pParams->GetModulus().GetMSB() != profile.expectedPBits ||
        qpParams->GetModulus().GetMSB() != profile.expectedQPBits ||
        cryptoParams->GetNumPartQ() != profile.numLargeDigits ||
        cryptoParams->GetNumPerPartQ() != profile.expectedAlpha || cryptoParams->GetDistributionParameter() != 3.19F ||
        cryptoParams->GetKeySwitchTechnique() != HYBRID || cryptoParams->GetScalingTechnique() != FLEXIBLEAUTO ||
        cryptoParams->GetCompositeDegree() != 1 || context->GetCKKSDataType() != COMPLEX)
        throw std::runtime_error("OpenFHE context drifted from the frozen audit profile");

    const SecurityLevel expectedSecurity = profile.production ? HEStd_128_classic : HEStd_NotSet;
    if (cryptoParams->GetStdLevel() != expectedSecurity)
        throw std::runtime_error("security-level metadata drifted from the frozen audit profile");

    report.basis                          = {static_cast<uint32_t>(qParams->GetParams().size()),
                    static_cast<uint32_t>(pParams->GetParams().size()),
                    static_cast<uint32_t>(qpParams->GetParams().size()),
                    qParams->GetModulus().GetMSB(),
                    pParams->GetModulus().GetMSB(),
                    qpParams->GetModulus().GetMSB(),
                    PrimeVector(qParams),
                    PrimeVector(pParams)};
    report.profileDriftGatePassed         = true;
    report.ordinarySecurityEnvelopePassed = !profile.production || report.basis.qpBits <= kOpenFHE128TernaryMaximumLogQ;
    if (!report.ordinarySecurityEnvelopePassed)
        throw std::runtime_error("actual QP exceeds the frozen HEStd_128_classic ternary envelope");

    const long double maximumCoefficient = cryptoParams->GetScalingFactorReal(0);
    report.numericalBudget =
        paco::detail::AnalyzeNumericalBudget(BigInteger(qParams->GetParams().front()->GetModulus().ConvertToInt()),
                                             maximumCoefficient, profile.admittedNonSmallAngleAbsoluteError);
    paco::detail::RequireNumericalBudget(report.numericalBudget, profile.requiredConditionalPrecisionBits);
    report.conditionalNumericalImplicationPassed = true;
}

void AddPoly(StorageStats& stats, const DCRTPoly& polynomial, const std::set<uint64_t>& qModuli,
             const std::set<uint64_t>& pModuli) {
    uint32_t qTowers = 0;
    uint32_t pTowers = 0;
    for (uint32_t i = 0; i < polynomial.GetNumOfElements(); ++i) {
        const uint64_t modulus = polynomial.GetElementAtIndex(i).GetModulus().ConvertToInt();
        if (qModuli.count(modulus))
            ++qTowers;
        else if (pModuli.count(modulus))
            ++pTowers;
        else
            throw std::runtime_error("evaluation material contains a tower outside frozen Q/P");
    }
    const uint32_t total = polynomial.GetNumOfElements();
    if (qTowers + pTowers != total)
        throw std::runtime_error("could not classify all evaluation-key towers");
    ++stats.dcrtPolynomials;
    const uint64_t residues = static_cast<uint64_t>(polynomial.GetLength()) * total;
    stats.residueCoefficients += residues;
    stats.coefficientBytes64Bit += residues * sizeof(uint64_t);
    stats.minTotalTowers = std::min(stats.minTotalTowers, total);
    stats.maxTotalTowers = std::max(stats.maxTotalTowers, total);
    stats.minQTowers     = std::min(stats.minQTowers, qTowers);
    stats.maxQTowers     = std::max(stats.maxQTowers, qTowers);
    stats.minPTowers     = std::min(stats.minPTowers, pTowers);
    stats.maxPTowers     = std::max(stats.maxPTowers, pTowers);
}

void AddEvalKey(StorageStats& stats, const EvalKey<DCRTPoly>& key, const std::set<uint64_t>& qModuli,
                const std::set<uint64_t>& pModuli) {
    if (!key)
        throw std::runtime_error("evaluator bundle contains a null evaluation key");
    for (const auto& polynomial : key->GetAVector())
        AddPoly(stats, polynomial, qModuli, pModuli);
    for (const auto& polynomial : key->GetBVector())
        AddPoly(stats, polynomial, qModuli, pModuli);
}

void MergeStorage(StorageStats& destination, const StorageStats& source) {
    if (source.dcrtPolynomials == 0)
        return;
    destination.dcrtPolynomials += source.dcrtPolynomials;
    destination.residueCoefficients += source.residueCoefficients;
    destination.coefficientBytes64Bit += source.coefficientBytes64Bit;
    destination.minTotalTowers = std::min(destination.minTotalTowers, source.minTotalTowers);
    destination.maxTotalTowers = std::max(destination.maxTotalTowers, source.maxTotalTowers);
    destination.minQTowers     = std::min(destination.minQTowers, source.minQTowers);
    destination.maxQTowers     = std::max(destination.maxQTowers, source.maxQTowers);
    destination.minPTowers     = std::min(destination.minPTowers, source.minPTowers);
    destination.maxPTowers     = std::max(destination.maxPTowers, source.maxPTowers);
}

void MeasureEvaluatorStorage(AuditReport& report, const CryptoContext<DCRTPoly>& context,
                             const PaCoBootstrapKeys& keys) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(context->GetCryptoParameters());
    std::set<uint64_t> qModuli;
    std::set<uint64_t> pModuli;
    for (const auto& tower : cryptoParams->GetElementParams()->GetParams())
        qModuli.insert(tower->GetModulus().ConvertToInt());
    for (const auto& tower : cryptoParams->GetParamsP()->GetParams())
        pModuli.insert(tower->GetModulus().ConvertToInt());

    for (const auto& ciphertext : keys.selectorCiphertexts) {
        if (!ciphertext)
            throw std::runtime_error("evaluator bundle contains a null selector ciphertext");
        for (const auto& polynomial : ciphertext->GetElements())
            AddPoly(report.selectorStorage, polynomial, qModuli, pModuli);
    }
    if (!keys.automorphismKeys)
        throw std::runtime_error("evaluator bundle has no automorphism key map");
    for (const auto& [index, key] : *keys.automorphismKeys) {
        (void)index;
        AddEvalKey(report.automorphismStorage, key, qModuli, pModuli);
    }
    AddEvalKey(report.multiplicationStorage, keys.multiplicationKey, qModuli, pModuli);
    report.selectorStorage.NormalizeEmpty();
    report.automorphismStorage.NormalizeEmpty();
    report.multiplicationStorage.NormalizeEmpty();
    MergeStorage(report.totalEvaluatorStorage, report.selectorStorage);
    MergeStorage(report.totalEvaluatorStorage, report.automorphismStorage);
    MergeStorage(report.totalEvaluatorStorage, report.multiplicationStorage);
    report.totalEvaluatorStorage.NormalizeEmpty();
    report.rotations                = keys.rotationIndices.size();
    report.automorphisms            = keys.automorphismIndices.size();
    report.automorphismLevelEntries = keys.automorphismKeyLevels.size();
    report.multiplicationKeyLevel   = keys.multiplicationKeyLevel;
    report.keyMaterialMeasured      = true;
}

std::vector<std::complex<double>> DeterministicFixture(uint32_t slots, double amplitude) {
    if (!std::isfinite(amplitude) || amplitude <= 0.0)
        throw std::runtime_error("fixture amplitude must be finite and positive");
    std::vector<std::complex<double>> fixture(slots);
    for (uint32_t i = 0; i < slots; ++i) {
        const int32_t realNumerator = static_cast<int32_t>((17 * i + 3) % 23) - 11;
        const int32_t imagNumerator = static_cast<int32_t>((29 * i + 7) % 19) - 9;
        fixture[i]                  = amplitude * std::complex<double>(static_cast<double>(realNumerator) / 2048.0,
                                                      static_cast<double>(imagNumerator) / 4096.0);
    }
    return fixture;
}

std::vector<std::complex<double>> RepeatToAmbient(const std::vector<std::complex<double>>& values,
                                                  uint32_t ambientSlots) {
    if (values.empty() || ambientSlots % values.size() != 0)
        throw std::runtime_error("fixture slot count does not divide the ambient CKKS slots");
    std::vector<std::complex<double>> ambient(ambientSlots);
    for (uint32_t i = 0; i < ambientSlots; ++i)
        ambient[i] = values[i % values.size()];
    return ambient;
}

std::vector<std::complex<double>> DecryptLogical(const CryptoContext<DCRTPoly>& context,
                                                 const PrivateKey<DCRTPoly>& secretKey,
                                                 ConstCiphertext<DCRTPoly> ciphertext, uint32_t logicalSlots) {
    Plaintext plaintext;
    const auto result = context->Decrypt(secretKey, ciphertext, &plaintext);
    if (!result.isValid || !plaintext)
        throw std::runtime_error("audit decryption failed");
    plaintext->SetLength(logicalSlots);
    auto values = plaintext->GetCKKSPackedValue();
    if (values.size() < logicalSlots)
        throw std::runtime_error("audit decryption returned too few slots");
    values.resize(logicalSlots);
    return values;
}

struct PreparedInput {
    Ciphertext<DCRTPoly> ciphertext;
    std::vector<std::complex<double>> fixture;
    std::vector<std::complex<double>> prebootstrap;
    CoefficientObservation coefficients;
};

long double CenteredMagnitude(const BigInteger& value, const BigInteger& modulus) {
    const BigInteger reduced = value.Mod(modulus);
    const BigInteger half    = modulus >> 1;
    return (reduced > half ? modulus - reduced : reduced).ConvertToLongDouble();
}

CoefficientObservation ObserveRawCoefficients(const CryptoContext<DCRTPoly>& context,
                                              const PrivateKey<DCRTPoly>& secretKey,
                                              ConstCiphertext<DCRTPoly> ciphertext, DCRTPoly encodedPlaintext) {
    if (!ciphertext || ciphertext->GetElements().empty())
        throw std::runtime_error("cannot inspect an empty audit input");
    const uint32_t activeTowers = ciphertext->GetElements().front().GetNumOfElements();
    if (activeTowers == 0 || encodedPlaintext.GetNumOfElements() < activeTowers)
        throw std::runtime_error("encoded audit input does not contain the active ciphertext basis");
    if (encodedPlaintext.GetNumOfElements() > activeTowers)
        encodedPlaintext.DropLastElements(encodedPlaintext.GetNumOfElements() - activeTowers);
    const auto encoded = paco::detail::InterpolateActiveQ(std::move(encodedPlaintext));

    Poly decrypted;
    const auto result = context->GetScheme()->Decrypt(ciphertext, secretKey, &decrypted);
    if (!result.isValid || decrypted.GetLength() != encoded.GetLength() ||
        decrypted.GetModulus() != encoded.GetModulus())
        throw std::runtime_error("raw audit decryption did not preserve the encoded polynomial basis");
    if (decrypted.GetFormat() != Format::COEFFICIENT)
        decrypted.SetFormat(Format::COEFFICIENT);

    CoefficientObservation observation;
    observation.ran          = true;
    const BigInteger modulus = encoded.GetModulus();
    for (uint32_t i = 0; i < encoded.GetLength(); ++i) {
        observation.maximumAbsEncodedCoefficient =
            std::max(observation.maximumAbsEncodedCoefficient, CenteredMagnitude(encoded[i], modulus));
        observation.maximumAbsDecryptedCoefficient =
            std::max(observation.maximumAbsDecryptedCoefficient, CenteredMagnitude(decrypted[i], modulus));
        const BigInteger error =
            paco::detail::AddModulo(decrypted[i], paco::detail::NegateModulo(encoded[i], modulus), modulus);
        observation.maximumAbsPolynomialError =
            std::max(observation.maximumAbsPolynomialError, CenteredMagnitude(error, modulus));
    }
    return observation;
}

CoefficientObservation ObserveOutputCoefficients(const CryptoContext<DCRTPoly>& context,
                                                 const PrivateKey<DCRTPoly>& secretKey,
                                                 ConstCiphertext<DCRTPoly> ciphertext,
                                                 const std::vector<std::complex<double>>& logicalFixture,
                                                 const paco::detail::PaCoNumericalBudget& budget) {
    const auto ambient = RepeatToAmbient(logicalFixture, context->GetRingDimension() / 2);
    auto plaintext     = context->MakeCKKSPackedPlaintext(ambient, 1, 0, nullptr, context->GetRingDimension() / 2);
    if (!plaintext)
        throw std::runtime_error("audit output oracle encoding failed");
    auto observation        = ObserveRawCoefficients(context, secretKey, ciphertext, plaintext->GetElement<DCRTPoly>());
    observation.boundPassed = observation.maximumAbsDecryptedCoefficient <= budget.maximumAbsCoefficient &&
                              observation.maximumAbsPolynomialError <= budget.totalAbsoluteErrorBound;
    if (!observation.boundPassed)
        throw std::runtime_error("raw audit output exceeds the conditional total polynomial-error bound");
    return observation;
}

PreparedInput PrepareInput(const CryptoContext<DCRTPoly>& context, const PaCoKeyMaterial& owner,
                           const AuditProfile& profile, uint32_t logicalSlots) {
    PreparedInput result;
    result.fixture     = DeterministicFixture(logicalSlots, profile.fixtureAmplitude);
    const auto ambient = RepeatToAmbient(result.fixture, context->GetRingDimension() / 2);
    auto plaintext     = context->MakeCKKSPackedPlaintext(ambient, 1, 0, nullptr, context->GetRingDimension() / 2);
    if (!plaintext)
        throw std::runtime_error("audit input encoding failed");
    DCRTPoly encodedPlaintext = plaintext->GetElement<DCRTPoly>();
    result.ciphertext         = context->Encrypt(owner.keyPair.publicKey, plaintext);
    result.ciphertext         = context->Compress(result.ciphertext, 1);
    if (!result.ciphertext || result.ciphertext->GetElements().empty() ||
        result.ciphertext->GetElements().front().GetNumOfElements() != 1)
        throw std::runtime_error("audit input did not reach the one-tower PaCo boundary");
    result.coefficients =
        ObserveRawCoefficients(context, owner.keyPair.secretKey, result.ciphertext, std::move(encodedPlaintext));
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(context->GetCryptoParameters());
    if (!cryptoParams)
        throw std::runtime_error("cannot inspect coefficients for a non-CKKS-RNS context");
    result.coefficients.boundPassed =
        result.coefficients.maximumAbsDecryptedCoefficient <= cryptoParams->GetScalingFactorReal(0) &&
        result.coefficients.maximumAbsPolynomialError <= profile.admittedNonSmallAngleAbsoluteError;
    if (!result.coefficients.boundPassed)
        throw std::runtime_error("raw audit input exceeds the frozen coefficient or incoming-error admission bound");
    result.prebootstrap = DecryptLogical(context, owner.keyPair.secretKey, result.ciphertext, logicalSlots);
    return result;
}

ErrorStats Compare(const std::vector<std::complex<double>>& expected, const std::vector<std::complex<double>>& actual) {
    if (expected.size() != actual.size() || expected.empty())
        throw std::runtime_error("cannot compare mismatched or empty audit vectors");
    ErrorStats result;
    long double total = 0.0L;
    for (size_t i = 0; i < expected.size(); ++i) {
        const double error = std::abs(expected[i] - actual[i]);
        result.maximum     = std::max(result.maximum, error);
        total += error;
    }
    result.mean = static_cast<double>(total / expected.size());
    if (result.maximum != 0.0)
        result.absolutePrecisionBits = -std::log2(result.maximum);
    return result;
}

double HeuristicDecodedErrorGate(const paco::detail::PaCoNumericalBudget& budget) {
    const long double gate = budget.totalAbsoluteErrorBound / budget.maximumAbsCoefficient;
    if (!std::isfinite(gate) || gate <= 0.0L || gate > static_cast<long double>(std::numeric_limits<double>::max()))
        throw std::runtime_error("conditional numerical allowance does not define a finite decoded-error gate");
    return static_cast<double>(gate);
}

void RequireDecodedErrorHeuristic(const paco::detail::PaCoNumericalBudget& budget, const ErrorStats& error,
                                  const char* label) {
    const double empiricalMaximumError = HeuristicDecodedErrorGate(budget);
    if (!std::isfinite(error.maximum) || !std::isfinite(error.mean) || error.maximum > empiricalMaximumError) {
        std::ostringstream message;
        message << label << " maximum error " << error.maximum << " exceeds frozen gate " << empiricalMaximumError
                << " derived from totalAbsoluteErrorBound/maximumAbsCoefficient";
        throw std::runtime_error(message.str());
    }
}

void FillOutputMetadata(EvalReport& report, ConstCiphertext<DCRTPoly> ciphertext) {
    report.outputLevel  = ciphertext->GetLevel();
    report.outputTowers = ciphertext->GetElements().empty() ? 0 : ciphertext->GetElements().front().GetNumOfElements();
    report.outputScale  = ciphertext->GetScalingFactor();
}

std::vector<uint8_t> AuditAuthenticationKey() {
    // Measurement-only trust anchor. It is never written to the artifact or
    // presented as a deployment secret.
    std::vector<uint8_t> key(32);
    for (uint32_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<uint8_t>(0xA5U ^ (17U * i));
    return key;
}

void MeasureSerialization(AuditReport& report, const CryptoContext<DCRTPoly>& context, const PaCoBootstrapKeys& keys) {
    report.serialization.requested = true;
    auto authenticationKey         = AuditAuthenticationKey();
    PaCoBootstrapKeyExportOptions exportOptions;
    exportOptions.lifecycle.bundleId   = report.options.profile.name + "-audit";
    exportOptions.lifecycle.issuer     = "openfhe-paco-production-audit";
    exportOptions.lifecycle.generation = 1;
    exportOptions.authenticationKey    = authenticationKey;

    std::vector<uint8_t> artifact;
    Measure(report, "authenticated_serialize",
            [&] { artifact = PaCoBootstrapKeySerializer::Serialize(context, keys, exportOptions); });
    report.serialization.artifactBytes = artifact.size();

    PaCoBootstrapKeyImportOptions importOptions;
    importOptions.expectedBundleId  = exportOptions.lifecycle.bundleId;
    importOptions.expectedIssuer    = exportOptions.lifecycle.issuer;
    importOptions.expectedKeyTag    = keys.keyTag;
    importOptions.minimumGeneration = 1;
    importOptions.authenticationKey = authenticationKey;
    importOptions.maxArtifactBytes  = artifact.size();
    Measure(report, "authenticated_deserialize", [&] {
        auto imported = PaCoBootstrapKeySerializer::Deserialize(context, keys.parameters, artifact, importOptions);
        if (!imported.manifest.authenticityVerified)
            throw std::runtime_error("authenticated artifact import did not verify authenticity");
        report.serialization.authenticityVerified = true;
        report.serialization.contextFingerprint =
            PaCoBootstrapKeySerializer::DigestHex(imported.manifest.contextFingerprint);
        report.serialization.manifestDigest = PaCoBootstrapKeySerializer::DigestHex(imported.manifest.manifestDigest);
        report.serialization.payloadDigest  = PaCoBootstrapKeySerializer::DigestHex(imported.manifest.payloadDigest);
    });
    // Best-effort overwrite of every live vector copy held by this measurement
    // harness. std::vector is not a secure-memory container, so deployments
    // still need an operating-system-backed secret-management facility.
    std::fill(authenticationKey.begin(), authenticationKey.end(), 0);
    std::fill(exportOptions.authenticationKey.begin(), exportOptions.authenticationKey.end(), 0);
    std::fill(importOptions.authenticationKey.begin(), importOptions.authenticationKey.end(), 0);
}

void PrintStorage(std::ostream& output, const StorageStats& stats) {
    const bool empty = stats.dcrtPolynomials == 0;
    output << "{\"dcrt_polynomials\":" << stats.dcrtPolynomials
           << ",\"residue_coefficients\":" << stats.residueCoefficients
           << ",\"coefficient_bytes_64bit\":" << stats.coefficientBytes64Bit
           << ",\"tower_counts\":{\"total_min\":" << (empty ? 0 : stats.minTotalTowers)
           << ",\"total_max\":" << stats.maxTotalTowers << ",\"q_min\":" << (empty ? 0 : stats.minQTowers)
           << ",\"q_max\":" << stats.maxQTowers << ",\"p_min\":" << (empty ? 0 : stats.minPTowers)
           << ",\"p_max\":" << stats.maxPTowers << "}}";
}

void PrintError(std::ostream& output, const ErrorStats& error) {
    output << "{\"max_abs\":" << JsonNumber(error.maximum) << ",\"mean_abs\":" << JsonNumber(error.mean)
           << ",\"absolute_precision_bits\":" << JsonNumber(error.absolutePrecisionBits) << '}';
}

void PrintComplexSample(std::ostream& output, const std::vector<std::complex<double>>& sample) {
    output << '[';
    for (size_t i = 0; i < sample.size(); ++i) {
        if (i != 0)
            output << ',';
        output << "[" << JsonNumber(sample[i].real()) << ',' << JsonNumber(sample[i].imag()) << ']';
    }
    output << ']';
}

void PrintU64Array(std::ostream& output, const std::vector<uint64_t>& values) {
    output << '[';
    for (size_t i = 0; i < values.size(); ++i) {
        if (i != 0)
            output << ',';
        output << values[i];
    }
    output << ']';
}

void PrintCoefficientObservation(std::ostream& output, const CoefficientObservation& observation) {
    output << "{\"ran\":" << (observation.ran ? "true" : "false") << ",\"maximum_abs_encoded_coefficient\":"
           << JsonNumber(static_cast<double>(observation.maximumAbsEncodedCoefficient))
           << ",\"maximum_abs_decrypted_coefficient\":"
           << JsonNumber(static_cast<double>(observation.maximumAbsDecryptedCoefficient))
           << ",\"maximum_abs_polynomial_error\":"
           << JsonNumber(static_cast<double>(observation.maximumAbsPolynomialError))
           << ",\"bound_passed\":" << (observation.boundPassed ? "true" : "false") << '}';
}

void PrintReport(const AuditReport& report) {
    const auto& profile = report.options.profile;
    std::ostringstream output;
    output << std::setprecision(17);
    output << "{\n  \"schema\":\"openfhe-paco-production-audit-v1\",\n"
           << "  \"status\":\"" << JsonEscape(report.status) << "\",\n"
           << "  \"evidence_only\":true,\n"
           << "  \"error\":" << (report.error.empty() ? "null" : "\"" + JsonEscape(report.error) + "\"") << ",\n"
           << "  \"openfhe_version\":\"" << JsonEscape(GetOPENFHEVersion()) << "\",\n"
           << "  \"profile\":{\"name\":\"" << JsonEscape(profile.name)
           << "\",\"production\":" << (profile.production ? "true" : "false") << ",\"N\":" << profile.N
           << ",\"h\":" << profile.h << ",\"C\":" << profile.C << ",\"g0\":" << profile.g0 << ",\"g1\":" << profile.g1
           << ",\"paco_depth\":" << PaCoParameters{profile.h, profile.C, profile.g0, profile.g1}.MultiplicativeDepth()
           << ",\"context_depth\":"
           << PaCoParameters{profile.h, profile.C, profile.g0, profile.g1}.MultiplicativeDepth() + 2
           << ",\"fixture_amplitude\":" << JsonNumber(profile.fixtureAmplitude) << "},\n"
           << "  \"request\":{\"phase\":\"" << JsonEscape(report.options.phase)
           << "\",\"acknowledged_large_run\":" << (report.options.acknowledgedLargeRun ? "true" : "false")
           << ",\"max_concurrency\":" << report.options.maxConcurrency
           << ",\"openfhe_threads\":" << report.options.openfheThreads << ",\"authenticated_serialization\":"
           << (report.options.measureAuthenticatedSerialization ? "true" : "false") << "},\n"
           << "  \"gates\":{\"profile_drift\":" << (report.profileDriftGatePassed ? "true" : "false")
           << ",\"ordinary_security_envelope\":" << (report.ordinarySecurityEnvelopePassed ? "true" : "false")
           << ",\"conditional_numerical_implication\":"
           << (report.conditionalNumericalImplicationPassed ? "true" : "false")
           << ",\"end_to_end_non_small_angle_bound_proved_by_harness\":false},\n"
           << "  \"basis\":{\"q_towers\":" << report.basis.qTowers << ",\"p_towers\":" << report.basis.pTowers
           << ",\"qp_towers\":" << report.basis.qpTowers << ",\"q_bits\":" << report.basis.qBits
           << ",\"p_bits\":" << report.basis.pBits << ",\"qp_bits\":" << report.basis.qpBits << ",\"q_primes\":";
    PrintU64Array(output, report.basis.qPrimes);
    output << ",\"p_primes\":";
    PrintU64Array(output, report.basis.pPrimes);
    output << "},\n  \"numerical_budget\":{\"contract\":\"conditional_on_external_non_small_angle_bound\""
           << ",\"modulus_bits\":" << report.numericalBudget.modulusBits << ",\"max_abs_coefficient\":"
           << JsonNumber(static_cast<double>(report.numericalBudget.maximumAbsCoefficient))
           << ",\"max_non_small_angle_absolute_error\":"
           << JsonNumber(static_cast<double>(report.numericalBudget.maximumNonSmallAngleAbsoluteError))
           << ",\"phase_argument_bound\":" << JsonNumber(static_cast<double>(report.numericalBudget.phaseArgumentBound))
           << ",\"small_angle_error_bound\":"
           << JsonNumber(static_cast<double>(report.numericalBudget.smallAngleErrorBound)) << ",\"total_error_bound\":"
           << JsonNumber(static_cast<double>(report.numericalBudget.totalAbsoluteErrorBound))
           << ",\"conditional_precision_bits\":"
           << JsonNumber(static_cast<double>(report.numericalBudget.conditionalPrecisionBits))
           << ",\"required_conditional_precision_bits\":" << profile.requiredConditionalPrecisionBits
           << ",\"heuristic_decoded_error_gate\":" << JsonNumber(HeuristicDecodedErrorGate(report.numericalBudget))
           << ",\"avoids_modular_wrap\":" << (report.numericalBudget.avoidsModularWrap ? "true" : "false")
           << "},\n  \"fixture_polynomial_observations\":{\"sequential_input\":";
    PrintCoefficientObservation(output, report.sequentialInput);
    output << ",\"sequential_output\":";
    PrintCoefficientObservation(output, report.sequentialOutput);
    output << ",\"parallel_input\":";
    PrintCoefficientObservation(output, report.parallelInput);
    output << ",\"parallel_serial_output\":";
    PrintCoefficientObservation(output, report.parallelSerialOutput);
    output << ",\"parallel_concurrent_output\":";
    PrintCoefficientObservation(output, report.parallelConcurrentOutput);
    output << "},\n  \"phases\":{";
    bool first = true;
    for (const auto& [name, measurement] : report.phases) {
        if (!first)
            output << ',';
        first = false;
        output << "\"" << JsonEscape(name) << "\":{\"wall_seconds\":" << measurement.wallSeconds
               << ",\"cpu_seconds\":" << measurement.cpuSeconds
               << ",\"peak_rss_bytes_after\":" << measurement.peakRssBytesAfter << '}';
    }
    output << "},\n  \"evaluator_material\":{\"measured\":" << (report.keyMaterialMeasured ? "true" : "false")
           << ",\"rotation_count\":" << report.rotations << ",\"automorphism_count\":" << report.automorphisms
           << ",\"automorphism_level_entries\":" << report.automorphismLevelEntries
           << ",\"multiplication_key_level\":" << report.multiplicationKeyLevel << ",\"selectors\":";
    PrintStorage(output, report.selectorStorage);
    output << ",\"automorphism_keys\":";
    PrintStorage(output, report.automorphismStorage);
    output << ",\"multiplication_key\":";
    PrintStorage(output, report.multiplicationStorage);
    output << ",\"total\":";
    PrintStorage(output, report.totalEvaluatorStorage);
    output << "},\n  \"serialization\":{\"requested\":" << (report.serialization.requested ? "true" : "false")
           << ",\"authenticated\":" << (report.serialization.authenticityVerified ? "true" : "false")
           << ",\"artifact_bytes\":" << report.serialization.artifactBytes << ",\"context_fingerprint\":"
           << (report.serialization.contextFingerprint.empty() ? "null" :
                                                                 "\"" + report.serialization.contextFingerprint + "\"")
           << ",\"manifest_digest\":"
           << (report.serialization.manifestDigest.empty() ? "null" : "\"" + report.serialization.manifestDigest + "\"")
           << ",\"payload_digest\":"
           << (report.serialization.payloadDigest.empty() ? "null" : "\"" + report.serialization.payloadDigest + "\"")
           << "},\n  \"sequential\":{\"ran\":" << (report.sequential.ran ? "true" : "false")
           << ",\"versus_prebootstrap\":";
    PrintError(output, report.sequential.versusPrebootstrap);
    output << ",\"versus_fixture\":";
    PrintError(output, report.sequential.versusFixture);
    output << ",\"output_level\":" << report.sequential.outputLevel
           << ",\"output_towers\":" << report.sequential.outputTowers
           << ",\"output_scale\":" << JsonNumber(report.sequential.outputScale) << ",\"decoded_sample\":";
    PrintComplexSample(output, report.sequential.decodedSample);
    output << "},\n  \"parallel\":{\"ran\":" << (report.parallel.ran ? "true" : "false")
           << ",\"D\":" << report.parallel.D << ",\"kappa\":" << report.parallel.kappa
           << ",\"serial_branches_versus_prebootstrap\":";
    PrintError(output, report.parallel.serialBranchesVersusPrebootstrap);
    output << ",\"concurrent_branches_versus_prebootstrap\":";
    PrintError(output, report.parallel.concurrentBranchesVersusPrebootstrap);
    output << ",\"serial_versus_concurrent\":";
    PrintError(output, report.parallel.serialVersusConcurrent);
    output << ",\"wall_speedup\":" << JsonNumber(report.parallel.wallSpeedup) << "},\n"
           << "  \"final_peak_rss_bytes\":" << report.finalPeakRssBytes << "\n}\n";
    std::cout << output.str();
}

}  // namespace

int main(int argc, char** argv) {
    AuditReport report;
    try {
#if NATIVEINT != 64
        throw std::runtime_error("PaCo production audit requires a 64-bit NativeInteger build");
#else
        ParseOptions(argc, argv, report.options);
        if (report.options.openfheThreads != 0)
            OpenFHEParallelControls.SetNumThreads(report.options.openfheThreads);

        CryptoContext<DCRTPoly> context;
        Measure(report, "context", [&] {
            context = MakeContext(report.options.profile);
            ValidateFrozenContext(report, context);
        });

        if (NeedsKeys(report.options)) {
            std::unique_ptr<PaCoCKKSRNS> paco;
            Measure(report, "evaluator_precompute", [&] {
                paco = std::make_unique<PaCoCKKSRNS>(context, MakeEvaluatorParameters(report.options.profile, context));
            });

            PaCoKeyMaterial owner;
            // Deliberately omit deterministicSeed. Production and smoke audits
            // both exercise the production CSPRNG path for key generation.
            Measure(report, "structured_keygen", [&] {
                owner = PaCoCKKSRNS::KeyGen(context, report.options.profile.h);
                if (!owner.keyPair.good())
                    throw std::runtime_error("structured PaCo key generation failed");
            });
            Measure(report, "bootstrap_key_setup", [&] { paco->GenerateBootstrapKeys(owner); });

            PaCoBootstrapKeys evaluatorKeys;
            Measure(report, "evaluator_material_measure", [&] {
                evaluatorKeys = paco->GetBootstrapKeys();
                MeasureEvaluatorStorage(report, context, evaluatorKeys);
            });

            if (report.options.measureAuthenticatedSerialization)
                MeasureSerialization(report, context, evaluatorKeys);

            if (NeedsSequential(report.options)) {
                PreparedInput input;
                Measure(report, "sequential_input_prepare", [&] {
                    input = PrepareInput(context, owner, report.options.profile, report.options.profile.C / 2);
                });
                report.sequentialInput = input.coefficients;
                Ciphertext<DCRTPoly> output;
                Measure(report, "sequential_eval", [&] { output = paco->EvalSequential(input.ciphertext); });
                Measure(report, "sequential_output_coefficient_check", [&] {
                    report.sequentialOutput = ObserveOutputCoefficients(context, owner.keyPair.secretKey, output,
                                                                        input.fixture, report.numericalBudget);
                });
                std::vector<std::complex<double>> decoded;
                Measure(report, "sequential_decrypt", [&] {
                    decoded = DecryptLogical(context, owner.keyPair.secretKey, output, input.fixture.size());
                });
                report.sequential.ran                = true;
                report.sequential.versusPrebootstrap = Compare(input.prebootstrap, decoded);
                report.sequential.versusFixture      = Compare(input.fixture, decoded);
                report.sequential.decodedSample.assign(decoded.begin(),
                                                       decoded.begin() + std::min<size_t>(8, decoded.size()));
                FillOutputMetadata(report.sequential, output);
                RequireDecodedErrorHeuristic(report.numericalBudget, report.sequential.versusPrebootstrap,
                                             "sequential PaCo");
            }

            if (NeedsParallel(report.options)) {
                PreparedInput input;
                Measure(report, "parallel_input_prepare", [&] {
                    input = PrepareInput(context, owner, report.options.profile, report.options.profile.parallelD / 2);
                });
                report.parallelInput = input.coefficients;
                Ciphertext<DCRTPoly> serialOutput;
                Ciphertext<DCRTPoly> concurrentOutput;
                Measure(report, "parallel_serial_branches_eval", [&] {
                    serialOutput = paco->EvalParallel(input.ciphertext, report.options.profile.parallelD,
                                                      report.options.profile.parallelKappa, false, 1);
                });
                Measure(report, "parallel_concurrent_branches_eval", [&] {
                    concurrentOutput =
                        paco->EvalParallel(input.ciphertext, report.options.profile.parallelD,
                                           report.options.profile.parallelKappa, true, report.options.maxConcurrency);
                });
                Measure(report, "parallel_output_coefficient_check", [&] {
                    report.parallelSerialOutput = ObserveOutputCoefficients(
                        context, owner.keyPair.secretKey, serialOutput, input.fixture, report.numericalBudget);
                    report.parallelConcurrentOutput = ObserveOutputCoefficients(
                        context, owner.keyPair.secretKey, concurrentOutput, input.fixture, report.numericalBudget);
                });
                std::vector<std::complex<double>> serialDecoded;
                std::vector<std::complex<double>> concurrentDecoded;
                Measure(report, "parallel_decrypt", [&] {
                    serialDecoded =
                        DecryptLogical(context, owner.keyPair.secretKey, serialOutput, input.fixture.size());
                    concurrentDecoded =
                        DecryptLogical(context, owner.keyPair.secretKey, concurrentOutput, input.fixture.size());
                });
                report.parallel.ran                                  = true;
                report.parallel.D                                    = report.options.profile.parallelD;
                report.parallel.kappa                                = report.options.profile.parallelKappa;
                report.parallel.serialBranchesVersusPrebootstrap     = Compare(input.prebootstrap, serialDecoded);
                report.parallel.concurrentBranchesVersusPrebootstrap = Compare(input.prebootstrap, concurrentDecoded);
                report.parallel.serialVersusConcurrent               = Compare(serialDecoded, concurrentDecoded);
                const auto serialTime       = report.phases.at("parallel_serial_branches_eval").wallSeconds;
                const auto concurrentTime   = report.phases.at("parallel_concurrent_branches_eval").wallSeconds;
                report.parallel.wallSpeedup = concurrentTime > 0.0 ? serialTime / concurrentTime : 0.0;
                RequireDecodedErrorHeuristic(report.numericalBudget, report.parallel.serialBranchesVersusPrebootstrap,
                                             "serial-branch parallel PaCo");
                RequireDecodedErrorHeuristic(report.numericalBudget,
                                             report.parallel.concurrentBranchesVersusPrebootstrap,
                                             "concurrent-branch parallel PaCo");
                RequireDecodedErrorHeuristic(report.numericalBudget, report.parallel.serialVersusConcurrent,
                                             "serial/concurrent PaCo agreement");
            }
        }

        report.status = "passed";
#endif
    }
    catch (const std::exception& error) {
        report.status = "failed";
        report.error  = error.what();
    }
    report.finalPeakRssBytes = PeakRssBytes();
    PrintReport(report);
    return report.status == "passed" ? 0 : 1;
}
