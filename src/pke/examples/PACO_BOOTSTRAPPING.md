# PaCo CKKS bootstrapping example

`paco-ckks-bootstrapping.cpp` is a small, research-only demonstration of the
native `PaCoCKKSRNS` API. It runs:

1. one sequential refresh of `C=4` real plaintext-polynomial coefficients
   (`C/2=2` logical complex CKKS slots); and
2. one `D=8`, `kappa=2` refresh using two concurrent sequential jobs
   (`D/2=4` logical complex slots).

It uses a 64-bit native build, complex CKKS packing, `FLEXIBLEAUTO`, HYBRID key
switching, `N=64`, and `HEStd_NotSet`.
Those are deliberately tiny correctness parameters. The example makes **no
security, production-readiness, latency, throughput, precision, or key-size
claim**.

## Paper and reference provenance

The algorithm follows Jean-Sebastien Coron and Tim Seure, *PaCo:
Bootstrapping for CKKS via Partial CoeffToSlot*, ASIACRYPT 2025. The workspace
copy is [PACO.md](https://github.com/createdaccountbecauseIwantgithubcopilot/GL-scheme/blob/openfhe-based/PACO.md). The authors' proof-of-concept
repository is [se-tim/PaCo-Implementation](https://github.com/se-tim/PaCo-Implementation),
with a recursively initialized snapshot in the parent workspace at
`GL_scheme/external/PaCo-Implementation`.

The behavior comparison used the following pinned revisions:

| Repository | Revision |
| --- | --- |
| `se-tim/PaCo-Implementation` | `e8467fad32cf17243f8ee83d09c307c546fb6d87` |
| nested `se-tim/CKKS-in-SageMath` | `3c42e2e265fc48df789d0cb66026d4ecbe20870b` |
| nested `malb/lattice-estimator` | `cca7ff4d7435089b9268736595356d0e96bb7a48` |

### Unresolved top-level reference license

At the pinned revision, the **top-level PaCo reference repository has no
`LICENSE` file**. Its tracked top-level files are `README.md`, `benchmarks.py`,
and the PaCo Python package plus submodule metadata. The nested
`CKKS-in-SageMath` submodule has its own license, but that does not establish a
license for the top-level PaCo Python sources.

This OpenFHE example and the native port are independently written under
OpenFHE's BSD-2-Clause terms. That license does not grant rights to the upstream
top-level reference code. Do not copy, redistribute, or relicense that code
without a license or permission from its copyright holders. Keep the reference
checkout as a behavioral oracle until this provenance issue is resolved.

## What the API demonstrates

The public API is declared in
`src/pke/include/scheme/ckksrns/ckksrns-paco.h`:

```cpp
PaCoParameters parameters{/*h=*/2, /*C=*/4, /*g0=*/2, /*g1=*/1};
auto owner = PaCoCKKSRNS::KeyGen(context, parameters.h, deterministicSeed);

PaCoCKKSRNS paco(context, parameters);
paco.GenerateBootstrapKeys(owner);

// Evaluator-side handoff; this bundle contains no private key or clear u/d.
PaCoCKKSRNS evaluator(context, parameters);
evaluator.LoadBootstrapKeys(paco.GetBootstrapKeys());

auto sequential = evaluator.EvalSequential(oneTowerCiphertext);
auto parallel   = evaluator.EvalParallel(oneTowerCiphertext, 8, 2, true, 2);
```

`PaCoBootstrapKeys` is a trusted in-process handle bundle, not a hardened wire
format. Loading recomputes the exact manifest, validates selector metadata and
the full Q basis, and privately clones selector ciphertexts and the key map.
The OpenFHE evaluation-key pointees remain shared handles and must be treated as
immutable after generation/loading. A context fingerprint and serialized wire
format remain production-hardening work.

The optional deterministic seed is for tests only. Anyone who knows it can
reconstruct the structured secret. Production callers must omit it.

`PaCoCKKSRNS` is independent of `FHECKKSRNS::EvalBootstrap`; it does not replace
or call conventional CKKS bootstrapping. The evaluator reconstructs the public
ciphertext relation through four encrypted selector/shift vectors, a partial
CoeffToSlot, phase products, and a final decomposed SlotToCoeff'.

## Structured secret is mandatory

PaCo Algorithm 1 uses

$$
s=\sum_{v=0}^{4h-1}d_vX^{4hu_v+v},
$$

where exactly one selector among `d[v]`, `d[h+v]`, `d[2h+v]`, and
`d[3h+v]` is one for every residue class `v`, and all other selectors are zero.
The secret is binary with Hamming weight `h`; its constant coefficient is one.

`PaCoCKKSRNS::KeyGen` constructs this exact secret and matching OpenFHE keys.
Do **not** replace it with `CryptoContext::KeyGen`, `SPARSE_TERNARY`, or
`UNIFORM_TERNARY`: those distributions do not satisfy the PaCo decryption
equations. The clear shift indices and selectors in `PaCoKeyMaterial` are
owner-only setup state. After `GenerateBootstrapKeys`, evaluation uses the four
encrypted selector vectors in `PaCoBootstrapKeys` and public ciphertext
coefficients; evaluator code does not need the clear secret descriptor.

The paper argues that the structured support has size

$$
|S|=(N/h)^{h-1}
$$

and prescribes estimator substitutions `N'=N(1-1/h)` and `h'=h-1`. That is not
a security certificate for this native RNS profile. A production assessment
must include the actual Q/P moduli, error distribution, key-switch
decomposition, structured-secret attacks, and secret-dependent bootstrapping
material. Sparse-secret encapsulation from a stronger ordinary key is a
separate, currently undemonstrated lifecycle that must specify both inbound and
any required outbound key switch.

## Parameters and depth

For ring dimension `N`, structured-key Hamming weight `h`, and sequential
coefficient count `C`, PaCo defines

$$
B=\frac{N}{4h},\qquad
k=\frac{N}{4hC},\qquad
n=2hC,
$$

with power-of-two constraints and `2 <= C <= B`. `C` counts real polynomial
coefficients, not ordinary complex slots.

With grouping parameters `g0` and `g1`, the multiplicative depth is

$$
L=
\left\lceil\frac{\log_2(2C)}{g_0}\right\rceil+
\left\lceil\frac{\log_2(C/2)}{g_1}\right\rceil+
\log_2(h)+3.
$$

The example chooses

```text
N=64, h=2, C=4, g0=2, g1=1
B=8, k=2, n=16
L=ceil(3/2)+ceil(1/1)+1+3=7
```

PaCo itself consumes seven levels. The implementation requires at least two
more Q towers than this depth, so the refreshed result has at least one usable
level rather than returning immediately depleted. The example calls
`SetMultiplicativeDepth(7+2)`: the two reserved levels make the refreshed output
visibly useful for subsequent toy computation. The native port checks the
actual tower count rather than trusting this comment.

The exact powers-of-two `q`, `p`, and `Delta` used by the Sage proof of concept
are not native NTT moduli. This example uses a 45-bit first modulus and 35-bit
scaling moduli. The PaCo phase denominator is the actual remaining bottom RNS
modulus, not a requested bit count. Consequently the paper's reported precision
and security do not transfer automatically.

## Native one-tower input profile

`EvalSequential` and `EvalParallel` require the input ciphertext to have
**exactly one active Q tower**. This is a limitation of this correctness-first
native implementation, not an intrinsic restriction of PaCo. Algorithm 3
publicly reads `ct0` and `ct1` modulo a modulus `q` and constructs phase
plaintexts

$$
\psi(a)=\exp(2\pi ia/q).
$$

A multi-tower native profile could instead define `q` as the product of its
active CRT moduli and interpolate every coefficient exactly before phase
conversion. That profile is not implemented here.

The example encrypts normally and then calls `context->Compress(ciphertext, 1)`
to perform a valid CKKS reduction to the base boundary. It checks every
ciphertext component has `GetNumOfElements() == 1` before calling PaCo. In a
real application, consume levels through valid CKKS arithmetic and modulus
reduction until the same precondition holds. Do not satisfy the check by
manually deleting CRT towers.

The logical input vectors are periodically repeated over all `N/2` ambient
slots. This realizes the paper's natural subring embedding. Zero-padding the
remaining slots would generally create a dense plaintext polynomial, so a
sequential `C`-coefficient projection would not preserve the displayed logical
message.

## Sequential and parallel behavior

`EvalSequential` refreshes only

$$
\sum_{i=0}^{C-1}m_{iN/C}X^{iN/C}.
$$

The repeated two-slot sequential input already lies in this subring, so the
first two decoded output slots can be compared with the input.

For parallel PaCo, write a `D`-coefficient polynomial in
`T=X^(N/D)`. `kappa` independent jobs refresh `C=D/kappa` coefficients each,
then use negacyclic monomial shifts to recombine the result. The example uses
`D=8`, `kappa=2`, and passes `runConcurrently=true`, which requests two
`std::async` jobs after all key generation is complete. Its explicit
`maxConcurrency=2` bounds simultaneous workers; a zero limit uses reported
hardware concurrency and still never launches all `kappa` jobs at once when
`kappa` is larger. This is an actual two-way execution request, unlike the
reference benchmark's simulated parallel timing. The example does not claim
that two threads are faster at this tiny dimension.

## Native resource-profile deviations

The current correctness-first port evaluates every nonzero grouped-matrix
diagonal directly. The pinned Sage implementation uses baby-step/giant-step.
The two schedules implement the same linear maps, but their rotation manifests,
key counts, memory use, and latency differ. Likewise, this port generates
ordinary full-context OpenFHE HYBRID automorphism and multiplication keys; it
does not yet restrict switching keys to the paper's lower evaluation levels.
Consequently Table 4's Galois-key count, evaluation-key modulus, key size, and
timings are not claims about this C++ bundle. The API exposes its complete,
deduplicated automorphism manifest so native measurements can use actual keys.

The paper's analysis assumes `p <= q` and `Delta >= q`. The tiny native example
uses a 45-bit first modulus with 35-bit CKKS scaling primes and therefore does
not claim that paper profile. It is a circuit/convention test only. Production
parameters require an explicit plaintext coefficient bound, a numerical
admissibility analysis for phase conversion through `complex<double>`, and a
native RNS security estimate.

The final `eta` multiplication cancels the bootstrap scale while the recovered
raw coefficients retain the input ciphertext's scale. The evaluator verifies
the exact level/noise-scale ledger and then restores the input scaling metadata;
this is the OpenFHE analogue of the reference's `boot_to_nonboot()` transition.

## Approximation caveat

Ideal phase multiplication performs modular addition exactly, but PaCo finally
uses

$$
m\approx\frac{q}{2\pi}\sin(2\pi m/q),\qquad |m|\ll q.
$$

The leading deterministic error is proportional to `m^3/q^2`, and CKKS adds
encoding, encryption, multiplication, rescaling, and key-switch error. Thus the
paper's "zero failure probability" means that PaCo avoids a failure event from
a homomorphically approximated periodic polynomial. It does not mean exact
decryption or zero numerical error. The example prints maximum complex-slot
error without treating the toy result as a precision guarantee.

`COMPLEX` CKKS mode also disables the usual imaginary-component dynamic noise
estimator. A production use would need a separate noise and precision analysis.

## Build and run

The PKE example targets are discovered through the existing CMake glob, so no
CMake edit is needed:

```bash
cmake -S . -B build -DBUILD_EXAMPLES=ON
cmake --build build --target paco-ckks-bootstrapping -j
./build/bin/examples/pke/paco-ckks-bootstrapping
```

The exact binary directory can differ with a multi-configuration generator.
The example exits with a diagnostic if the native build does not support the
required 64-bit `FLEXIBLEAUTO` profile, key setup fails, an input has more than
one tower, evaluation/decryption throws, or either maximum slot error exceeds
the conservative `5e-3` toy threshold. HYBRID key switching is also required.

The port was verified on 2026-07-13 in a fresh GCC 12 Release/Ninja tree. All
14 PaCo tests passed, the complete PKE executable passed all 1,996 tests from
41 suites, and a final example run reported maximum slot errors of
`4.269605e-06` (sequential) and `9.217250e-06` (parallel). Encryption is
randomized, so these are observations rather than stable expected values; they
are not production precision or performance claims.

The unit suite covers pinned-Sage D/E numerical fixtures, transform inverses
and grouping, extended bit reversal, the one-hot rotation convention,
structured-key shape and binding, independent decryption of all four encrypted
selector vectors, the central Algorithm 2 packing relation, evaluator-side
bundle import and defensive cloning, incomplete and mismatched material,
public coefficient-boundary extraction, exact level/scale metadata, one
post-bootstrap multiply/rescale continuation, `C=2`, maximum `C`, `k=1`,
`k=2`, `k=4`, nonconstant sequential and parallel messages, and
concurrent/serial parity. Passing these toy tests is correctness evidence only.
High-precision per-stage encrypted oracles, dense coefficient-projection
fixtures, production-size runs, native security estimation, and
performance/key-size benchmarking remain separate research gates.
