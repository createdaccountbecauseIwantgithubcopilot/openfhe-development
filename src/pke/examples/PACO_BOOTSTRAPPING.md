# PaCo CKKS bootstrapping example

`paco-ckks-bootstrapping.cpp` is a small correctness smoke test for the native
`PaCoCKKSRNS` API. It runs:

1. one sequential refresh of `C=4` real plaintext-polynomial coefficients
   (`C/2=2` logical complex CKKS slots); and
2. one `D=8`, `kappa=2` refresh using two concurrent sequential jobs
   (`D/2=4` logical complex slots).

The executable itself still uses a 64-bit native build, complex CKKS packing,
`FLEXIBLEAUTO`, HYBRID key switching, `N=64`, and `HEStd_NotSet` so that it runs
quickly. Those are deliberately tiny correctness parameters. They describe
this smoke executable, **not the limits of the PaCo implementation**, and the
run makes no security, production-readiness, latency, throughput, precision,
or key-size claim.

The hardened implementation also freezes the revised 64-bit
`PACO-P128-65536-v1` candidate profile: `N=65536`, `h=C=128`,
`g0=g1=3`, `HEStd_128_classic`, 50-bit scaling primes, 18 Q primes (910
bits), six P primes (360 bits), and a three-part HYBRID decomposition over a
1,270-bit QP product. Its complete pinned conventional estimator run has a
144.4963829467-bit minimum among the modeled attacks and passes the repository's
140-bit parameter-screening floor. Release evidence must bind the exact clean,
published OpenFHE revision, estimator script, embedded manifest, and reference
revisions; this living guide is not execution evidence. A parameter-screening
label is deliberately narrower than “128-bit secure” or “independently
audited.”

## Exact admitted native profile

`PaCoCKKSRNS` currently admits:

- CKKS-RNS with `COMPLEX` full-width packing and the paper's periodic subring
  embedding;
- `FLEXIBLEAUTO` scaling, with composite scaling degree one (one RNS prime per
  logical level);
- HYBRID key switching;
- a relinearized two-component input with noise-scale degree one and a finite
  scale equal to one of the context's configured CKKS scales;
- any nonempty, exact prefix of the configured Q basis for phase extraction,
  provided the OpenFHE level agrees with that prefix; full evaluation admits
  one tower under the all-zero research policy or at most the configured
  numerical-policy cap; and
- at least `L+2` total Q towers, so the fixed PaCo circuit leaves a usable
  output level.

`N`, `h`, and `C` obey the power-of-two PaCo constraints, including
`2 <= C <= N/(4h)`. Secured contexts require an explicit
`PaCoNumericalPolicy`; only `HEStd_NotSet` research contexts may use the
all-zero policy. The frozen deployment profile and its evidence use a
64-bit `NativeInteger`; other native widths are not part of that frozen
qualification even though the evaluator no longer has a PaCo-specific
one-tower or 64-bit guard.

Both grouping parameters are restricted to `1 <= g0,g1 <= 3`. This bounds the
native BSGS planning problem as well as matching the grouping range used by the
revised profile. The frozen deployment policy admits exactly
one active Q tower; wider active prefixes are not part of its qualification.

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

auto sequential = evaluator.EvalSequential(activeQPrefixCiphertext);
auto parallel   = evaluator.EvalParallel(activeQPrefixCiphertext, 8, 2, true, 2);
```

`PaCoBootstrapKeys` remains the validated in-process representation. Loading
recomputes the exact schedule and checks selector metadata, key tags, the Q
basis, the per-key level ledger, and every restricted HYBRID basis. Selector
ciphertexts and the key map are privately cloned; OpenFHE evaluation-key
pointees remain shared immutable handles.

For transport, `PaCoBootstrapKeySerializer` exports a canonical authenticated
version-2 envelope. It binds a full context fingerprint, PaCo and numerical
parameters, lifecycle identity/generation/timestamps, selectors, rotation and
automorphism manifests, and each restricted key's level, exact Q-prefix-plus-P
basis, digit count, length, and digest. Version 2 requires a 16--64-byte keyed
BLAKE2b authentication key. It is the only wire version accepted by this port;
there is no legacy import, unauthenticated mode, or migration path. See
`PACO_KEY_LIFECYCLE.md`.

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

and prescribes estimator substitutions `N'=N(1-1/h)` and `h'=h-1`. The frozen
workflow checks the exact Q/P vectors, discrete-Gaussian error, HYBRID
decomposition, direct sparse MITM, dual, dual-hybrid, primal-uSVP, and
primal-hybrid MITM/Babai models. The revised-chain minimum is 144.4963829467
bits. That reproducible screen is not a reduction
for the real one-per-known-block secret distribution. It also does not cover
correlations in the four selector ciphertexts and automorphism/multiplication
keys. Those public values expose secret-dependent functions under a related
secret and retain the PaCo circular/KDM-style assumption. Independent
cryptanalysis remains a release gate. Sparse-secret encapsulation from a
stronger ordinary key is a separate, currently undemonstrated lifecycle that
must specify both inbound and any required outbound key switch.

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

The native API admits only `g0,g1` in `[1,3]`.

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
scaling moduli. The PaCo phase denominator is the exact product of the input's
active Q prefix, not a requested bit count. Consequently the paper's reported
precision and security do not transfer automatically.

## Active-Q input and exact CRT phase extraction

The Algorithm 3 phase-extraction path accepts any nonempty active Q prefix that
exactly matches the context's tower ordering and the ciphertext's OpenFHE
level. `EvalSequential` and `EvalParallel` additionally apply the numerical
policy gates described below. Algorithm 3 publicly reads `ct0` and `ct1` modulo

$$
q=\prod_{i=0}^{t-1}q_i
$$

for `t` active towers and constructs phase plaintexts

$$
\psi(a)=\exp(2\pi ia/q).
$$

Every coefficient is interpolated exactly into an arbitrary-size `BigInteger`
before modular addition/negation and phase conversion. The centered
residue-to-modulus ratio is evaluated with a 100-decimal-digit intermediate;
only the final complex phase is rounded to binary64. Unit tests compare
two-tower extraction to an independent CRT oracle. Full `EvalSequential` and
`EvalParallel` calls with more than one tower require an explicit numerical
policy and must stay within its `maximumActiveTowers` cap. Evaluation checks the
conditional budget at `q0`, uses OpenFHE's valid level-reduction path to
normalize an admitted wider prefix to one tower, and then constructs its phase
encodings at `q0`. A unit test exercises an admitted two-tower input's
normalization and end-to-end `q0` refresh, and rejects a three-tower input under
a two-tower policy. The frozen
deployment profile remains capped at one active input tower.

`GetCoefficientEncodings` is intentionally different: when called directly on
an admitted wider prefix, it interpolates and uses the complete exact active-Q
product. That public extraction oracle does not perform the evaluation-time
one-tower normalization.

The smoke example encrypts normally and then calls
`context->Compress(ciphertext, 1)` to exercise the one-tower boundary. A real
application may retain more towers, but it must arrive at the selected prefix
through valid CKKS arithmetic or modulus reduction. Manually deleting towers
does not establish the required level, scale, or error ledger.

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

## Native BSGS and restricted-key resource profile

Regular grouped PaCo matrices use a validated baby-step/giant-step planner. It
searches aligned decompositions, checks every diagonal decomposition, and
minimizes rotation operations and then distinct rotation keys. The direct
sparse-diagonal evaluator remains only as an oracle/fail-closed fallback for an
irregular support or when BSGS does not improve that operation/key objective.
Clear-vector tests compare both schedules; the encrypted PaCo suite exercises
the BSGS path but does not claim a second encrypted direct-diagonal oracle. For
the paper's PaCo I dimensions, the native schedule requires 25 signed rotations
and 27 switching automorphisms after
adding conjugation and the fused conjugate-rotate; this is below the paper's
stated 29-key budget. The
pinned Sage revision instead has 39 logical rotations including identity and
40 actual switching automorphisms after conjugation and fused
conjugate-rotate, so paper key counts and timings are still not native
measurements.

Each automorphism and multiplication key retained in the PaCo bundle is
restricted to its first scheduled use. At OpenFHE level `ell`, its basis is
exactly `Q[0,totalTowers-ell) || P`, and only the leading
`ceil(activeQTowers/alpha)` HYBRID digits are retained. Generation never uses
an ambient full-context key as retained evaluator material: it may obtain a
fresh or cached full-context OpenFHE key as a transient source, then clones and
restricts it into the private PaCo bundle. Import and evaluation reject an early
use, wrong level, missing Q/P tower, reordered basis, or wrong digit count. This implements
the paper's level restriction structurally, but OpenFHE HYBRID representation
still differs from the paper's idealized key-size formula. Actual serialized
bytes, resident memory, and timings must come from `paco-production-audit`.

OpenFHE key generation can leave its full source keys in the owner process's
ambient evaluation-key registry. They are not serialized into the PaCo v2
artifact and the evaluator does not consult them, but a production ceremony
must isolate setup and clear/destroy that transient registry after exporting the
restricted artifact. The frozen estimator conservatively screens the full QP
exposure; level restriction is not a license to weaken that security screen.

The paper's analysis assumes `p <= q` and `Delta >= q`. The tiny native example
uses a 45-bit first modulus with 35-bit CKKS scaling primes and therefore does
not claim that paper profile. It is a circuit/convention test only. The frozen
candidate supplies an explicit scaled-coefficient bound, a caller-established
bound covering all non-small-angle error, an active-tower cap, a
minimum-precision target, and a native RNS security screen. These are
conditional admission inputs, not values inferred from an encrypted plaintext.

The final `eta` multiplication cancels the bootstrap scale while the recovered
raw coefficients retain the input ciphertext's scale. The evaluator verifies
the exact level/noise-scale ledger and then restores the input scaling metadata;
this is the OpenFHE analogue of the reference's `boot_to_nonboot()` transition.

## Conditional numerical certificate

Ideal phase multiplication performs modular addition exactly, but PaCo finally
uses

$$
m\approx\frac{q}{2\pi}\sin(2\pi m/q),\qquad |m|\ll q.
$$

The implementation's `AnalyzeNumericalBudget` takes an explicit modulus, an
application-established coefficient bound, and an application-established
absolute-error bound covering **every** non-small-angle source: incoming CKKS
error, binary64 phase and transforms, encoding, rescaling, key switching, and
evaluation noise. It analytically bounds the sine small-angle term, checks that
the declared coefficient-plus-error range stays inside `(-q/2,q/2)`, combines
the two error bounds, and reports conditional retained precision.
For full evaluation, `ValidateInput` recomputes that implication at `q0`, the
modulus actually used after admitted wider inputs are normalized; direct public
coefficient extraction still uses the exact active-Q product. Validation fails
before evaluation if the policy's tower cap, wrap condition, or requested
precision is not met. The `PACO-P128-65536-v1` policy uses the configured
level-zero scale (approximately `2^50`) as its coefficient bound, `2^34` as its
caller-established non-small-angle allowance, a one-tower cap, and a 14-bit
minimum. The full audit reports a **heuristic** decoded gate of
`totalAbsoluteErrorBound / maximumAbsCoefficient = 4.0359640038e-5` (about
`2^-14.5967`). Raw polynomial-coefficient checks are the primary empirical
evidence because CKKS embedding norms do not make that decoded ratio a proof.
The policy contains no operation-count or `gamma_n` guarantee.

This certificate is conditional. The evaluator cannot discover the plaintext
coefficient bound or establish the caller's aggregate non-small-angle error
bound from a ciphertext. The reported precision is true only if those external
bounds hold. The certificate does not validate an entropy source or replace
high-precision stage oracles and empirical large-parameter failure testing.
`COMPLEX` mode also disables OpenFHE's usual imaginary-part dynamic noise
estimate. Thus the paper's "zero failure probability" means that PaCo avoids a
failure event from a homomorphically approximated periodic polynomial; it does
not mean exact CKKS arithmetic or zero numerical error. The smoke executable
prints maximum complex-slot error but does not attach the frozen profile's
certificate to its toy parameters.

## Build and run

The PKE example targets are discovered through the existing CMake glob, so no
CMake edit is needed:

```bash
cmake -S . -B build -DBUILD_EXAMPLES=ON
cmake --build build --target paco-ckks-bootstrapping -j
./build/bin/examples/pke/paco-ckks-bootstrapping
```

The exact binary directory can differ with a multi-configuration generator.
The smoke executable itself exits with a diagnostic if it is not built for its
chosen 64-bit `FLEXIBLEAUTO` fixture, key setup fails, its deliberately
one-tower input cannot be constructed, evaluation/decryption throws, or either
maximum slot error exceeds the conservative `5e-3` toy threshold. The library
supports only `FLEXIBLEAUTO`. Multi-tower exact phase extraction exists, but a
wider-prefix `Eval` call is policy-gated and normalizes to `q0`; it is not PaCo
evaluation with the full CRT-product modulus. HYBRID key switching remains
required.

The unit suite covers pinned-Sage D/E numerical fixtures, transform inverses
and grouping, clear-vector BSGS/direct parity and the 27-automorphism PaCo I
budget, extended bit reversal, the one-hot rotation convention, structured-key
shape and binding, independent decryption of all four encrypted selector vectors,
the central Algorithm 2 packing relation, exact two-tower CRT extraction and
its independent oracle, admitted two-tower input normalization and end-to-end
`q0` refresh, and rejection of a three-tower input under a two-tower policy,
level-restricted Q-prefix-plus-P HYBRID keys, exact level/scale
metadata, one post-bootstrap multiply/rescale continuation, `C=2`, maximum
`C`, `k=1`, `k=2`, `k=4`, nonconstant sequential/parallel messages, and
concurrent/serial parity. Separate serialization tests exercise authenticated
v2 round trips, context/numerical/lifecycle binding, corruption and rollback,
and wrong key-basis/level rejection. Numerical tests use high-precision clear
phase oracles and large arbitrary-size moduli.

The acknowledged full production audit is the machine-readable evidence gate.
It requires an authenticated v2 round-trip, the frozen 26-signed-rotation and
28-automorphism manifests, exact serial/concurrent parallel agreement, admitted
output metadata, raw polynomial error below the conditional total bound, and
decoded error below the explicitly labeled heuristic gate. It records the
actual restricted-key layout, live coefficient bytes, artifact bytes, wall and
CPU time, concurrency speedup, and peak RSS. Exact observations belong in the
commit-bound JSON evidence bundle because encryption randomness, scheduling,
and host resources make them run-specific. The externally supplied `2^34`
non-small-angle premise remains an assumption beyond those fixtures.

Those tests, measurements, and the complete conventional estimator support the
parameter-screening candidate label. They do not supply independent
cryptanalysis, a KDM/circular-security reduction, a side-channel or entropy
audit, or a production-approval decision. A release must either pin the exact
evaluated OpenFHE commit or regenerate its estimator and production evidence
after any source revision; documentation text must never be used to relabel an
older execution as a newer one.
