# PaCo bootstrap-key lifecycle

`PaCoBootstrapKeySerializer` provides a versioned evaluator-key transport for
the native PaCo implementation. It serializes only evaluator-visible material:
the four selector ciphertexts, automorphism keys, and multiplication key. The
structured secret descriptor and private key are never included.

## Export and import

```cpp
#include "scheme/ckksrns/ckksrns-paco-serialization.h"

std::vector<uint8_t> authenticationKey = LoadSecretFromKms();  // 16--64 bytes

lbcrypto::PaCoBootstrapKeyExportOptions out;
out.lifecycle.bundleId             = "payments/paco/evaluator";
out.lifecycle.issuer               = "offline-key-owner";
out.lifecycle.generation           = 4;
out.lifecycle.createdAtUnixSeconds = 1783915200;
out.lifecycle.expiresAtUnixSeconds = 1815451200;
out.authenticationKey              = authenticationKey;

const auto bytes = lbcrypto::PaCoBootstrapKeySerializer::Serialize(
    context, owner.GetBootstrapKeys(), out);

lbcrypto::PaCoBootstrapKeyImportOptions in;
in.expectedBundleId       = out.lifecycle.bundleId;
in.expectedIssuer         = out.lifecycle.issuer;
in.expectedKeyTag         = expectedKeyTag;  // stored outside the artifact
in.minimumGeneration      = 4;               // persisted rollback floor
in.currentTimeUnixSeconds = TrustedUnixTime();
in.authenticationKey      = authenticationKey;

auto imported = lbcrypto::PaCoBootstrapKeySerializer::Deserialize(
    context, productionPaCoParameters, bytes, in);
evaluator.LoadBootstrapKeys(std::move(imported.keys));
```

Keep the authentication key, expected key tag, expected bundle/issuer, and
minimum accepted generation in a trust store separate from the artifact. A
deployment should atomically raise its persisted generation floor after it
accepts new material. Distribute a new `bundleId` when changing the deployment
role rather than reusing an unrelated bundle's identity.

The production-audit harness creates three authentication-key vector copies:
the local vector, the export-options copy, and the import-options copy. After a
verified import it best-effort overwrites all three. This is not secure erasure:
compiler transformations, allocator behavior, and temporary copies may leave
key bytes in memory. Production callers need secure-memory and KMS-backed
process controls appropriate to their threat model.

## What version 2 binds

The canonical little-endian envelope contains independently versioned OpenFHE
portable-binary payloads and commits to:

- every serialized CKKS-RNS crypto parameter and encoding parameter;
- security/noise/secret-distribution, scaling, multiplication, encryption, and
  HYBRID-decomposition settings;
- every Q, P, QP, and public-key-basis modulus and root of unity;
- PaCo `h`, `C`, `g0`, and `g1`, the exact IEEE-754 bit patterns of both
  numerical-policy bounds, the minimum precision, maximum active-tower cap,
  ring dimension, and total Q-tower count;
- the external key tag, exact signed-rotation list, and exact automorphism list;
- every key's earliest usable OpenFHE level, exact active Q prefix, complete P
  basis, HYBRID digit count, serialized length, and serialized digest;
- every byte of every selector ciphertext and evaluation key; and
- bundle identity, issuer, generation, creation time, and expiry.

Each ciphertext and key is a separately length-bounded OpenFHE portable-binary
section. Import verifies the envelope MAC, trust anchors, aggregate and
per-entry digests, declared levels, and Q/P basis descriptors before invoking
OpenFHE deserialization. It then checks the decoded objects against those
descriptors and passes the reconstructed bundle through
`PaCoCKKSRNS::LoadBootstrapKeys`, which checks ciphertext metadata and bases,
all object contexts and key tags, and the exact evaluator schedule.

The envelope contains only the restricted `Q-prefix || P` key objects retained
by PaCo. Key setup may temporarily obtain full-context OpenFHE keys as sources
before cloning and restriction; those source objects and the ambient evaluation
key registry are never serialized into the v2 artifact.

## Integrity is not authenticity

All artifacts contain an unkeyed 256-bit BLAKE2b integrity digest for corruption
detection. It is not an authenticity claim: an attacker who can replace an
artifact can also recompute it.

Version 2 additionally requires a 16--64-byte `authenticationKey` on export and
import. It adds a keyed 256-bit BLAKE2b tag over the complete envelope and
integrity digest. There is no unauthenticated import or export mode.

Version 2 is the only supported wire format. The decoder rejects every other
version or magic value before constructing OpenFHE objects; there is no legacy
import, downgrade flag, or implicit migration path. A deployment holding an
artifact from any earlier experimental codec must regenerate and export its
evaluator material with the current authenticated serializer.

The keyed tag authenticates the artifact symmetrically; it does not provide
public verifiability or non-repudiation. Deployments needing those properties
should additionally sign the complete artifact with their normal release-signing
system and verify that signature before calling `Deserialize`.
