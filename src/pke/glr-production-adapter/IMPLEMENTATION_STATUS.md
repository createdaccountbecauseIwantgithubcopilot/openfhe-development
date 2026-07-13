# GLR production-adapter implementation status

## H64 selected-leaf P14 fold

The adapter exposes `GetH64SelectedLeafFoldCapabilities()` and
`EvaluateH64SelectedLeafFoldCpu()` for the selected-leaf fold committed in
GLScheme core revision `3f2675b1514f6535e63164074bf079bc8ecc7f36`.
The receipt binds the exact `GL-128-257-N32` parameter fingerprint and H64
support commitment. The evaluator accepts 64 provider-selected, randomized
nontransparent sparse-key leaves at L2, delegates the 63-product six-frontier
tree, and returns the primary-key result at L14 after conjugation-add and the
sparse-to-primary switch.

The fold uses the complete P14 basis: API sentinel `0`, effective special-prime
count 14, and 32,505,952 compact bytes (31.00 MiB) across the L2
relinearization key and two L14 return keys. The core owner acceptance executes
63 products, 63 relinearizations, 63 logical paired rescales, and 126 physical
Q-prime drops across all 32,768 X/W coordinates. The OpenFHE focused test pins
the typed delegation surface and metadata; it deliberately does not duplicate
the 184-second core owner run or claim a framework-native ciphertext value pass.

This seam starts after selection. Hidden encrypted controls, the complete
hidden 64-support fold, all-Y/StC value composition, a formal composed-noise
certificate, structured-security certification, GPU execution, production
authorization, and `BootstrapDirect` admission remain false.

## H64 private owner material cursor

GLScheme core revision `599dde94b91b10249eb6d222e008bf67b5b6b457`
adds a move-only owner cursor, exposed here through
`CreateH64HiddenSelectorOwnerCursor()` and
`EmitNextH64HiddenSelectorOwnerCursorChunk()`. Its sink is write-only: there is
no old-record load callback. The library retains a private authenticated
checkpoint and accepts one to ten new records per transaction. If persistence
throws after an ambiguous write, the cursor is poisoned and rejects retrying
that index.

The bounded core acceptance emitted the first support's ten records in `1/9`
chunks, independently matched record zero, loaded or reverified zero previous
records, and kept at most one full pair and one compact record live. The typed
receipt binds those facts to the canonical 64 supports, 10 controls per
support, and 640-record total schedule.

This is not a claim that all 640 records executed. No complete manifest or
full in-memory material bank was produced, and the complete hidden fold,
all-Y/StC value path, exact estimator/noise evidence, structured security, GPU
execution, production authorization, and bootstrap-direct admission remain
false.

## H64 selected-leaf h4 GPU frontier

The device-conditional `EvaluateH64SelectedLeafH4GpuFrontier()` seam delegates
GLScheme core revision `f9324e8a73f8ca98e0bc4e334890e0e83a84f3e1`.
Four already-selected randomized sparse L2 leaves cross the input boundary
once, then execute two L2 products and one L4 product with the full-P14
relinearization key. The result remains authoritative and `DeviceDirty` at L6.
Callers must explicitly perform owner readback and unregister both component
spans before destroying the host object, as required by the core contract.

The core acceptance reports exact CPU ciphertext-byte parity and decrypts all
32,768 coordinates with maximum error `1.086e-10`. Input upload is 96,468,992
bytes (92 MiB), explicit owner readback is 19,922,944 bytes (19 MiB), and all
three resident product/relinearization/rescale nodes transfer zero ciphertext
values over PCIe. The measured internal/wall runtimes are 5.81/6.00 seconds at
595.46 MiB peak RSS.

This receipt attributes value execution only to the GLScheme CUDA acceptance,
not to OpenFHE-native ciphertexts. The remaining 60 leaves, conjugation and
sparse-to-primary returns, hidden controls, all-Y/StC, formal noise and
structured-security certificates, GPU bootstrap readiness, production
authorization, and bootstrap-direct admission remain false.

## H64 selected-leaf 64 GPU tree

Core revision `cef5ac76b72b9c4b6da2e6d14519172305002739`
extends the resident selected-leaf executor through all 64 already-selected
leaves. `EvaluateH64SelectedLeaf64GpuTree()` delegates the exact six-frontier
P14 schedule: 63 products, relinearizations, and logical paired rescales across
`L2:32`, `L4:16`, `L6:8`, `L8:4`, `L10:2`, and `L12:1`, producing an
authoritative `DeviceDirty` sparse L14 root.

The core owner acceptance decrypts all 32,768 coordinates with maximum error
`4.340e-10`. Aggregate input upload is 1,543,503,872 bytes (1,472 MiB), owner
readback is 11,534,336 bytes (11 MiB), and the 63 resident nodes transfer zero
ciphertext values over PCIe. Internal/wall runtime is 34.71/34.92 seconds at
604.52 MiB peak RSS.

This completes only the selected-leaf product tree. It does not execute hidden
controls, conjugation-add, sparse-to-primary return, all-Y/StC, or an
OpenFHE-native ciphertext value path. Formal noise and structured-security
certificates, GPU bootstrap readiness, production authorization, and
bootstrap-direct admission remain false.

## H64 selected-leaf resident GPU return

Core revision `ddf77625ae1cc4de1183223e761c4d9df0b32411` continues the
already-selected sparse L14 tree root without a ciphertext-value transfer.
`EvaluateH64SelectedLeaf64GpuReturn()` delegates the resident lane-swap,
full-P14 conjugation-to-sparse switch, two component additions forming
`2*Re(root)`, and full-P14 sparse-to-primary switch. The result remains an
authoritative `DeviceDirty` primary L14 ciphertext.

The combined core tree/return acceptance decrypts all 32,768 primary slots
with maximum error `8.666e-10`. Both switches report all 14 special primes,
the return stage transfers zero ciphertext-value bytes in either direction,
and the combined run takes 31.77/31.95 seconds internal/wall at 604.87 MiB
peak RSS. The P13 return-binding negative rejects.

These are core CUDA measurements, not an OpenFHE-native value rerun. Hidden
controls, the hidden 64-support fold, all-Y/StC, formal composed-noise and
structured-security certificates, GPU bootstrap readiness, production
authorization, and bootstrap-direct admission remain false.
