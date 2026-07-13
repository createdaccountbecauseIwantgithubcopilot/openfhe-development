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
