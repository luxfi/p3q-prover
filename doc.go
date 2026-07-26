// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package p3qprover is the OFFLINE P3Q rollup prover (LP-218): it compresses N
// INDEPENDENT ML-DSA-65 certificates over a finality subject into a succinct
// warp.P3QRoot, and ships the matching reference warp.P3QRollupVerifier.
//
// It sits BELOW the warp verification boundary (warp/offline_signers.go names
// the boundary). The chain never imports the prover; it receives only the
// compact P3QRoot and verifies it through an injected P3QRollupVerifier.
//
// # What the existing verifier really checks (honest, read at warp v1.23.0)
//
//   - warp's in-package P3QRollupVerifier is a FAIL-CLOSED STUB
//     (warp.UnavailableP3QVerifier → ErrP3QVerifierUnavailable). The real
//     verifier is INJECTED from above warp.
//   - precompile 0x012205 (luxfi/precompile/p3q) is NOT a rollup verifier. It
//     verifies a SINGLE ML-DSA-65 (FIPS 204) signature under a group key vs a
//     32-byte messageHash, with FIPS 204 context "lux-evm-precompile-p3q-v1".
//     Its core is mldsa.PublicKey.VerifySignatureCtx — the same primitive this
//     package calls per cert (see CrossCheckCtx and the cross-check test).
//   - the genuine STARK/FRI machinery lives at precompile 0x012220
//     (luxfi/precompile/starkfri, a Plonky3 fork over Goldilocks/cSHAKE256),
//     but it is an FFI shim with no registered verifier and no P3Q-specific
//     AIR. There is, today, NO concrete "N independent ML-DSA-65 sigs →
//     succinct PQ proof" argument in-tree.
//
// So this package builds the prover against the DEFINED relation the verifier
// must check, plus a matching SOUND reference verifier, and flags the succinct
// proof as the gap. See "Honesty: real vs scaffolded" below.
//
// # The P3Q rollup relation R (what a P3Q root attests)
//
// Public statement, all bound into the public-input digest PI:
//
//	subject        the 32-byte warp finality subject (D for warp, M for quasar)
//	signerSetID    the validator set the keys belong to (P3QRoot.SignerSetID)
//	eraHandle      the signer-set snapshot selector (P3QRoot.EraHandle)
//	threshold      the weighted quorum fraction (P3QRoot.Threshold)
//	root           the 32-byte commitment over the verified signer set (P3QRoot.Root)
//
// Witness (held by the prover; carried in P3QRoot.Proof for the reference
// backend; replaced by a FRI proof for the succinct backend):
//
//	a set S of distinct validators with their ML-DSA-65 signatures sig_i.
//
// R holds iff there exist distinct validators i in S such that, with each
// (pk_i, weight_i) RESOLVED FROM THE AUTHORITY (never from the witness):
//
//  1. ML-DSA-65 Verify(pk_i, subject, sig_i, ctx="lux-evm-precompile-p3q-v1")
//     for every i in S  (byte-identical to the precompile 0x012205 verify);
//  2. every i in S is a member of ResolveSignerSet(signerSetID, eraHandle);
//  3. the i in S are pairwise distinct (each validator counted once);
//  4. the canonical commitment over leaves(S) equals root; and
//  5. sum(weight_i) / totalWeight >= threshold (128-bit exact compare).
//
// Keys come from the AUTHORITY, not the witness, so a prover can never
// substitute a key it controls — both prover and verifier resolve the same
// authenticated on-chain registry (warp.SignerSetAuthority).
//
// # Commitment + public inputs (FIPS 202 / SHA3-256, post-quantum)
//
//	leaf_i = SHA3-256( leafDST  || nodeID_i || SHA3-256(pkDST||pk_i) || weight_i )
//	node   = SHA3-256( nodeDST  || left || right )   (leaves canonically sorted by nodeID)
//	root   = Merkle root over the sorted leaves (odd node promoted, no duplication)
//	PI     = SHA3-256( piDST || subject || signerSetID || eraHandle || thrNum ||
//	                   thrDen || totalWeight || attestedWeight || root || nSigners )
//
// Leaf vs node domain separation makes a node uncomputable as a leaf
// (second-preimage resistance). SHA3-256 is FIPS 202, a post-quantum-friendly
// (hash-based) assumption and the same family the strict-PQ STARK profile uses.
//
// # Proven-system binding (the v1.23.0 contract)
//
// VerifyP3QRollup MUST return the proof system it ACTUALLY verified; the warp
// dispatcher rejects the lane if it differs from P3QRoot.ProvingSystem. This
// package makes that binding impossible to fake:
//
//   - BackendDirect → proven system "none". There is no succinct-proof wrapper;
//     the PQ root of trust is the ML-DSA-65 signatures themselves, re-verified
//     by the reference verifier. warp.IsPQRootOfTrust("none") == true, so a
//     "none" root is strict-PQ admissible (the warp authors made "none" PQ
//     precisely for "the signature itself is the evidence").
//   - BackendStarkFRI → proven system "stark-rescue". This is the SUCCINCT
//     instantiation; its AIR + Plonky3 prover/verifier is NOT built here, so
//     Prove returns ErrStarkBackendUnavailable and the verifier returns it for
//     a stark-tagged proof. The prover therefore CANNOT emit a root that
//     falsely claims "stark-rescue".
//
// # Honesty: real vs scaffolded
//
// REAL, complete, and tested end-to-end (BackendDirect):
//   - real ML-DSA-65 (FIPS 204, cloudflare/circl via luxfi/crypto/mldsa)
//     verification of every cert, byte-identical to precompile 0x012205;
//   - real authority-resolved membership, real distinctness, real 128-bit
//     weighted-quorum accounting;
//   - real SHA3-256 hash-based commitment + public-input binding;
//   - a SOUND reference verifier that re-runs R and returns "none";
//   - the full proven-system binding, exercised through warp.AcceptQuasarCert.
//
// SCAFFOLDED, flagged as the gap (BackendStarkFRI):
//   - the SUCCINCT proof. The reference proof carries the witness (signatures),
//     so VerifyP3QRollup is SOUND but O(N) in verify time and proof size: it is
//     the executable SPECIFICATION / oracle of R, not a succinct argument.
//     Making verify O(polylog N) requires a FRI/STARK proof of R over the
//     Plonky3-fork at precompile 0x012220 (a P3Q AIR that arithmetizes ML-DSA
//     verification). The P3QRoot interface, the Root, and PI are FINAL — the
//     succinct proof is a drop-in replacement of P3QRoot.Proof and the
//     ProvingSystem string ("none" → "stark-rescue"); everything else is
//     unchanged.
//
// One relation, one place: prover and verifier share evalRelation (relation.go)
// so the proven and the produced statement can never drift.
package p3qprover
