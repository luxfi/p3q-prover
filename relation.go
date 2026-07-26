// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3qprover

import (
	"bytes"
	"sort"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
)

// quorum is the canonical outcome of evaluating the P3Q relation R over a set
// of candidate certs. It is the single source of truth shared by the prover
// (which produces the P3QRoot from it) and the reference verifier (which
// re-derives it and checks the P3QRoot against it).
type quorum struct {
	// entries is the verified subset in canonical order (sorted by NodeID,
	// deduplicated). The proof stores these so re-decode is order-stable.
	entries []CertEntry
	// root is the Merkle commitment over the verified-signer leaves.
	root [32]byte
	// attestedWeight is the summed stake weight of the verified subset.
	attestedWeight uint64
	// totalWeight is the signer set's total stake (from the authority).
	totalWeight uint64
}

// evalRelation is the ONE place R is checked (doc.go). Given the candidate
// entries and the authenticated authority, it:
//
//  1. resolves the signer set (pk_i, weight_i) + totalWeight from the authority;
//  2. canonicalizes the entries (sort by NodeID, reject duplicates);
//  3. verifies every cert's ML-DSA-65 signature over subject under certCtx
//     (byte-identical to precompile 0x012205) using the AUTHORITY's key;
//  4. enforces membership (every NodeID is in the resolved set);
//  5. accumulates attestedWeight and checks attested/total >= threshold; and
//  6. builds the canonical Merkle commitment.
//
// It is STRICT: every supplied entry MUST verify, be known, and be distinct.
// The prover is responsible for assembling a clean cert set; the verifier holds
// the witness to the same standard.
func evalRelation(
	subject []byte,
	signerSetID ids.ID,
	eraHandle uint64,
	threshold warp.WeightThreshold,
	entries []CertEntry,
	authority warp.SignerSetAuthority,
) (quorum, error) {
	var q quorum
	if len(subject) != subjectLen {
		return q, ErrInvalidSubject
	}
	if err := validateThreshold(threshold); err != nil {
		return q, err
	}
	if authority == nil {
		return q, ErrNilAuthority
	}
	if len(entries) == 0 {
		return q, ErrEmptyCertSet
	}

	signers, totalWeight, err := authority.ResolveSignerSet(signerSetID, eraHandle)
	if err != nil {
		return q, wrap(ErrSignerSetUnresolved, err)
	}
	// Index the authenticated registry by NodeID. The key + weight ALWAYS come
	// from here, never from the witness.
	type keyWeight struct {
		pk     *mldsa.PublicKey
		weight uint64
	}
	reg := make(map[ids.NodeID]keyWeight, len(signers))
	for _, s := range signers {
		pk, perr := mldsa.PublicKeyFromBytes(s.PublicKey, mldsaMode)
		if perr != nil {
			return q, wrap(ErrSignerSetUnresolved, perr)
		}
		reg[s.NodeID] = keyWeight{pk: pk, weight: s.Weight}
	}

	// Canonicalize: sort by NodeID, reject duplicates. Sorting BEFORE building
	// the tree makes the root independent of input order (no reordering
	// malleability).
	sorted := make([]CertEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i].NodeID[:], sorted[j].NodeID[:]) < 0
	})
	for i := 1; i < len(sorted); i++ {
		if sorted[i].NodeID == sorted[i-1].NodeID {
			return q, ErrDuplicateSigner
		}
	}

	leaves := make([][32]byte, 0, len(sorted))
	var attested uint64
	for _, e := range sorted {
		kw, ok := reg[e.NodeID]
		if !ok {
			return q, ErrUnknownSigner
		}
		if len(e.Sig) != mldsaSigSize {
			return q, ErrBadCert
		}
		// FIPS 204 ML-DSA-65 verify under the P3Q context — the exact primitive
		// precompile 0x012205 runs (mldsa.PublicKey.VerifySignatureCtx).
		if !kw.pk.VerifySignatureCtx(subject, e.Sig, []byte(certCtx)) {
			return q, ErrBadCert
		}
		attested += kw.weight
		leaves = append(leaves, leafHash(e.NodeID, kw.pk.Bytes(), kw.weight))
	}

	if !meetsThreshold(attested, totalWeight, threshold.Numerator, threshold.Denominator) {
		return q, ErrThresholdNotMet
	}

	q.entries = sorted
	q.root = merkleRoot(leaves)
	q.attestedWeight = attested
	q.totalWeight = totalWeight
	return q, nil
}
