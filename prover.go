// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3qprover

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
)

// Prover is the offline P3Q rollup prover. It implements warp.P3QProver.
//
// It is constructed with the quorum context it proves for — the authenticated
// signer-set authority, the signer-set ID, the required threshold, and the
// proof backend — because warp.P3QProver.Prove(subject, certSet) carries
// neither the authority nor the signer-set ID (the cert set names only its
// ChainID + EraHandle).
type Prover struct {
	authority   warp.SignerSetAuthority
	signerSetID ids.ID
	threshold   warp.WeightThreshold
	backend     Backend
}

var _ warp.P3QProver = (*Prover)(nil)

// Option configures a Prover.
type Option func(*Prover)

// WithBackend selects the proof backend (default BackendDirect). BackendStarkFRI
// is not built and makes Prove return ErrStarkBackendUnavailable.
func WithBackend(b Backend) Option { return func(p *Prover) { p.backend = b } }

// NewProver returns a Prover for the given signer set + threshold, resolving
// keys/weights through authority. The default backend is BackendDirect (proven
// system "none").
func NewProver(authority warp.SignerSetAuthority, signerSetID ids.ID, threshold warp.WeightThreshold, opts ...Option) (*Prover, error) {
	if authority == nil {
		return nil, ErrNilAuthority
	}
	if err := validateThreshold(threshold); err != nil {
		return nil, err
	}
	p := &Prover{
		authority:   authority,
		signerSetID: signerSetID,
		threshold:   threshold,
		backend:     BackendDirect,
	}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

// Prove rolls up the independent ML-DSA-65 certificates in certSet over subject
// into a succinct warp.P3QRoot. It performs the REAL relation R: every cert is
// FIPS-204 verified against its authority-resolved key, membership/distinctness
// are enforced, and the weighted quorum is checked, before any commitment is
// formed. The produced root's ProvingSystem is exactly the system the matching
// verifier will report ("none" for BackendDirect), so the warp claimed==proven
// binding holds by construction.
func (p *Prover) Prove(subject []byte, certSet warp.CertSetEvidence) (warp.P3QRoot, error) {
	var zero warp.P3QRoot

	// The succinct backend is the flagged gap: refuse rather than emit a root
	// that falsely claims "stark-rescue".
	if p.backend == BackendStarkFRI {
		return zero, ErrStarkBackendUnavailable
	}
	if p.backend != BackendDirect {
		return zero, ErrUnknownBackend
	}

	if len(subject) != subjectLen {
		return zero, ErrInvalidSubject
	}

	entries, err := decodeCertSet(certSet.CertSet)
	if err != nil {
		return zero, err
	}

	q, err := evalRelation(subject, p.signerSetID, certSet.EraHandle, p.threshold, entries, p.authority)
	if err != nil {
		return zero, err
	}

	pi := publicInputs(subject, p.signerSetID, certSet.EraHandle, p.threshold,
		q.totalWeight, q.attestedWeight, q.root, len(q.entries))

	proof := encodeProof(proofPayload{
		backend:        BackendDirect,
		pi:             pi,
		attestedWeight: q.attestedWeight,
		entries:        q.entries,
	})

	provenSystem, _ := provenSystemFor(BackendDirect) // ("none", nil)

	root := q.root
	return warp.P3QRoot{
		SignerSetID:   p.signerSetID,
		EraHandle:     certSet.EraHandle,
		Root:          root[:],
		Proof:         proof,
		ProvingSystem: provenSystem,
		Threshold:     p.threshold,
		SuiteID:       suiteID,
	}, nil
}
