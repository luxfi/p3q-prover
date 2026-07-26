// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3qprover

import (
	"bytes"

	"github.com/luxfi/warp"
)

// RollupVerifier is the reference warp.P3QRollupVerifier for the P3Q rollup
// lane. It is SOUND but O(N): it re-runs the relation R against the witness
// carried in P3QRoot.Proof and the authenticated authority, so it is the
// executable specification / oracle for the succinct (FRI) instantiation. The
// succinct verifier replaces the witness re-check with a polylog FRI check over
// the SAME public inputs and root; the interface here is final.
//
// It returns the proof system it ACTUALLY verified ("none" for BackendDirect),
// satisfying the warp v1.23.0 claimed==proven binding.
type RollupVerifier struct{}

var _ warp.P3QRollupVerifier = RollupVerifier{}

// NewRollupVerifier returns the reference P3Q rollup verifier.
func NewRollupVerifier() RollupVerifier { return RollupVerifier{} }

// VerifyP3QRollup verifies root over subject against authority and returns the
// proven proof system. On any failure it returns ("", err) so the dispatcher's
// claimed==proven check can never see a spurious match.
func (RollupVerifier) VerifyP3QRollup(subject []byte, root warp.P3QRoot, authority warp.SignerSetAuthority) (string, error) {
	if len(subject) != subjectLen {
		return "", ErrInvalidSubject
	}
	if root.SuiteID != suiteID {
		return "", ErrWrongSuite
	}
	if authority == nil {
		return "", ErrNilAuthority
	}

	payload, err := decodeProof(root.Proof)
	if err != nil {
		return "", err
	}

	switch payload.backend {
	case BackendDirect:
		return verifyDirect(subject, root, payload, authority)
	case BackendStarkFRI:
		// The succinct backend's verifier is the flagged gap. Fail closed.
		return "", ErrStarkBackendUnavailable
	default:
		return "", ErrUnknownBackend
	}
}

// verifyDirect re-runs R against the witness and binds every P3QRoot field via
// the root commitment + the public-input digest. Returns "none" on success.
func verifyDirect(subject []byte, root warp.P3QRoot, payload proofPayload, authority warp.SignerSetAuthority) (string, error) {
	q, err := evalRelation(subject, root.SignerSetID, root.EraHandle, root.Threshold, payload.entries, authority)
	if err != nil {
		return "", err
	}

	// 1. The advertised commitment must match the witness.
	if !bytes.Equal(q.root[:], root.Root) {
		return "", ErrRootMismatch
	}

	// 2. The proof's attested-weight field must match the witness sum.
	if q.attestedWeight != payload.attestedWeight {
		return "", ErrAttestedWeightMismatch
	}

	// 3. The public-input digest must bind every other P3QRoot field
	//    (signerSetID, eraHandle, threshold, totalWeight, attestedWeight, root,
	//    nSigners). Any tampering with the root struct flips PI and is rejected.
	pi := publicInputs(subject, root.SignerSetID, root.EraHandle, root.Threshold,
		q.totalWeight, q.attestedWeight, q.root, len(q.entries))
	if pi != payload.pi {
		return "", ErrPublicInputMismatch
	}

	// Report the system actually verified. BackendDirect has no succinct
	// wrapper, so the PQ root of trust is the ML-DSA-65 signatures themselves.
	return ProvingSystemNone, nil
}
