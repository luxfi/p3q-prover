// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3qprover_test

import (
	"bytes"
	"testing"

	p3q "github.com/luxfi/p3q-prover"
	"github.com/luxfi/warp"
	"github.com/stretchr/testify/require"
)

// TestProveVerify_RoundTrip is the load-bearing e2e: N real ML-DSA-65 keypairs
// sign a subject, the prover rolls them up into a P3QRoot, and the reference
// verifier accepts it AND reports a post-quantum proof system whose string
// round-trips through warp's claimed==proven binding.
func TestProveVerify_RoundTrip(t *testing.T) {
	a := newAuthority(t, 7, 1) // total weight 7
	subject := randSubject(t)

	// 5-of-7 meets 2/3 (5*3 = 15 >= 7*2 = 14).
	entries := certsForSubset(t, a, 5, subject)
	certSet := p3q.CertSetEvidence(a.setID, 42, entries)

	prover, err := p3q.NewProver(a, a.setID, twoThirds)
	require.NoError(t, err)

	root, err := prover.Prove(subject, certSet)
	require.NoError(t, err)

	// The P3QRoot is well-formed and carries the fixed P3Q lane shape.
	require.Equal(t, warp.SuiteP3QMLDSARollup, root.SuiteID)
	require.Equal(t, a.setID, root.SignerSetID)
	require.Equal(t, uint64(42), root.EraHandle)
	require.Equal(t, twoThirds, root.Threshold)
	require.Len(t, root.Root, 32, "commitment root is the O(1) chain artifact")
	require.Equal(t, p3q.ProvingSystemNone, root.ProvingSystem)

	// The reference verifier accepts and reports the system it actually proved.
	proven, err := p3q.NewRollupVerifier().VerifyP3QRollup(subject, root, a)
	require.NoError(t, err)
	require.Equal(t, p3q.ProvingSystemNone, proven)

	// Claimed == proven (the v1.23.0 dispatcher invariant), and the system is a
	// PQ root of trust (so the root is strict-PQ admissible).
	require.Equal(t, root.ProvingSystem, proven)
	require.True(t, warp.IsPQRootOfTrust(proven))
	require.NoError(t, warp.P3QStrictRootOK(root))
}

// TestProve_RejectsThresholdNotMet: a sub-quorum cert set is refused by the
// prover (4-of-7 fails 2/3).
func TestProve_RejectsThresholdNotMet(t *testing.T) {
	a := newAuthority(t, 7, 1)
	subject := randSubject(t)
	entries := certsForSubset(t, a, 4, subject) // 4*3 = 12 < 14
	certSet := p3q.CertSetEvidence(a.setID, 1, entries)

	prover, err := p3q.NewProver(a, a.setID, twoThirds)
	require.NoError(t, err)
	_, err = prover.Prove(subject, certSet)
	require.ErrorIs(t, err, p3q.ErrThresholdNotMet)
}

// TestProve_RejectsForgedSignature: a corrupted signature for a known signer is
// rejected by the real FIPS-204 verify inside the relation.
func TestProve_RejectsForgedSignature(t *testing.T) {
	a := newAuthority(t, 5, 1)
	subject := randSubject(t)
	entries := certsForSubset(t, a, 5, subject)
	entries[2].Sig[100] ^= 0x01 // flip one bit
	certSet := p3q.CertSetEvidence(a.setID, 1, entries)

	prover, err := p3q.NewProver(a, a.setID, twoThirds)
	require.NoError(t, err)
	_, err = prover.Prove(subject, certSet)
	require.ErrorIs(t, err, p3q.ErrBadCert)
}

// TestProve_RejectsUnknownSigner: a cert whose NodeID is not in the resolved
// signer set is rejected (membership).
func TestProve_RejectsUnknownSigner(t *testing.T) {
	a := newAuthority(t, 5, 1)
	subject := randSubject(t)
	entries := certsForSubset(t, a, 5, subject)
	entries[0].NodeID[0] ^= 0xFF // mutate into an id not in the set
	certSet := p3q.CertSetEvidence(a.setID, 1, entries)

	prover, err := p3q.NewProver(a, a.setID, twoThirds)
	require.NoError(t, err)
	_, err = prover.Prove(subject, certSet)
	require.ErrorIs(t, err, p3q.ErrUnknownSigner)
}

// TestProve_RejectsDuplicateSigner: the same validator counted twice is
// rejected (one validator, one vote).
func TestProve_RejectsDuplicateSigner(t *testing.T) {
	a := newAuthority(t, 7, 1)
	subject := randSubject(t)
	entries := certsForSubset(t, a, 5, subject)
	entries = append(entries, entries[0]) // duplicate signer 0
	certSet := p3q.CertSetEvidence(a.setID, 1, entries)

	prover, err := p3q.NewProver(a, a.setID, twoThirds)
	require.NoError(t, err)
	_, err = prover.Prove(subject, certSet)
	require.ErrorIs(t, err, p3q.ErrDuplicateSigner)
}

// TestProve_SubjectBinding: certs over subject A do not roll up under subject B
// (each ML-DSA sig is over the subject).
func TestProve_SubjectBinding(t *testing.T) {
	a := newAuthority(t, 7, 1)
	subjectA := randSubject(t)
	subjectB := randSubject(t)
	entries := certsForSubset(t, a, 5, subjectA)
	certSet := p3q.CertSetEvidence(a.setID, 1, entries)

	prover, err := p3q.NewProver(a, a.setID, twoThirds)
	require.NoError(t, err)
	_, err = prover.Prove(subjectB, certSet)
	require.ErrorIs(t, err, p3q.ErrBadCert)
}

// TestVerify_RejectsTamperedRoot: flipping a byte of the advertised commitment
// breaks the witness↔root binding.
func TestVerify_RejectsTamperedRoot(t *testing.T) {
	a := newAuthority(t, 7, 1)
	subject := randSubject(t)
	root := mustProve(t, a, subject, 5)

	root.Root[0] ^= 0x01
	_, err := p3q.NewRollupVerifier().VerifyP3QRollup(subject, root, a)
	require.ErrorIs(t, err, p3q.ErrRootMismatch)
}

// TestVerify_RejectsTamperedField: mutating any bound P3QRoot field (here
// EraHandle and Threshold) flips the public-input digest.
func TestVerify_RejectsTamperedField(t *testing.T) {
	a := newAuthority(t, 7, 1)
	subject := randSubject(t)

	root := mustProve(t, a, subject, 5)
	root.EraHandle++
	_, err := p3q.NewRollupVerifier().VerifyP3QRollup(subject, root, a)
	require.ErrorIs(t, err, p3q.ErrPublicInputMismatch)

	root2 := mustProve(t, a, subject, 5)
	root2.Threshold = warp.WeightThreshold{Numerator: 1, Denominator: 3} // lower the bar
	_, err = p3q.NewRollupVerifier().VerifyP3QRollup(subject, root2, a)
	require.ErrorIs(t, err, p3q.ErrPublicInputMismatch)
}

// TestVerify_RejectsWrongSuite: a non-P3Q suite is refused before any crypto.
func TestVerify_RejectsWrongSuite(t *testing.T) {
	a := newAuthority(t, 7, 1)
	subject := randSubject(t)
	root := mustProve(t, a, subject, 5)
	root.SuiteID = warp.SuiteBeamBLS12381
	_, err := p3q.NewRollupVerifier().VerifyP3QRollup(subject, root, a)
	require.ErrorIs(t, err, p3q.ErrWrongSuite)
}

// TestVerify_RejectsMalformedProof: garbage proof bytes fail closed.
func TestVerify_RejectsMalformedProof(t *testing.T) {
	a := newAuthority(t, 7, 1)
	subject := randSubject(t)
	root := mustProve(t, a, subject, 5)
	root.Proof = bytes.Repeat([]byte{0xAB}, 64)
	_, err := p3q.NewRollupVerifier().VerifyP3QRollup(subject, root, a)
	require.ErrorIs(t, err, p3q.ErrMalformedProof)
}

// TestVerify_RejectsUnresolvableAuthority: if the authority cannot resolve the
// signer set, verification fails closed.
func TestVerify_RejectsUnresolvableAuthority(t *testing.T) {
	a := newAuthority(t, 7, 1)
	subject := randSubject(t)
	root := mustProve(t, a, subject, 5)

	a.fail = true
	_, err := p3q.NewRollupVerifier().VerifyP3QRollup(subject, root, a)
	require.ErrorIs(t, err, p3q.ErrSignerSetUnresolved)
}

// TestVerify_NilAuthority fails closed.
func TestVerify_NilAuthority(t *testing.T) {
	a := newAuthority(t, 7, 1)
	subject := randSubject(t)
	root := mustProve(t, a, subject, 5)
	_, err := p3q.NewRollupVerifier().VerifyP3QRollup(subject, root, nil)
	require.ErrorIs(t, err, p3q.ErrNilAuthority)
}

// TestStarkBackend_Unavailable: selecting the succinct backend refuses to
// produce a root (the prover never lies about "stark-rescue").
func TestStarkBackend_Unavailable(t *testing.T) {
	a := newAuthority(t, 7, 1)
	subject := randSubject(t)
	entries := certsForSubset(t, a, 5, subject)
	certSet := p3q.CertSetEvidence(a.setID, 1, entries)

	prover, err := p3q.NewProver(a, a.setID, twoThirds, p3q.WithBackend(p3q.BackendStarkFRI))
	require.NoError(t, err)
	_, err = prover.Prove(subject, certSet)
	require.ErrorIs(t, err, p3q.ErrStarkBackendUnavailable)
}

// TestProve_InvalidInputs covers the construction/argument guards.
func TestProve_InvalidInputs(t *testing.T) {
	a := newAuthority(t, 7, 1)

	_, err := p3q.NewProver(nil, a.setID, twoThirds)
	require.ErrorIs(t, err, p3q.ErrNilAuthority)

	_, err = p3q.NewProver(a, a.setID, warp.WeightThreshold{Numerator: 4, Denominator: 3})
	require.ErrorIs(t, err, p3q.ErrInvalidThreshold)

	prover, err := p3q.NewProver(a, a.setID, twoThirds)
	require.NoError(t, err)

	_, err = prover.Prove(make([]byte, 31), p3q.CertSetEvidence(a.setID, 1, nil))
	require.ErrorIs(t, err, p3q.ErrInvalidSubject)

	subject := randSubject(t)
	_, err = prover.Prove(subject, p3q.CertSetEvidence(a.setID, 1, nil))
	require.ErrorIs(t, err, p3q.ErrEmptyCertSet)
}

// mustProve is a helper producing a valid P3QRoot from the first k signers.
func mustProve(t *testing.T, a *testAuthority, subject []byte, k int) warp.P3QRoot {
	t.Helper()
	entries := certsForSubset(t, a, k, subject)
	certSet := p3q.CertSetEvidence(a.setID, 7, entries)
	prover, err := p3q.NewProver(a, a.setID, twoThirds)
	require.NoError(t, err)
	root, err := prover.Prove(subject, certSet)
	require.NoError(t, err)
	return root
}
