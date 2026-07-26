// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3qprover_test

import (
	"testing"

	p3q "github.com/luxfi/p3q-prover"
	"github.com/luxfi/warp"
	"github.com/stretchr/testify/require"
)

// stubBeam is a trivially-accepting BeamVerifier so these tests exercise the
// P3Q lane in isolation through warp's real policy API (the Beam/BLS lane is
// out of scope here).
type stubBeam struct{}

func (stubBeam) VerifyBeam(_ []byte, _ warp.BitSetSignature) error { return nil }

// buildRecoveryCert assembles a TierRecovery QuasarCert whose P3Q lane is a real
// rollup over k signers, signed over the cert's consensus subject M.
func buildRecoveryCert(t *testing.T, a *testAuthority, k int) (*warp.QuasarCert, warp.P3QRoot) {
	t.Helper()
	params := warp.QuasarFinalityParams{
		Height:       100,
		Round:        1,
		SignerSetID:  a.setID,
		KeyEraID:     1,
		Generation:   0,
		PChainHeight: 50,
		PolicyID:     warp.PolicyIDForTier(warp.TierRecovery),
	}
	cert := &warp.QuasarCert{Subject: params}
	m := cert.SubjectBytes()
	subject := m[:]

	entries := certsForSubset(t, a, k, subject)
	certSet := p3q.CertSetEvidence(a.setID, params.Generation, entries)
	prover, err := p3q.NewProver(a, a.setID, twoThirds)
	require.NoError(t, err)
	root, err := prover.Prove(subject, certSet)
	require.NoError(t, err)

	cert.Beam = warp.BitSetSignature{}
	cert.P3QRoot = &root
	return cert, root
}

func recoveryLanes(a *testAuthority) warp.LaneVerifierSet {
	return warp.LaneVerifierSet{
		Beam:      stubBeam{},
		P3Q:       p3q.NewRollupVerifier(),
		SignerSet: a,
	}
}

// TestAcceptQuasarCert_Recovery_Accepts is the gold-standard e2e: a P3QRoot
// produced by this prover is admitted as a strict-PQ recovery root through
// warp's public AcceptQuasarCert — exercising the REAL dispatcher, the REAL
// claimed==proven binding, and the REAL strict-PQ-root gate.
func TestAcceptQuasarCert_Recovery_Accepts(t *testing.T) {
	a := newAuthority(t, 7, 1)
	cert, _ := buildRecoveryCert(t, a, 5)
	require.NoError(t, warp.AcceptQuasarCert(warp.TierRecovery, cert, recoveryLanes(a)))
}

// TestAcceptQuasarCert_Hybrid_Accepts: the same root satisfies the
// Beam ∧ (Pulsar ∨ P3Q) checkpoint tier via the P3Q arm.
func TestAcceptQuasarCert_Hybrid_Accepts(t *testing.T) {
	a := newAuthority(t, 7, 1)
	params := warp.QuasarFinalityParams{
		Height:      200,
		SignerSetID: a.setID,
		PolicyID:    warp.PolicyIDForTier(warp.TierHybridPQCheckpoint),
	}
	cert := &warp.QuasarCert{Subject: params}
	m := cert.SubjectBytes()
	subject := m[:]
	entries := certsForSubset(t, a, 5, subject)
	prover, err := p3q.NewProver(a, a.setID, twoThirds)
	require.NoError(t, err)
	root, err := prover.Prove(subject, p3q.CertSetEvidence(a.setID, 0, entries))
	require.NoError(t, err)
	cert.Beam = warp.BitSetSignature{}
	cert.P3QRoot = &root
	require.NoError(t, warp.AcceptQuasarCert(warp.TierHybridPQCheckpoint, cert, recoveryLanes(a)))
}

// TestAcceptQuasarCert_RejectsRelabeledPQSystem: claiming "stark-rescue" while
// the verifier actually proves "none" is caught by warp's claimed==proven bind.
func TestAcceptQuasarCert_RejectsRelabeledPQSystem(t *testing.T) {
	a := newAuthority(t, 7, 1)
	cert, root := buildRecoveryCert(t, a, 5)

	// Relabel the (PQ-admissible) system to a different PQ system the verifier
	// did NOT prove. Strict gate passes (stark-rescue is PQ), so the mismatch
	// binding is what must fire.
	root.ProvingSystem = p3q.ProvingSystemStarkRescue
	cert.P3QRoot = &root
	err := warp.AcceptQuasarCert(warp.TierRecovery, cert, recoveryLanes(a))
	// satisfyGroup collapses a failing P3Q-only group into ErrMissingLane, but
	// the CAUSE is warp's claimed==proven binding (verifyFinalityEvidence):
	// the verifier proved "none", the root claimed "stark-rescue".
	require.ErrorIs(t, err, warp.ErrMissingLane)
	require.ErrorContains(t, err, "P3Q proving system does not match")
	require.ErrorContains(t, err, `verifier proved "none"`)
}

// TestAcceptQuasarCert_RejectsClassicalRoot: relabeling to a classical system
// (groth16) is refused by the strict-PQ-root guardrail before verification.
func TestAcceptQuasarCert_RejectsClassicalRoot(t *testing.T) {
	a := newAuthority(t, 7, 1)
	cert, root := buildRecoveryCert(t, a, 5)

	root.ProvingSystem = "groth16"
	cert.P3QRoot = &root
	err := warp.AcceptQuasarCert(warp.TierRecovery, cert, recoveryLanes(a))
	require.ErrorIs(t, err, warp.ErrP3QClassicalRoot)
}

// TestAcceptQuasarCert_ClassicalRoot_OptInThenMismatch: with the explicit
// opt-in, the strict gate is bypassed, but the claimed("groth16") vs
// proven("none") binding still fails closed.
func TestAcceptQuasarCert_ClassicalRoot_OptInThenMismatch(t *testing.T) {
	a := newAuthority(t, 7, 1)
	cert, root := buildRecoveryCert(t, a, 5)

	root.ProvingSystem = "groth16"
	cert.P3QRoot = &root
	err := warp.AcceptQuasarCert(warp.TierRecovery, cert, recoveryLanes(a), warp.WithAllowClassicalP3QRoot())
	// Opt-in bypasses the strict-PQ-root gate; the claimed("groth16") vs
	// proven("none") binding still fails closed (collapsed into ErrMissingLane).
	require.ErrorIs(t, err, warp.ErrMissingLane)
	require.ErrorContains(t, err, "P3Q proving system does not match")
}

// TestAcceptQuasarCert_RejectsTamperedRoot: corrupting the commitment makes the
// P3Q lane fail, so the required recovery group is unsatisfied.
func TestAcceptQuasarCert_RejectsTamperedRoot(t *testing.T) {
	a := newAuthority(t, 7, 1)
	cert, root := buildRecoveryCert(t, a, 5)
	root.Root[0] ^= 0x01
	cert.P3QRoot = &root
	err := warp.AcceptQuasarCert(warp.TierRecovery, cert, recoveryLanes(a))
	require.ErrorIs(t, err, warp.ErrMissingLane) // group unsatisfied (last err = ErrRootMismatch)
}
