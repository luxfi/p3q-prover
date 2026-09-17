// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3qprover_test

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/ids"
	p3q "github.com/luxfi/p3q-prover"
	"github.com/luxfi/warp"
	"github.com/stretchr/testify/require"
)

// validator is a test signer: identity, ML-DSA-65 key, stake weight.
type validator struct {
	nodeID  ids.NodeID
	sk      *mldsa.PrivateKey
	pkBytes []byte
	weight  uint64
}

// testAuthority is a stand-in for the authenticated on-chain signer-set
// registry (warp.SignerSetAuthority). Both prover and verifier resolve keys +
// weights from it — never from the witness.
type testAuthority struct {
	setID ids.ID
	vals  []validator
	total uint64
	fail  bool // when true, simulate an unresolvable signer set
}

func (a *testAuthority) ResolveSignerSet(setID ids.ID, _ uint64) ([]warp.ValidatorMLDSAKey, uint64, error) {
	if a.fail {
		return nil, 0, errors.New("authority offline")
	}
	if setID != a.setID {
		return nil, 0, errors.New("unknown signer set")
	}
	out := make([]warp.ValidatorMLDSAKey, len(a.vals))
	for i, v := range a.vals {
		out[i] = warp.ValidatorMLDSAKey{NodeID: v.nodeID, PublicKey: v.pkBytes, Weight: v.weight}
	}
	return out, a.total, nil
}

// newAuthority generates n validators each with the given weight and a fresh
// random signer-set ID.
func newAuthority(t *testing.T, n int, weight uint64) *testAuthority {
	t.Helper()
	var setID ids.ID
	_, err := rand.Read(setID[:])
	require.NoError(t, err)

	a := &testAuthority{setID: setID, vals: make([]validator, 0, n)}
	for range n {
		var id ids.NodeID
		_, err := rand.Read(id[:])
		require.NoError(t, err)
		sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
		require.NoError(t, err)
		a.vals = append(a.vals, validator{
			nodeID:  id,
			sk:      sk,
			pkBytes: sk.PublicKey.Bytes(),
			weight:  weight,
		})
		a.total += weight
	}
	return a
}

// certFor produces validator v's ML-DSA-65 cert over subject under the P3Q
// context (CrossCheckCtx) — the exact convention precompile 0x012205 verifies.
func certFor(t *testing.T, v validator, subject []byte) p3q.CertEntry {
	t.Helper()
	sig, err := v.sk.SignCtx(rand.Reader, subject, p3q.CrossCheckCtx())
	require.NoError(t, err)
	return p3q.CertEntry{NodeID: v.nodeID, Sig: sig}
}

// certsForSubset signs the first k validators over subject.
func certsForSubset(t *testing.T, a *testAuthority, k int, subject []byte) []p3q.CertEntry {
	t.Helper()
	entries := make([]p3q.CertEntry, 0, k)
	for i := range k {
		entries = append(entries, certFor(t, a.vals[i], subject))
	}
	return entries
}

// twoThirds is the canonical supermajority threshold.
var twoThirds = warp.WeightThreshold{Numerator: 2, Denominator: 3}

// randSubject returns a fresh 32-byte subject.
func randSubject(t *testing.T) []byte {
	t.Helper()
	s := make([]byte, 32)
	_, err := rand.Read(s)
	require.NoError(t, err)
	return s
}
