// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3qprover_test

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/crypto/mldsa"
	p3q "github.com/luxfi/p3q-prover"
	"github.com/stretchr/testify/require"
)

// TestCrossCheck_PrecompileCtx asserts the per-cert verification this rollup
// performs is byte-identical to the on-chain P3Q precompile (0x012205).
//
// precompile/p3q.Verify (contract.go:432) reduces to:
//
//	pk.VerifySignatureCtx(messageHash, sig, PrecompileCtx)   // contract.go:450/409
//	PrecompileCtx = []byte("lux-evm-precompile-p3q-v1")      // contract.go:226
//
// This rollup signs each cert over the 32-byte subject under the identical
// context, then verifies with the identical mldsa primitive. So every cert the
// rollup attests is ALSO a valid 0x012205 call. We don't import the precompile
// module (it pulls the full geth EVM graph into an offline prover); the
// equivalence is at the shared primitive + the byte-identical context.
func TestCrossCheck_PrecompileCtx(t *testing.T) {
	// 1. The context bytes match the precompile's PrecompileCtx verbatim.
	require.Equal(t, []byte("lux-evm-precompile-p3q-v1"), p3q.CrossCheckCtx())

	// 2. A cert signed under this context verifies via the same primitive the
	//    precompile runs (mldsa.PublicKey.VerifySignatureCtx).
	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)
	subject := randSubject(t) // a 32-byte messageHash, exactly the precompile's slot

	sig, err := sk.SignCtx(rand.Reader, subject, p3q.CrossCheckCtx())
	require.NoError(t, err)

	pk, err := mldsa.PublicKeyFromBytes(sk.PublicKey.Bytes(), mldsa.MLDSA65)
	require.NoError(t, err)
	require.True(t, pk.VerifySignatureCtx(subject, sig, p3q.CrossCheckCtx()),
		"cert must verify under the P3Q precompile context (0x012205 core)")

	// 3. Domain separation: a signature minted under the sibling Pulsar
	//    precompile context (0x012204) must NOT verify under the P3Q context —
	//    mirrors precompile/p3q TestP3Q_RejectsWrongContextDomainSeparation.
	pulsarCtx := []byte("lux-evm-precompile-pulsar-v1")
	wrongSig, err := sk.SignCtx(rand.Reader, subject, pulsarCtx)
	require.NoError(t, err)
	require.False(t, pk.VerifySignatureCtx(subject, wrongSig, p3q.CrossCheckCtx()),
		"a Pulsar-context signature must not verify under the P3Q context")
}
