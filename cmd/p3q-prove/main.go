// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command p3q-prove is a self-contained demonstration of the offline P3Q
// rollup prover: it generates N ML-DSA-65 validators, signs a subject with a
// quorum subset, rolls them up into a warp.P3QRoot, and verifies the root with
// the reference verifier — printing the compact root and the proven system.
//
// It is the runnable smoke / manual e2e. Production callers use the library
// (p3qprover.NewProver / NewRollupVerifier) with their authenticated
// SignerSetAuthority and real cert sets.
//
//	go run ./cmd/p3q-prove -n 7 -k 5
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/ids"
	p3q "github.com/luxfi/p3q-prover"
	"github.com/luxfi/warp"
)

type demoValidator struct {
	id     ids.NodeID
	sk     *mldsa.PrivateKey
	pk     []byte
	weight uint64
}

type demoAuthority struct {
	setID ids.ID
	vals  []demoValidator
	total uint64
}

func (a *demoAuthority) ResolveSignerSet(setID ids.ID, _ uint64) ([]warp.ValidatorMLDSAKey, uint64, error) {
	if setID != a.setID {
		return nil, 0, fmt.Errorf("unknown signer set")
	}
	out := make([]warp.ValidatorMLDSAKey, len(a.vals))
	for i, v := range a.vals {
		out[i] = warp.ValidatorMLDSAKey{NodeID: v.id, PublicKey: v.pk, Weight: v.weight}
	}
	return out, a.total, nil
}

func main() {
	n := flag.Int("n", 7, "number of validators in the signer set")
	k := flag.Int("k", 5, "number of signers that produced a cert (the quorum subset)")
	num := flag.Uint64("num", 2, "threshold numerator")
	den := flag.Uint64("den", 3, "threshold denominator")
	flag.Parse()

	if err := run(*n, *k, warp.WeightThreshold{Numerator: *num, Denominator: *den}); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(n, k int, threshold warp.WeightThreshold) error {
	if k > n {
		return fmt.Errorf("k (%d) must be <= n (%d)", k, n)
	}

	// 1. Build an authenticated signer set of N ML-DSA-65 validators.
	a := &demoAuthority{}
	if _, err := rand.Read(a.setID[:]); err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		var id ids.NodeID
		if _, err := rand.Read(id[:]); err != nil {
			return err
		}
		sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
		if err != nil {
			return err
		}
		a.vals = append(a.vals, demoValidator{id: id, sk: sk, pk: sk.PublicKey.Bytes(), weight: 1})
		a.total++
	}

	// 2. A 32-byte finality subject, and K independent certs over it.
	subject := make([]byte, 32)
	if _, err := rand.Read(subject); err != nil {
		return err
	}
	entries := make([]p3q.CertEntry, 0, k)
	for i := 0; i < k; i++ {
		sig, err := a.vals[i].sk.SignCtx(rand.Reader, subject, p3q.CrossCheckCtx())
		if err != nil {
			return err
		}
		entries = append(entries, p3q.CertEntry{NodeID: a.vals[i].id, Sig: sig})
	}
	certSet := p3q.CertSetEvidence(a.setID, 1, entries)

	// 3. Prove: roll up the K independent certs into a succinct P3QRoot.
	prover, err := p3q.NewProver(a, a.setID, threshold)
	if err != nil {
		return err
	}
	root, err := prover.Prove(subject, certSet)
	if err != nil {
		return err
	}

	// 4. Verify with the reference verifier and report the proven system.
	proven, err := p3q.NewRollupVerifier().VerifyP3QRollup(subject, root, a)
	if err != nil {
		return err
	}

	fmt.Printf("P3Q rollup over %d/%d ML-DSA-65 signers, threshold %d/%d\n",
		k, n, threshold.Numerator, threshold.Denominator)
	fmt.Printf("  subject       : %s\n", hex.EncodeToString(subject))
	fmt.Printf("  commitment    : %s  (%d bytes, the O(1) chain artifact)\n", hex.EncodeToString(root.Root), len(root.Root))
	fmt.Printf("  proving system: %q  (PQ root of trust: %v)\n", root.ProvingSystem, warp.IsPQRootOfTrust(root.ProvingSystem))
	fmt.Printf("  proof bytes   : %d  (reference witness — NOT succinct; a FRI proof replaces this)\n", len(root.Proof))
	fmt.Printf("  cert-set bytes: %d  (the rollup INPUT)\n", len(certSet.CertSet))
	fmt.Printf("  note          : commitment is O(1); reference proof+verify are O(N). Succinct O(polylog N) = the FRI backend (gap).\n")
	fmt.Printf("  verify        : OK, proven system = %q (claimed == proven)\n", proven)
	if root.ProvingSystem != proven {
		return fmt.Errorf("claimed/proven mismatch: %q != %q", root.ProvingSystem, proven)
	}
	if err := warp.P3QStrictRootOK(root); err != nil {
		return fmt.Errorf("strict-PQ root gate: %w", err)
	}
	fmt.Println("  strict-PQ root: admissible")
	return nil
}
