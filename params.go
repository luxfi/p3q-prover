// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3qprover

import (
	"errors"
	"fmt"
	"math/bits"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/warp"
)

// wrap annotates a sentinel error with an underlying cause while keeping the
// sentinel matchable via errors.Is.
func wrap(sentinel, cause error) error {
	return fmt.Errorf("%w: %v", sentinel, cause)
}

// Mode is fixed to ML-DSA-65 (NIST Category 3, the Lux production target). The
// wire encodings still carry a mode byte so a future parameter set (44/87) is a
// strict, self-describing extension rather than a silent reinterpretation.
const (
	modeMLDSA65 byte = 0x65

	mldsaMode    = mldsa.MLDSA65
	mldsaSigSize = mldsa.MLDSA65SignatureSize // 3309

	// subjectLen is the fixed width of a warp finality subject (D or M).
	subjectLen = 32

	// nodeIDLen is the byte width of an ids.NodeID (ShortID).
	nodeIDLen = 20
)

// Per-cert FIPS 204 context. This is byte-identical to
// luxfi/precompile/p3q.PrecompileCtx (contract.go:226), so a cert this prover
// rolls up ALSO verifies on the on-chain precompile at 0x012205. Exposed via
// CrossCheckCtx for callers that want to assert the equivalence directly.
const certCtx = "lux-evm-precompile-p3q-v1"

// CrossCheckCtx is the FIPS 204 context every rolled-up cert is signed/verified
// under. It equals luxfi/precompile/p3q.PrecompileCtx, so each cert is a valid
// 0x012205 call: precompile/p3q.Verify(ModeMLDSA65, pk, sig, subject) == nil.
func CrossCheckCtx() []byte { return []byte(certCtx) }

// Domain-separation tags for the SHA3-256 (FIPS 202) commitment. Distinct
// per role so a node digest can never be reinterpreted as a leaf digest
// (second-preimage resistance) and the public-input digest never collides with
// a tree digest.
const (
	leafDST = "LUX-WARP-P3Q-LEAF-v1"
	nodeDST = "LUX-WARP-P3Q-NODE-v1"
	pkDST   = "LUX-WARP-P3Q-PK-v1"
	piDST   = "LUX-WARP-P3Q-PI-v1"

	// emptyMarker marks the (degenerate) empty-set commitment. An empty quorum
	// never meets a positive threshold, so this only exists to keep merkleRoot
	// total.
	emptyMarker = "LUX-WARP-P3Q-EMPTY-v1"
)

// Wire magics.
const (
	certSetMagic = "P3QC" // canonical CertSetEvidence.CertSet encoding
	proofMagic   = "P3QR" // P3QRoot.Proof encoding (reference backend)
	wireVersion  = 0x01
)

// Backend selects which proof system a P3QRoot is produced/verified under. It
// is encoded as a single byte in P3QRoot.Proof so the verifier returns EXACTLY
// the system it executed.
type Backend byte

const (
	// BackendDirect re-verifies the ML-DSA-65 signatures directly. Proven
	// system "none" (no succinct wrapper); SOUND but O(N). Built + tested.
	BackendDirect Backend = 0x01

	// BackendStarkFRI is the SUCCINCT instantiation (a FRI/STARK proof of R over
	// the strict-PQ Plonky3 fork). Proven system "stark-rescue". NOT built —
	// Prove/Verify return ErrStarkBackendUnavailable. This is the flagged gap.
	BackendStarkFRI Backend = 0x02
)

// Proven-system strings (warp.IsPQRootOfTrust is case-insensitive).
const (
	// ProvingSystemNone: the reference backend. No succinct wrapper; the PQ root
	// of trust is the ML-DSA-65 signatures themselves. PQ-admissible.
	ProvingSystemNone = "none"

	// ProvingSystemStarkRescue: the succinct backend's system. PQ-admissible.
	ProvingSystemStarkRescue = "stark-rescue"
)

// provenSystemFor maps a backend to the proof-system string it MUST report so
// the warp claimed==proven binding holds.
func provenSystemFor(b Backend) (string, error) {
	switch b {
	case BackendDirect:
		return ProvingSystemNone, nil
	case BackendStarkFRI:
		return ProvingSystemStarkRescue, ErrStarkBackendUnavailable
	default:
		return "", ErrUnknownBackend
	}
}

// Errors.
var (
	ErrInvalidSubject          = errors.New("p3qprover: subject must be 32 bytes")
	ErrEmptyCertSet            = errors.New("p3qprover: cert set is empty")
	ErrMalformedCertSet        = errors.New("p3qprover: malformed cert-set encoding")
	ErrMalformedProof          = errors.New("p3qprover: malformed proof encoding")
	ErrUnsupportedMode         = errors.New("p3qprover: unsupported ML-DSA mode (only 0x65 / ML-DSA-65)")
	ErrUnknownSigner           = errors.New("p3qprover: cert references a signer absent from the resolved signer set")
	ErrDuplicateSigner         = errors.New("p3qprover: duplicate signer in cert set")
	ErrBadCert                 = errors.New("p3qprover: ML-DSA-65 signature did not verify")
	ErrThresholdNotMet         = errors.New("p3qprover: attested weight does not meet the threshold")
	ErrRootMismatch            = errors.New("p3qprover: recomputed commitment root does not match P3QRoot.Root")
	ErrPublicInputMismatch     = errors.New("p3qprover: recomputed public inputs do not match the proof")
	ErrAttestedWeightMismatch  = errors.New("p3qprover: proof attested-weight field is inconsistent with the witness")
	ErrSignerSetUnresolved     = errors.New("p3qprover: signer-set authority failed")
	ErrNilAuthority            = errors.New("p3qprover: nil signer-set authority")
	ErrWrongSuite              = errors.New("p3qprover: P3QRoot.SuiteID is not the P3Q rollup suite")
	ErrUnknownBackend          = errors.New("p3qprover: unknown proof backend")
	ErrInvalidThreshold        = errors.New("p3qprover: threshold must have 0 < numerator <= denominator")
	ErrStarkBackendUnavailable = errors.New(
		"p3qprover: stark-rescue FRI backend not built — the P3Q AIR + Plonky3 prover/verifier (precompile 0x012220) is the flagged gap")
)

// suiteID is the fixed P3Q rollup suite this prover/verifier speaks.
const suiteID = warp.SuiteP3QMLDSARollup

// validateThreshold enforces 0 < num <= den.
func validateThreshold(t warp.WeightThreshold) error {
	if t.Denominator == 0 || t.Numerator == 0 || t.Numerator > t.Denominator {
		return ErrInvalidThreshold
	}
	return nil
}

// meetsThreshold reports attested/total >= num/den using an exact 128-bit
// cross-multiply (no floating point, overflow-safe): attested*den >= total*num.
// total==0 (empty/degenerate set) never meets a positive threshold.
func meetsThreshold(attested, total, num, den uint64) bool {
	if total == 0 {
		return false
	}
	hiA, loA := bits.Mul64(attested, den)
	hiB, loB := bits.Mul64(total, num)
	if hiA != hiB {
		return hiA > hiB
	}
	return loA >= loB
}
