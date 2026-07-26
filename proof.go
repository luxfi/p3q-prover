// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3qprover

// proofPayload is the decoded P3QRoot.Proof for the reference (BackendDirect)
// backend. It carries the witness (the verified subset's signatures) plus the
// bound public-input digest and attested weight. For BackendStarkFRI this
// payload is replaced by a FRI proof; the surrounding P3QRoot fields (Root,
// SignerSetID, EraHandle, Threshold, SuiteID) are unchanged.
type proofPayload struct {
	backend        Backend
	pi             [32]byte
	attestedWeight uint64
	entries        []CertEntry
}

// encodeProof serializes the reference proof envelope.
//
// Layout:
//
//	[4]  magic "P3QR"
//	[1]  version
//	[1]  backend
//	[1]  mode (0x65)
//	[32] PI digest
//	[8]  attestedWeight (BE)
//	[4]  N (BE uint32)
//	N ×  entry{ [20] nodeID | [4] sigLen (BE) | [sigLen] sig }
func encodeProof(p proofPayload) []byte {
	out := make([]byte, 0, 4+1+1+1+32+8+4+len(p.entries)*(nodeIDLen+4+mldsaSigSize))
	out = append(out, []byte(proofMagic)...)
	out = append(out, wireVersion, byte(p.backend), modeMLDSA65)
	out = append(out, p.pi[:]...)
	out = append(out, be64(p.attestedWeight)...)
	out = appendU32(out, uint32(len(p.entries)))
	return appendEntries(out, p.entries)
}

// decodeProof parses the reference proof envelope. It validates the structural
// frame only; the cryptographic checks (signatures, root, PI) are the
// verifier's job (verify.go).
func decodeProof(b []byte) (proofPayload, error) {
	var p proofPayload
	r := newReader(b)
	magic, ok := r.take(4)
	if !ok || string(magic) != proofMagic {
		return p, ErrMalformedProof
	}
	ver, ok := r.byteAt()
	if !ok || ver != wireVersion {
		return p, ErrMalformedProof
	}
	backend, ok := r.byteAt()
	if !ok {
		return p, ErrMalformedProof
	}
	p.backend = Backend(backend)
	mode, ok := r.byteAt()
	if !ok {
		return p, ErrMalformedProof
	}
	if mode != modeMLDSA65 {
		return p, ErrUnsupportedMode
	}
	pi, ok := r.take(32)
	if !ok {
		return p, ErrMalformedProof
	}
	copy(p.pi[:], pi)
	aw, ok := r.u64()
	if !ok {
		return p, ErrMalformedProof
	}
	p.attestedWeight = aw
	entries, err := readEntries(&r)
	if err != nil {
		return p, err
	}
	if !r.done() {
		return p, ErrMalformedProof
	}
	p.entries = entries
	return p, nil
}
