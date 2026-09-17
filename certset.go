// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3qprover

import (
	"encoding/binary"

	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
)

// CertEntry is one accountable per-validator certificate: a node identity and
// its ML-DSA-65 signature over the subject (under CrossCheckCtx). The public key
// is NOT carried here — it is resolved from the authenticated SignerSetAuthority
// by NodeID, so a producer can never substitute a key.
type CertEntry struct {
	NodeID ids.NodeID
	Sig    []byte
}

// EncodeCertSet serializes the rollup INPUT — the raw independent ML-DSA-65
// cert set — into the canonical bytes carried by warp.CertSetEvidence.CertSet.
// This is the one and only encoder; producers (validators gossiping certs) and
// the prover agree on it.
//
// Layout:
//
//	[4]  magic "P3QC"
//	[1]  version
//	[1]  mode (0x65)
//	[4]  N (big-endian uint32)
//	N ×  entry{ [20] nodeID | [4] sigLen (BE) | [sigLen] sig }
func EncodeCertSet(entries []CertEntry) []byte {
	out := make([]byte, 0, 4+1+1+4+len(entries)*(nodeIDLen+4+mldsaSigSize))
	out = append(out, []byte(certSetMagic)...)
	out = append(out, wireVersion, modeMLDSA65)
	out = appendU32(out, uint32(len(entries)))
	return appendEntries(out, entries)
}

// CertSetEvidence is a convenience that wraps EncodeCertSet into the warp lane
// payload the prover consumes.
func CertSetEvidence(chainID ids.ID, eraHandle uint64, entries []CertEntry) warp.CertSetEvidence {
	return warp.CertSetEvidence{
		ChainID:   chainID,
		EraHandle: eraHandle,
		CertSet:   EncodeCertSet(entries),
	}
}

// decodeCertSet parses the canonical cert-set bytes back into entries.
func decodeCertSet(b []byte) ([]CertEntry, error) {
	r := newReader(b)
	magic, ok := r.take(4)
	if !ok || string(magic) != certSetMagic {
		return nil, ErrMalformedCertSet
	}
	ver, ok := r.byteAt()
	if !ok || ver != wireVersion {
		return nil, ErrMalformedCertSet
	}
	mode, ok := r.byteAt()
	if !ok {
		return nil, ErrMalformedCertSet
	}
	if mode != modeMLDSA65 {
		return nil, ErrUnsupportedMode
	}
	entries, err := readEntries(&r)
	if err != nil {
		return nil, wrap(ErrMalformedCertSet, err)
	}
	if !r.done() {
		return nil, ErrMalformedCertSet
	}
	return entries, nil
}

// --- shared entry codec (used by both certset and proof encodings) ---

func appendU32(dst []byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return append(dst, b[:]...)
}

func appendEntries(dst []byte, entries []CertEntry) []byte {
	for _, e := range entries {
		dst = append(dst, e.NodeID[:]...)
		dst = appendU32(dst, uint32(len(e.Sig)))
		dst = append(dst, e.Sig...)
	}
	return dst
}

// readEntries reads a [4]N-prefixed run of entries from r.
func readEntries(r *reader) ([]CertEntry, error) {
	n, ok := r.u32()
	if !ok {
		return nil, ErrMalformedProof
	}
	entries := make([]CertEntry, 0, n)
	for range n {
		idBytes, ok := r.take(nodeIDLen)
		if !ok {
			return nil, ErrMalformedProof
		}
		sigLen, ok := r.u32()
		if !ok {
			return nil, ErrMalformedProof
		}
		sig, ok := r.take(int(sigLen))
		if !ok {
			return nil, ErrMalformedProof
		}
		var id ids.NodeID
		copy(id[:], idBytes)
		// Copy sig out of the backing buffer so callers can retain it safely.
		s := make([]byte, len(sig))
		copy(s, sig)
		entries = append(entries, CertEntry{NodeID: id, Sig: s})
	}
	return entries, nil
}

// --- minimal byte reader ---

type reader struct {
	b   []byte
	off int
}

func newReader(b []byte) reader { return reader{b: b} }

func (r *reader) take(n int) ([]byte, bool) {
	if n < 0 || r.off+n > len(r.b) {
		return nil, false
	}
	s := r.b[r.off : r.off+n]
	r.off += n
	return s, true
}

func (r *reader) byteAt() (byte, bool) {
	s, ok := r.take(1)
	if !ok {
		return 0, false
	}
	return s[0], true
}

func (r *reader) u32() (uint32, bool) {
	s, ok := r.take(4)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint32(s), true
}

func (r *reader) u64() (uint64, bool) {
	s, ok := r.take(8)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint64(s), true
}

func (r *reader) done() bool { return r.off == len(r.b) }
