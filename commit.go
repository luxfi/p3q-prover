// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3qprover

import (
	"encoding/binary"

	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
	"golang.org/x/crypto/sha3"
)

// sha3sum returns SHA3-256(parts...) (FIPS 202). Used for every commitment and
// public-input digest. SHA3 (not keccak) is the FIPS-202 form; warp's D/M use
// keccak for on-chain opcode parity, but the rollup-internal commitment is
// independent of that and uses standard SHA3-256.
func sha3sum(parts ...[]byte) [32]byte {
	h := sha3.New256()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// be64 returns the big-endian encoding of v.
func be64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

// leafHash commits one verified signer: SHA3(leafDST || nodeID || SHA3(pkDST||pk) || weight).
// The public key is inner-hashed so the leaf preimage stays small and fixed-shape.
func leafHash(nodeID ids.NodeID, pk []byte, weight uint64) [32]byte {
	pkH := sha3sum([]byte(pkDST), pk)
	return sha3sum([]byte(leafDST), nodeID[:], pkH[:], be64(weight))
}

// nodeHash combines two child digests under the node domain tag.
func nodeHash(l, r [32]byte) [32]byte {
	return sha3sum([]byte(nodeDST), l[:], r[:])
}

// merkleRoot computes a binary Merkle root over canonically-ordered leaf
// digests. An odd node is PROMOTED unchanged (not duplicated), which — combined
// with leaf/node domain separation — avoids the classic duplicate-leaf and
// leaf/node-confusion second-preimage attacks. The empty set maps to a fixed
// marker digest (only reachable for a degenerate quorum, which fails the
// threshold check regardless).
func merkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return sha3sum([]byte(nodeDST), []byte(emptyMarker))
	}
	level := make([][32]byte, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i]) // promote the lone odd node
				continue
			}
			next = append(next, nodeHash(level[i], level[i+1]))
		}
		level = next
	}
	return level[0]
}

// publicInputs is the public-input digest PI binding the whole statement. The
// verifier recomputes it from the P3QRoot fields + authority-resolved
// totalWeight + the witness-derived attestedWeight/root/n and rejects on any
// mismatch — making the entire P3QRoot tamper-evident against its proof.
func publicInputs(
	subject []byte,
	signerSetID ids.ID,
	eraHandle uint64,
	threshold warp.WeightThreshold,
	totalWeight, attestedWeight uint64,
	root [32]byte,
	nSigners int,
) [32]byte {
	buf := make([]byte, 0, subjectLen+32+8*5+32+8)
	buf = append(buf, subject...)
	buf = append(buf, signerSetID[:]...)
	buf = append(buf, be64(eraHandle)...)
	buf = append(buf, be64(threshold.Numerator)...)
	buf = append(buf, be64(threshold.Denominator)...)
	buf = append(buf, be64(totalWeight)...)
	buf = append(buf, be64(attestedWeight)...)
	buf = append(buf, root[:]...)
	buf = append(buf, be64(uint64(nSigners))...)
	return sha3sum([]byte(piDST), buf)
}
