// Package sskg provides a Go implementation of Seekable Sequential Key
// Generators (SSKGs). Specifically, this package provides an HKDF-based
// implementation of a binary tree-based SSKG as described by Marson and
// Poettering (https://eprint.iacr.org/2014/479.pdf) which features fast key
// advancing (~6μs) and low memory usage (O(log N)).
//
// An example of SSKG usage is cryptographically protected local logs. In this
// scenario, logs on a computer are secured via MACs. If the MAC key is
// constant, an attacker can extract the key and forge or modify log entries in
// the past.
//
// The traditional solution to this is to use a foward-secure solution like a
// hash chain, but this presents a large computational expense to auditors: in
// order to verify the MAC using the Nth key, the auditor must calculate N-1
// hashes, which may be cumbersome. An SSKG, in contrast, allows quickly seeking
// forward to arbitrary points of time (specifically, Marson and Poettering's
// tree-based SSKG can perform O(log N) seeks).
package sskg

import (
	"hash"
	"math"

	"golang.org/x/crypto/hkdf"
)

// A Seq is a sequence of forward-secure keys.
type Seq struct {
	Nodes []node             `json:"nodes"`
	alg     func() hash.Hash
	Size    int              `json:"size"`
	Version string           `json:"version"`
}

// New creates a new Seq with the given hash algorithm, seed, and maximum number
// of keys.
func New(alg func() hash.Hash, seed []byte, maxKeys uint) Seq {
	size := alg().Size()
	return Seq{
		Nodes: []node{{
			K: prf(alg, size, []byte("seed"), seed),
			H: uint(math.Ceil(math.Log2(float64(maxKeys) + 1))),
		}},
		alg:  alg,
		Size: size,
	}
}

// Key returns the Seq's current key of the given size.
func (s Seq) Key(size int) []byte {
	return prf(s.alg, size, []byte("key"), s.Nodes[len(s.Nodes)-1].K)
}

// Next advances the Seq's current key to the next in the sequence.
//
// (In the literature, this function is called Evolve.)
func (s *Seq) Next() {
	k, h := s.pop()

	if h > 1 {
		s.push(prf(s.alg, s.Size, right, k), h-1)
		s.push(prf(s.alg, s.Size, left, k), h-1)
	}
}

// Seek moves the Seq to the N-th key without having to calculate all of the
// intermediary keys. It is equivalent to, but faster than, N invocations of
// Next().
// WARNING: Seek does not work when the state is already advanced. If you
// want to keep advancing a state that has already been advanced, use
// Superseek. You probably just want to use Superseek.
// This method will probably be superseded by Superseek in a future version.
func (s *Seq) Seek(n int) {
	k, h := s.pop()

	for n > 0 {
		h--

		if h <= 0 {
			panic("keyspace exhausted")
		}

		pow := 1 << h
		if n < pow {
			s.push(prf(s.alg, s.Size, right, k), h)
			k = prf(s.alg, s.Size, left, k)
			n--
		} else {
			k = prf(s.alg, s.Size, right, k)
			n -= pow
		}
	}

	s.push(k, h)
}

// Superseek is equivalent to Seek, but works even when the state is already advanced.
func (s *Seq) Superseek(n int) {
	k, h := s.pop()

	delta := n
	for delta >= (1<<h)-1 {
		delta -= (1<<h)-1
		k, h = s.pop()
	}
	n = delta

	for n > 0 {
		h--

		if h <= 0 {
			panic("keyspace exhausted")
		}

		pow := 1 << h
		if n < pow {
			s.push(prf(s.alg, s.Size, right, k), h)
			k = prf(s.alg, s.Size, left, k)
			n--
		} else {
			k = prf(s.alg, s.Size, right, k)
			n -= pow
		}
	}

	s.push(k, h)
}

func (s *Seq) pop() ([]byte, uint) {
	node := s.Nodes[len(s.Nodes)-1]
	s.Nodes = s.Nodes[:len(s.Nodes)-1]
	return node.K, node.H
}

func (s *Seq) push(k []byte, h uint) {
	s.Nodes = append(s.Nodes, node{K: k, H: h})
}

type node struct {
	K []byte `json:"k"`
	H uint   `json:"h"`
}

var (
	right = []byte("right")
	left  = []byte("left")
)

func prf(alg func() hash.Hash, size int, label, seed []byte) []byte {
	buf := make([]byte, size)
	kdf := hkdf.New(alg, seed, nil, label)
	_, _ = kdf.Read(buf)
	return buf
}
