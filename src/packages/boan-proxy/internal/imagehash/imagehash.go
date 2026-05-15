// Package imagehash wraps perceptual-hash computation + Hamming-distance
// comparison for the GI1 image guardrail. Lives on the device side so the
// admin-uploaded image bytes never leave the device — only the resulting
// 16-hex pHash crosses the wire to the cloud policy server.
package imagehash

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"math/bits"
	"sync"

	"github.com/corona10/goimagehash"
)

// Compute returns the 16-hex pHash of an image read from r.
func Compute(r io.Reader) (string, error) {
	img, _, err := image.Decode(r)
	if err != nil {
		return "", fmt.Errorf("decode image: %w", err)
	}
	h, err := goimagehash.PerceptionHash(img)
	if err != nil {
		return "", fmt.Errorf("phash: %w", err)
	}
	buf := new(bytes.Buffer)
	if err := h.Dump(buf); err != nil {
		return "", fmt.Errorf("phash dump: %w", err)
	}
	raw := buf.Bytes()
	if len(raw) < 9 {
		return "", fmt.Errorf("phash dump too short: %d bytes", len(raw))
	}
	return hex.EncodeToString(raw[len(raw)-8:]), nil
}

// HammingDistance returns the number of differing bits between two 16-hex
// pHash strings. Returns -1 on parse error.
func HammingDistance(a, b string) int {
	av, err := decode64(a)
	if err != nil {
		return -1
	}
	bv, err := decode64(b)
	if err != nil {
		return -1
	}
	return bits.OnesCount64(av ^ bv)
}

// EvaluateForbidden returns the matched forbidden entry and the actual
// Hamming distance if any forbidden hash sits within `threshold` bits of
// `imageHash`. Returns ("", -1) on no match. Caller is responsible for the
// replacement / block decision based on the matched entry.
type Forbidden struct {
	Hash        string
	Description string
	Replacement string
}

func EvaluateForbidden(imageHash string, list []Forbidden, threshold int) (Forbidden, int) {
	if threshold < 0 {
		return Forbidden{}, -1
	}
	for _, f := range list {
		d := HammingDistance(imageHash, f.Hash)
		if d < 0 {
			continue
		}
		if d <= threshold {
			return f, d
		}
	}
	return Forbidden{}, -1
}

// Entry — pre-decoded forbidden image record. Hash is the raw uint64 so the
// hot path can XOR + popcount directly instead of decoding hex every query.
// We keep the source string Hash16 to round-trip back to the caller without
// re-encoding.
type Entry struct {
	Hash        uint64
	Hash16      string
	Description string
	Replacement string
}

// Store — in-memory index of forbidden image hashes for one org. Built once
// per policy revision and reused for every image-gate evaluation. At 10K
// entries the slice is ~80 KB raw and a full Hamming scan completes in well
// under 100 µs on a single core, so we don't need a BK-tree / multi-index
// hashing scheme — we just want to avoid the HTTP fetch and the per-query
// hex decode that the previous string-based path paid.
//
// Concurrency: the underlying slice is replaced (not mutated in place) by
// Rebuild, so concurrent readers see either the old slice or the new one,
// never a torn view. Match is lock-free on the slice it captured.
type Store struct {
	mu        sync.RWMutex
	entries   []Entry
	threshold int
	version   int
}

// NewStore returns an empty store with no entries.
func NewStore() *Store {
	return &Store{threshold: 10}
}

// Rebuild swaps the entire entry slice atomically. Callers should hand in the
// canonical list from the policy server every time the policy version bumps
// (policysync.Client emits an event we can hook). Invalid hex hashes are
// silently dropped — they would never match anyway and we'd rather not block
// the rebuild on a single bad row.
func (s *Store) Rebuild(raw []Forbidden, threshold, version int) {
	out := make([]Entry, 0, len(raw))
	for _, r := range raw {
		v, err := decode64(r.Hash)
		if err != nil {
			continue
		}
		out = append(out, Entry{
			Hash:        v,
			Hash16:      r.Hash,
			Description: r.Description,
			Replacement: r.Replacement,
		})
	}
	s.mu.Lock()
	s.entries = out
	if threshold < 0 {
		threshold = 0
	}
	if threshold > 64 {
		threshold = 64
	}
	s.threshold = threshold
	s.version = version
	s.mu.Unlock()
}

// Match returns the first entry whose Hamming distance to query is ≤ threshold,
// along with the distance, or a zero Entry + -1 on no match. The hot path is
// a tight loop over a pre-decoded uint64 slice — popcount on a single core is
// ~1 ns, so 10K entries scan in ~10-50 µs.
func (s *Store) Match(query uint64) (Entry, int) {
	s.mu.RLock()
	entries := s.entries
	threshold := s.threshold
	s.mu.RUnlock()
	for _, e := range entries {
		d := bits.OnesCount64(query ^ e.Hash)
		if d <= threshold {
			return e, d
		}
	}
	return Entry{}, -1
}

// MatchHex is a convenience wrapper for callers that still have a hex string.
func (s *Store) MatchHex(queryHex string) (Entry, int) {
	v, err := decode64(queryHex)
	if err != nil {
		return Entry{}, -1
	}
	return s.Match(v)
}

// Len returns the number of indexed entries.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Version returns the policy version this store was last rebuilt from. Caller
// can use it to skip a rebuild when the policy hasn't changed.
func (s *Store) Version() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

// Threshold returns the current Hamming-distance threshold the Match method
// will accept.
func (s *Store) Threshold() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.threshold
}

func decode64(hexStr string) (uint64, error) {
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return 0, err
	}
	if len(raw) != 8 {
		return 0, fmt.Errorf("expected 8 bytes, got %d", len(raw))
	}
	return binary.BigEndian.Uint64(raw), nil
}
