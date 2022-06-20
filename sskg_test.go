package sskg_test

import (
	"bytes"
	"crypto/sha256"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
	"time"

	"github.com/oreparaz/sskg"
)

func TestNext(t *testing.T) {
	seq := sskg.New(sha256.New, make([]byte, 32), 1<<32)
	for i := 0; i < 10000; i++ {
		seq.Next()
	}

	if v := seq.Key(32); !bytes.Equal(expected, v) {
		t.Errorf("Key was %#v, but expected %#v", v, expected)
	}
}

func TestSeek(t *testing.T) {
	seq := sskg.New(sha256.New, make([]byte, 32), 1<<32)
	seq.Seek(10000)

	if v := seq.Key(32); !bytes.Equal(expected, v) {
		t.Errorf("Key was %#v, but expected %#v", v, expected)
	}
}

func TestSeekTooFar(t *testing.T) {
	defer func() {
		e := recover()
		if e != "keyspace exhausted" {
			t.Errorf("Unexpected error: %v", e)
		}
	}()

	seq := sskg.New(sha256.New, make([]byte, 32), 1<<32)
	seq.Seek(1 << 33)

	t.Fatal("expected to exhaust the keyspace")
}

func assertEqualSeq(t *testing.T, s1 sskg.Seq, s2 sskg.Seq) {
	v1 := s1.Key(32)
	v2 := s2.Key(32)
	assert.Equal(t, v1, v2)
}

func TestSuperseek(t *testing.T) {
	seq := sskg.New(sha256.New, make([]byte, 32), 1<<32)
	seq.Seek(10000)

	seq2 := sskg.New(sha256.New, make([]byte, 32), 1<<32)
	seq2.Superseek(5000)
	seq2.Superseek(5000)

	seq3 := sskg.New(sha256.New, make([]byte, 32), 1<<32)
	for i:=0; i<10; i++ {
		seq3.Superseek(1000)
	}

	assertEqualSeq(t, seq, seq2)
	assertEqualSeq(t, seq, seq3)
}

func helperTestSuperseekRandom(t *testing.T) {
	seq := sskg.New(sha256.New, make([]byte, 32), 1<<32)
	seq2 := sskg.New(sha256.New, make([]byte, 32), 1<<32)

	count := 0
	for i:=0; i<rand.Intn(10); i++ {
		n := rand.Intn(1000)
		count += n
		seq2.Superseek(n)
	}
	seq.Seek(count)
	assertEqualSeq(t, seq, seq2)
}

func TestSuperseekRandom(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	for i:=0; i<10000; i++ {
		helperTestSuperseekRandom(t)
	}
}

func BenchmarkNext(b *testing.B) {
	seq := sskg.New(sha256.New, make([]byte, 32), 1<<32)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		seq.Next()
	}
}

func BenchmarkNext1000(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		seq := sskg.New(sha256.New, make([]byte, 32), 1<<32)
		for j := 0; j < 1000; j++ {
			seq.Next()
		}
	}
}

func BenchmarkSeek1000(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		seq := sskg.New(sha256.New, make([]byte, 32), 1<<32)
		seq.Seek(1000)
	}
}

var (
	expected = []byte{
		0x46, 0x36, 0x7f, 0x8f, 0x2b, 0x62, 0xc8, 0x4d, 0x8d, 0x40, 0xb5, 0x36,
		0x7b, 0xac, 0x77, 0xc8, 0xae, 0xb2, 0xde, 0x72, 0x7e, 0x50, 0xb5, 0x1a,
		0x9e, 0xae, 0x22, 0xa3, 0xe0, 0x21, 0xb4, 0x6f,
	}
)
