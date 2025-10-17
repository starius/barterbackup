package usercontent

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestContentRoundTrip(t *testing.T) {
	contentSeal, contentOpen := makeContentIDAEAD(t)
	metadataAEAD := makeAEAD(t)
	xor := makeTestXOR(t)
	ivKey := randomKey(t)

	uc := UserContent{
		CreatedAt: time.Unix(1234, 5678),
		Files: map[string]File{
			"hello": {Body: bytes.NewReader([]byte("world")), Size: 5},
			"foo":   {Body: bytes.NewReader([]byte("bar")), Size: 3},
		},
	}

	var buf bytes.Buffer
	meta, cid, err := WriteContentFile(&buf, uc, contentSeal, contentOpen, metadataAEAD, xor, ivKey)
	require.NoError(t, err)
	require.NotNil(t, meta)
	require.NotEmpty(t, cid)

	parsed, parsedMeta, parsedCID, err := ParseContentFile(bytes.NewReader(buf.Bytes()), contentSeal, contentOpen, metadataAEAD, xor, ivKey)
	require.NoError(t, err)
	require.NotNil(t, parsedMeta)
	require.Equal(t, cid, parsedCID)

	require.Equal(t, uc.CreatedAt.Unix(), parsedMeta.GetMostRecentContent().GetCreatedAt())
	require.Equal(t, uc.CreatedAt.Nanosecond(), int(parsedMeta.GetMostRecentContent().GetCreatedAtNs()))

	require.Equal(t, len(uc.Files), len(parsed.Files))
	for name, file := range parsed.Files {
		orig, ok := uc.Files[name]
		require.True(t, ok)
		buf := make([]byte, orig.Size)
		n, err := file.Body.ReadAt(buf, 0)
		if err != nil && err != io.EOF {
			require.NoError(t, err)
		}
		require.Equal(t, int(orig.Size), n)
		origBuf := make([]byte, orig.Size)
		n, err = orig.Body.ReadAt(origBuf, 0)
		require.NoError(t, err)
		require.Equal(t, int(orig.Size), n)
		require.Equal(t, origBuf, buf)
	}
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func makeAEAD(t *testing.T) cipher.AEAD {
	block, err := aes.NewCipher(randomKey(t))
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return aead
}

func makeCipherBlock(t *testing.T) cipher.Block {
	t.Helper()
	block, err := aes.NewCipher(randomKey(t))
	require.NoError(t, err)
	return block
}

func makeContentIDAEAD(t *testing.T) (SealFunc, OpenFunc) {
	t.Helper()
	seal, open, err := NewAEAD(randomKey(t))
	require.NoError(t, err)
	return seal, open
}

func makeTestXOR(t *testing.T) XORKeyStreamAt {
	block := makeCipherBlock(t)
	blockSize := block.BlockSize()
	return func(dst, src, iv []byte, offset uint64) {
		if len(dst) != len(src) {
			panic("xor: len mismatch")
		}
		counter := make([]byte, blockSize)
		copy(counter, iv)
		addTestCounter(counter, offset/uint64(blockSize))
		buf := make([]byte, blockSize)
		skip := int(offset % uint64(blockSize))
		written := 0
		for written < len(src) {
			block.Encrypt(buf, counter)
			for i := skip; i < blockSize && written < len(src); i++ {
				dst[written] = src[written] ^ buf[i]
				written++
			}
			skip = 0
			addTestCounter(counter, 1)
		}
	}
}

func addTestCounter(counter []byte, delta uint64) {
	carry := delta
	for i := len(counter) - 1; i >= 0 && carry > 0; i-- {
		sum := uint64(counter[i]) + (carry & 0xff)
		counter[i] = byte(sum)
		carry = carry>>8 + sum>>8
	}
}
