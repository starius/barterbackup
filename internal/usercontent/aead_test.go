package usercontent

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAEADVectors(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	seal, open, err := NewAEAD(key)
	require.NoError(t, err)

	testCases := []struct {
		name      string
		plain     []byte
		ad        []byte
		cipherHex string
	}{
		{
			name:      "empty",
			plain:     []byte{},
			ad:        nil,
			cipherHex: "2edd35ccc2cdf8ff76db4aa8b7bfef31",
		},
		{
			name:      "hello",
			plain:     []byte("hello"),
			ad:        nil,
			cipherHex: "7d9c42f0e73e849f0aee40c166de0233c523c241e2",
		},
		{
			name:      "fifteen-bytes",
			plain:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e},
			ad:        nil,
			cipherHex: "8b06b2cb778c1de483db5b9c86d879ecbd6047f3c963125e01cb8bf0adba8a",
		},
		{
			name:      "longer",
			plain:     []byte("this is a longer sample plaintext for testing deterministic output"),
			ad:        nil,
			cipherHex: "7096aa90c95f56948a64cfa67afb516040cadba051bb5aeb8216313ea232a5ae8e328370eec4b1525b64720603ea6a696e26fa0e9ad347f13bee559a87467901a3cc08ab46a0f86593a9f42b574fe489ea2b",
		},
		{
			name:      "with-ad",
			plain:     []byte("metadata body"),
			ad:        []byte("associated-data-test"),
			cipherHex: "a17bf71eb9faf31abdea78cb278ddf19c41adf1e0364670031be831145",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ciphertext, err := seal(tc.plain, tc.ad)
			require.NoError(t, err)
			require.Equal(t, tc.cipherHex, hex.EncodeToString(ciphertext))

			recovered, err := open(ciphertext, tc.ad)
			require.NoError(t, err)
			require.Equal(t, tc.plain, recovered)
		})
	}

	large := bytes.Repeat([]byte("x"), 1024)
	ciphertext, err := seal(large, nil)
	require.NoError(t, err)
	recovered, err := open(ciphertext, nil)
	require.NoError(t, err)
	require.Equal(t, large, recovered)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	require.NoError(t, err)

	return b
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
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
	return func(dst, src, iv []byte, offset uint64) {
		if len(dst) != len(src) {
			panic("xor: len mismatch")
		}
		stream := cipher.NewCTR(block, iv)
		if offset > 0 {
			const chunkSize = 32 * 1024
			buf := make([]byte, chunkSize)
			remaining := offset
			for remaining > 0 {
				n := chunkSize
				if remaining < uint64(n) {
					n = int(remaining)
				}
				stream.XORKeyStream(buf[:n], buf[:n])
				remaining -= uint64(n)
			}
		}
		stream.XORKeyStream(dst, src)
	}
}
