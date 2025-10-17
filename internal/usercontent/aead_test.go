package usercontent

import (
	"bytes"
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
		cipherHex string
	}{
		{
			name:      "empty",
			plain:     []byte{},
			cipherHex: "2edd35ccc2cdf8ff76db4aa8b7bfef31",
		},
		{
			name:      "hello",
			plain:     []byte("hello"),
			cipherHex: "7d9c42f0e73e849f0aee40c166de0233c523c241e2",
		},
		{
			name:      "fifteen-bytes",
			plain:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e},
			cipherHex: "8b06b2cb778c1de483db5b9c86d879ecbd6047f3c963125e01cb8bf0adba8a",
		},
		{
			name:      "longer",
			plain:     []byte("this is a longer sample plaintext for testing deterministic output"),
			cipherHex: "7096aa90c95f56948a64cfa67afb516040cadba051bb5aeb8216313ea232a5ae8e328370eec4b1525b64720603ea6a696e26fa0e9ad347f13bee559a87467901a3cc08ab46a0f86593a9f42b574fe489ea2b",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ciphertext, err := seal(tc.plain)
			require.NoError(t, err)
			require.Equal(t, tc.cipherHex, hex.EncodeToString(ciphertext))

			recovered, err := open(ciphertext)
			require.NoError(t, err)
			require.Equal(t, tc.plain, recovered)
		})
	}

	large := bytes.Repeat([]byte("x"), 1024)
	ciphertext, err := seal(large)
	require.NoError(t, err)
	recovered, err := open(ciphertext)
	require.NoError(t, err)
	require.Equal(t, large, recovered)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	require.NoError(t, err)

	return b
}
