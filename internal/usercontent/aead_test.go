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
			cipherHex: "2ea046a23642cb8028bcadaf66b4208f4dc6b0c8da274e56f35fa1cd2797b77f",
		},
		{
			name:      "hello",
			plain:     []byte("hello"),
			cipherHex: "cefc62a9efcdbb580d01cab90211e49c8aaebbdf50e939f585744fd980a8e071",
		},
		{
			name:      "max-15",
			plain:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e},
			cipherHex: "07db91bb9cd66fbaef901e17217b2a77247e239c6ae3306673a2dd7e4a1b9080",
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

	tooLong := bytes.Repeat([]byte{0xff}, contentIDMaxPayload+1)
	_, err = seal(tooLong)
	require.Error(t, err)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
