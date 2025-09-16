package keys

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeriveMasterPriv_Table(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		seed       string
		wantHex    string
		wantLength int
	}{
		{
			name:       "empty",
			seed:       "",
			wantHex:    "ecc7360ce9c0f8e0cec5d8be2ddbcf9c4bb1a810c5350e4081db45eaf899f2ed0a7baed905d7b88eab4fa85d86e32103867e617166628e0db68a9684ca24a7ab",
			wantLength: 64,
		},
		{
			name:       "simple",
			seed:       "password",
			wantHex:    "b9a023e45bd280e4cc6d093feb81dc1f34423523f7ac6e730e337ab4b3d79ff0112b694de0cd1fad90ed55393222e5a47f656c20f488be5522afe98bd7f9de07",
			wantLength: 64,
		},
		{
			name:       "unicode",
			seed:       "pässwörd",
			wantHex:    "4fd00b3a4ca5cf0d5e81f9b1caad16f9596158726ea0c942f13157699cd4c0a57ccfcd04850ca56c180769a180d1d8752047b9c1f60fe9d1c5f62e42297e851d",
			wantLength: 64,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := DeriveMasterPriv(tc.seed)
			require.Len(t, got, tc.wantLength)

			gotHex := hex.EncodeToString(got)
			require.Equal(t, tc.wantHex, gotHex)
		})
	}
}

func TestDeriveKey_Table(t *testing.T) {
	t.Parallel()

	master := DeriveMasterPriv("test-seed")
	cases := []struct {
		name    string
		purpose string
		length  int
		wantHex string
	}{
		{
			name:    "k32",
			purpose: "purpose-32",
			length:  32,
			wantHex: "e5f72051031a2bb3c75a9f50d8640fd3fdfbc7cd01fd9f9fee96d9e01e522225",
		},
		{
			name:    "ed-seed",
			purpose: "tor/onion/v3",
			length:  32,
			wantHex: "d3ce31dc0f3a710b4a3d42259a7628a894c4b6c2bd3a0ed6e6bb0a8e003b2348",
		},
		{
			name:    "k48",
			purpose: "purpose-48",
			length:  48,
			wantHex: "35278391bd7b851be5a795a3d46713350ac6488bfaeb67bcdcec37919c099461aaa6267470cc8d284173d182f5797fd2",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := DeriveKey(master, tc.purpose, tc.length)
			require.NoError(t, err)
			require.Len(t, got, tc.length)

			gotHex := hex.EncodeToString(got)
			require.Equal(t, tc.wantHex, gotHex)
		})
	}
}

func TestDeriveEd25519FromMaster_Table(t *testing.T) {
	t.Parallel()

	// Error case: empty masterPriv.
	_, _, err := DeriveEd25519FromMaster(nil, "tor/onion/v3")
	require.Error(t, err)

	master := DeriveMasterPriv("test-seed")
	cases := []struct {
		name        string
		purpose     string
		wantPubHex  string
		wantPrivHex string
	}{
		{
			name:        "onion",
			purpose:     "tor/onion/v3",
			wantPubHex:  "8031f51821da22e80497bc338ca38cb7ac2c6739b706dcff776d4e71a62e7124",
			wantPrivHex: "d3ce31dc0f3a710b4a3d42259a7628a894c4b6c2bd3a0ed6e6bb0a8e003b23488031f51821da22e80497bc338ca38cb7ac2c6739b706dcff776d4e71a62e7124",
		},
		{
			name:        "generic",
			purpose:     "ed25519/generic",
			wantPubHex:  "06ccbedc5b86851cd0ee8c648e4bfcc75347431a8c39d0dcb066a8497694d931",
			wantPrivHex: "f1b56590d316b35d65d1088325395f52359bf3f65c68c683e7d82b7eb8dcb52d06ccbedc5b86851cd0ee8c648e4bfcc75347431a8c39d0dcb066a8497694d931",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			priv, pub, err := DeriveEd25519FromMaster(master, tc.purpose)
			require.NoError(t, err)

			pubHex := hex.EncodeToString(pub)
			privHex := hex.EncodeToString(priv)
			require.Equal(t, tc.wantPubHex, pubHex)
			require.Equal(t, tc.wantPrivHex, privHex)
		})
	}
}
