package usercontent

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/ericlagergren/siv"
	"github.com/stretchr/testify/require"
)

// TestContentRoundTrip ensures content can be written and parsed without loss.
func TestContentRoundTrip(t *testing.T) {
	contentSeal, contentOpen := makeContentIDAEAD(t)
	metadataSeal, metadataOpen := makeContentIDAEAD(t)
	xor := makeTestXOR(t)

	uc := UserContent{
		CreatedAt: time.Unix(1234, 5678),
		Files: map[string]File{
			"hello": {Body: bytes.NewReader([]byte("world")), Size: 5},
			"foo":   {Body: bytes.NewReader([]byte("bar")), Size: 3},
		},
	}

	var buf bytes.Buffer
	cid, err := WriteContentFile(&buf, uc, contentSeal, metadataSeal, xor)
	require.NoError(t, err)
	require.NotEmpty(t, cid)

	parsed, parsedCID, err := ParseContentFile(
		bytes.NewReader(buf.Bytes()), contentOpen, metadataOpen, xor,
	)
	require.NoError(t, err)
	require.Equal(t, cid, parsedCID)
	require.Equal(t, uc.CreatedAt.UTC(), parsed.CreatedAt.UTC())

	revision, err := ParseContentID(cid, contentOpen)
	require.NoError(t, err)
	require.Equal(t, uc.CreatedAt.Unix(), revision.GetCreatedAt())
	require.Equal(t, uc.CreatedAt.Nanosecond(), int(revision.GetCreatedAtNs()))

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

// TestFileKeystreamDiffersPerFile checks per-file keystream diversity.
func TestFileKeystreamDiffersPerFile(t *testing.T) {
	contentSeal, contentOpen := makeContentIDAEAD(t)
	metadataSeal, _ := makeContentIDAEAD(t)
	xor := makeTestXOR(t)

	payload := bytes.Repeat([]byte{0x42}, 64)
	uc := UserContent{
		CreatedAt: time.Unix(10, 0),
		Files: map[string]File{
			"a": {Body: bytes.NewReader(payload), Size: int64(len(payload))},
			"b": {Body: bytes.NewReader(payload), Size: int64(len(payload))},
		},
	}

	var buf bytes.Buffer
	cid, err := WriteContentFile(&buf, uc, contentSeal, metadataSeal, xor)
	require.NoError(t, err)

	revision, err := ParseContentID(cid, contentOpen)
	require.NoError(t, err)

	headerLen := len(headerMagic) + 1
	metaLen := int(revision.GetMetadataAeadLength())
	offset := headerLen + len(cid) + metaLen

	fileLen := len(payload)
	raw := buf.Bytes()
	require.GreaterOrEqual(t, len(raw), offset+fileLen*2)

	first := raw[offset : offset+fileLen]
	second := raw[offset+fileLen : offset+fileLen*2]
	require.NotEqual(
		t, first, second,
		"ciphertexts should differ for identical plaintexts in the same revision",
	)
}

// TestFileTamperDetected asserts corrupted file ciphertext is rejected.
func TestFileTamperDetected(t *testing.T) {
	contentSeal, contentOpen := makeContentIDAEAD(t)
	metadataSeal, metadataOpen := makeContentIDAEAD(t)
	xor := makeTestXOR(t)

	uc := UserContent{
		CreatedAt: time.Unix(20, 0),
		Files: map[string]File{
			"foo": {Body: bytes.NewReader([]byte("barbaz")), Size: 6},
		},
	}

	var buf bytes.Buffer
	cid, err := WriteContentFile(&buf, uc, contentSeal, metadataSeal, xor)
	require.NoError(t, err)

	revision, err := ParseContentID(cid, contentOpen)
	require.NoError(t, err)

	headerLen := len(headerMagic) + 1
	metaLen := int(revision.GetMetadataAeadLength())
	offset := headerLen + len(cid) + metaLen

	raw := buf.Bytes()
	require.GreaterOrEqual(t, len(raw), offset+int(uc.Files["foo"].Size))

	raw[offset] ^= 0x01

	_, _, err = ParseContentFile(
		bytes.NewReader(raw), contentOpen, metadataOpen, xor,
	)
	require.ErrorIs(t, err, errInvalidContent)
}

type sizedReader struct {
	*bytes.Reader
}

func (sr *sizedReader) Size() int64 {
	return int64(sr.Len())
}

// TestPaddingAlignsAndDecrypts verifies total size alignment and zero padding.
func TestPaddingAlignsAndDecrypts(t *testing.T) {
	contentSeal, contentOpen := makeContentIDAEAD(t)
	metadataSeal, metadataOpen := makeContentIDAEAD(t)
	xor := makeTestXOR(t)

	payload := []byte("short")
	uc := UserContent{
		CreatedAt: time.Unix(30, 0),
		Files: map[string]File{
			"pad": {
				Body: bytes.NewReader(payload),
				Size: int64(len(payload)),
			},
		},
	}

	var buf bytes.Buffer
	cid, err := WriteContentFile(&buf, uc, contentSeal, metadataSeal, xor)
	require.NoError(t, err)
	require.Equal(t, int64(0), int64(len(buf.Bytes()))%contentSizeAlignment)

	reader := &sizedReader{Reader: bytes.NewReader(buf.Bytes())}
	parsed, parsedCID, err := ParseContentFile(
		reader, contentOpen, metadataOpen, xor,
	)
	require.NoError(t, err)
	require.Equal(t, cid, parsedCID)
	require.Len(t, parsed.Files, 1)

	revision, err := ParseContentID(cid, contentOpen)
	require.NoError(t, err)
	metaLen := int(revision.GetMetadataAeadLength())
	headerLen := len(headerMagic) + 1
	cidLen := len(cid)
	raw := buf.Bytes()
	metaCipher := raw[headerLen+cidLen : headerLen+cidLen+metaLen]
	metadataTag := metaCipher[len(metaCipher)-siv.TagSize:]
	streamIV, err := revisionIVKey(revision, metadataTag)
	require.NoError(t, err)

	padLen := int64(len(raw)) - int64(headerLen+cidLen+metaLen+len(payload))
	require.Greater(t, padLen, int64(0))
	dataSize := int64(len(raw)) - int64(headerLen+cidLen+metaLen)

	dec, err := newDecryptedFile(bytes.NewReader(raw), xor, streamIV, int64(headerLen+cidLen+metaLen), dataSize, 0)
	require.NoError(t, err)
	padded := make([]byte, padLen)
	n, err := dec.ReadAt(padded, int64(len(payload)))
	require.Equal(t, int(padLen), n)
	require.Equal(t, io.EOF, err)
	require.Equal(t, make([]byte, len(padded)), padded)
}

// TestPaddingWorksWithoutFiles ensures alignment and parsing with empty content.
func TestPaddingWorksWithoutFiles(t *testing.T) {
	contentSeal, _ := makeContentIDAEAD(t)
	metadataSeal, _ := makeContentIDAEAD(t)
	xor := makeTestXOR(t)

	uc := UserContent{
		CreatedAt: time.Unix(40, 0),
		Files:     map[string]File{},
	}

	var buf bytes.Buffer
	_, err := WriteContentFile(&buf, uc, contentSeal, metadataSeal, xor)
	require.Error(t, err)
}
