package usercontent

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/ericlagergren/siv"
	"github.com/starius/barterbackup/storedpb"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"
)

// File-level constants for the content file format header.
const (
	headerMagic    = "UCNT"
	currentVersion = 1

	// contentSizeAlignment pads the encoded content file so its total size is a
	// multiple of this alignment to reduce information leaked by ciphertext
	// length.
	contentSizeAlignment = 32 * 1024

	// paddingPseudoName seeds padding IV derivation when no files exist.
	paddingPseudoName = "__padding__"
)

var (
	// errInvalidMagic signals an unexpected file header prefix.
	errInvalidMagic = errors.New("usercontent: invalid magic")

	// errInvalidContent is returned when decryption or validation fails.
	errInvalidContent = errors.New("usercontent: invalid content")
)

// XORKeyStreamAt applies a key stream to src and writes the result into dst.
// The IV identifies the stream and offset allows random access.
type XORKeyStreamAt func(dst, src, iv []byte, offset uint64)

// File represents a single file participating in user content.
type File struct {
	Body io.ReaderAt
	Size int64
}

// UserContent is the in-memory representation of encoded content.
type UserContent struct {
	CreatedAt time.Time
	Files     map[string]File
	Peers     []*storedpb.Peer
}

// metadataFromUserContent builds the metadata structure for the provided
// user content and the associated revision descriptor derived from timestamps.
func metadataFromUserContent(uc UserContent) ([]byte, []fileDescriptor,
	*storedpb.ContentRevision, error) {

	names := make([]string, 0, len(uc.Files))
	for name := range uc.Files {
		names = append(names, name)
	}
	sort.Strings(names)

	meta := &storedpb.Metadata{
		Peers: append([]*storedpb.Peer(nil), uc.Peers...),
	}

	descriptors := make([]fileDescriptor, 0, len(names))
	for _, name := range names {
		file, ok := uc.Files[name]
		if !ok {
			return nil, nil, nil, fmt.Errorf("usercontent: missing file %q", name)
		}
		sum, err := hashFile(file)
		if err != nil {
			return nil, nil, nil, err
		}
		meta.Files = append(meta.Files, &storedpb.FileHeader{
			Name:       name,
			FileLength: file.Size,
			FileSha256: sum,
		})
		descriptors = append(descriptors, fileDescriptor{
			name: name,
			file: file,
		})
	}

	metaPlain, err := proto.Marshal(meta)
	if err != nil {
		return nil, nil, nil, err
	}

	expectedCipherLen := len(metaPlain) + siv.TagSize

	revision := &storedpb.ContentRevision{
		CreatedAt:          uc.CreatedAt.Unix(),
		CreatedAtNs:        int64(uc.CreatedAt.Nanosecond()),
		MetadataAeadLength: int64(expectedCipherLen),
	}

	return metaPlain, descriptors, revision, nil
}

// WriteContentFile encodes user content to w using the provided primitives and
// returns the generated content ID.
func WriteContentFile(w io.Writer, uc UserContent,
	contentSeal, metadataSeal SealFunc, xor XORKeyStreamAt) ([]byte, error) {

	if contentSeal == nil || metadataSeal == nil {
		return nil, errors.New("usercontent: encryption primitives must be provided")
	}
	if xor == nil {
		return nil, errors.New("usercontent: XOR function missing")
	}

	metaPlain, descriptors, revision, err := metadataFromUserContent(uc)
	if err != nil {
		return nil, err
	}

	ad, err := revisionMetadataAD(revision)
	if err != nil {
		return nil, err
	}
	metaCipher, err := metadataSeal(metaPlain, ad)
	if err != nil {
		return nil, err
	}
	if int64(len(metaCipher)) != revision.MetadataAeadLength {
		return nil, fmt.Errorf("usercontent: metadata aead length mismatch: expected %d got %d",
			revision.MetadataAeadLength, len(metaCipher))
	}

	contentID, err := MakeContentID(revision, contentSeal)
	if err != nil {
		return nil, err
	}

	if _, err := w.Write([]byte(headerMagic)); err != nil {
		return nil, err
	}
	if _, err := w.Write([]byte{currentVersion}); err != nil {
		return nil, err
	}
	if len(contentID) != siv.TagSize+contentIDPlaintextSize {
		return nil, fmt.Errorf("usercontent: unexpected content id length %d",
			len(contentID))
	}
	if _, err := w.Write(contentID); err != nil {
		return nil, err
	}

	if _, err := w.Write(metaCipher); err != nil {
		return nil, err
	}

	// Bind file keystream derivation to the authenticated metadata ciphertext tag.
	metadataTag := metaCipher[len(metaCipher)-siv.TagSize:]
	ivKey, err := revisionIVKey(revision, metadataTag)
	if err != nil {
		return nil, err
	}

	for _, desc := range descriptors {
		fileIV, err := deriveFileIV(ivKey, desc.name)
		if err != nil {
			return nil, err
		}
		if err := writeEncryptedFile(w, desc, xor, fileIV); err != nil {
			return nil, err
		}
	}

	// Pad the ciphertext so the total size reveals less about plaintext size.
	// Padding is encrypted as a continuation of the final file's keystream; if
	// there are no files, use a dedicated padding IV derived from the revision.
	var padIV []byte
	var padOffset uint64
	if len(descriptors) > 0 {
		last := descriptors[len(descriptors)-1]
		var err error
		padIV, err = deriveFileIV(ivKey, last.name)
		if err != nil {
			return nil, err
		}
		padOffset = uint64(last.file.Size)
	} else {
		var err error
		padIV, err = deriveFileIV(ivKey, paddingPseudoName)
		if err != nil {
			return nil, err
		}
		padOffset = 0
	}

	currentSize := int64(len(headerMagic) + 1 + len(contentID) + len(metaCipher))
	for _, desc := range descriptors {
		currentSize += desc.file.Size
	}
	padLen := paddingNeeded(currentSize)
	if padLen > 0 {
		if err := writePadding(w, xor, padIV, padOffset, padLen); err != nil {
			return nil, err
		}
	}

	return contentID, nil
}

// ParseContentFile decodes user content from r and returns the content and
// serialized content identifier.
func ParseContentFile(r io.ReaderAt, contentOpen, metadataOpen OpenFunc,
	xor XORKeyStreamAt) (UserContent, []byte, error) {

	var result UserContent
	if contentOpen == nil || metadataOpen == nil {
		return result, nil, errors.New("usercontent: encryption primitives must be provided")
	}
	if xor == nil {
		return result, nil, errors.New("usercontent: XOR function missing")
	}

	header := make([]byte, len(headerMagic)+1)
	if _, err := r.ReadAt(header, 0); err != nil {
		return result, nil, err
	}
	if string(header[:len(headerMagic)]) != headerMagic {
		return result, nil, errInvalidMagic
	}
	if header[len(headerMagic)] != currentVersion {
		return result, nil, fmt.Errorf("usercontent: unsupported version %d",
			header[len(headerMagic)])
	}

	offset := int64(len(header))
	cid := make([]byte, siv.TagSize+contentIDPlaintextSize)
	if _, err := r.ReadAt(cid, offset); err != nil {
		return result, nil, err
	}
	offset += int64(len(cid))

	revision, err := ParseContentID(cid, contentOpen)
	if err != nil {
		return result, nil, err
	}

	metaLen := revision.GetMetadataAeadLength()
	metaBuf := make([]byte, metaLen)
	if _, err := r.ReadAt(metaBuf, offset); err != nil {
		return result, nil, err
	}
	offset += metaLen

	ad, err := revisionMetadataAD(revision)
	if err != nil {
		return result, nil, err
	}
	metaPlain, err := metadataOpen(metaBuf, ad)
	if err != nil {
		return result, nil, err
	}
	var metadata storedpb.Metadata
	if err := proto.Unmarshal(metaPlain, &metadata); err != nil {
		return result, nil, err
	}

	// Recover file IV material only after authenticating the metadata.
	metadataTag := metaBuf[len(metaBuf)-siv.TagSize:]
	ivKey, err := revisionIVKey(revision, metadataTag)
	if err != nil {
		return result, nil, err
	}

	result.CreatedAt = time.Unix(revision.GetCreatedAt(), revision.GetCreatedAtNs())
	result.Peers = metadata.GetPeers()
	result.Files = make(map[string]File, len(metadata.GetFiles()))

	names := orderedNames(&metadata)
	fileHeaders := make(map[string]*storedpb.FileHeader, len(metadata.GetFiles()))
	for _, fh := range metadata.GetFiles() {
		fileHeaders[fh.GetName()] = fh
	}
	for _, name := range names {
		header, ok := fileHeaders[name]
		if !ok {
			return result, nil, errInvalidContent
		}
		size := header.GetFileLength()
		fileIV, err := deriveFileIV(ivKey, name)
		if err != nil {
			return result, nil, err
		}
		file, err := newCipherFile(r, xor, fileIV, offset, size)
		if err != nil {
			return result, nil, err
		}
		f := File{
			Body: file, Size: size,
		}
		if err := verifyFileHash(header.GetFileSha256(), f); err != nil {
			return result, nil, err
		}
		result.Files[name] = f
		offset += size
	}

	// Skip trailing padding if present; padding ensures total size is aligned.
	if sized, ok := r.(interface{ Size() int64 }); ok {
		totalSize := sized.Size()
		if totalSize < offset {
			return result, nil, errInvalidContent
		}
		padding := totalSize - offset
		if totalSize%contentSizeAlignment != 0 {
			return result, nil, errInvalidContent
		}
		if padding < 0 {
			return result, nil, errInvalidContent
		}
	}

	return result, cid, nil
}

// --- helper structures ---

type fileDescriptor struct {
	name string
	file File
}

// hashFile computes a SHA-256 digest for the provided file reader.
func hashFile(file File) ([]byte, error) {
	if file.Body == nil {
		return nil, errors.New("usercontent: file body missing for hash")
	}
	hasher := sha256.New()
	reader := io.NewSectionReader(file.Body, 0, file.Size)
	if _, err := io.Copy(hasher, reader); err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}

// orderedNames returns the sorted list of file names from metadata.
func orderedNames(metadata *storedpb.Metadata) []string {
	names := make([]string, 0, len(metadata.GetFiles()))
	for _, fh := range metadata.GetFiles() {
		names = append(names, fh.GetName())
	}
	sort.Strings(names)
	return names
}

// revisionMaterial serializes the revision fields into a fixed buffer.
func revisionMaterial(revision *storedpb.ContentRevision) ([]byte, error) {
	if revision == nil {
		return nil, errors.New("usercontent: nil revision")
	}
	if revision.GetCreatedAt() < 0 {
		return nil, errors.New("usercontent: negative revision created_at")
	}
	if revision.GetCreatedAtNs() < 0 {
		return nil, errors.New("usercontent: negative revision created_at_ns")
	}
	if revision.GetCreatedAtNs() >= 1_000_000_000 {
		return nil, errors.New("usercontent: revision created_at_ns out of range")
	}
	if revision.GetMetadataAeadLength() < 0 {
		return nil, errors.New("usercontent: negative metadata aead length")
	}

	buf := make([]byte, 24)
	binary.BigEndian.PutUint64(buf[0:8], uint64(revision.GetCreatedAt()))
	binary.BigEndian.PutUint64(buf[8:16], uint64(revision.GetCreatedAtNs()))
	binary.BigEndian.PutUint64(buf[16:], uint64(revision.GetMetadataAeadLength()))

	return buf, nil
}

// revisionIVKey derives the base IV key material from the revision and metadata tag.
func revisionIVKey(revision *storedpb.ContentRevision, metadataTag []byte) ([]byte, error) {
	material, err := revisionMaterial(revision)
	if err != nil {
		return nil, err
	}

	if len(metadataTag) != siv.TagSize {
		return nil, errors.New("usercontent: invalid metadata tag length")
	}

	deriver := hkdf.New(
		sha256.New, material, metadataTag, []byte("usercontent/file-iv"),
	)
	key := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(deriver, key); err != nil {
		return nil, err
	}

	return key, nil
}

// revisionMetadataAD derives associated data for metadata sealing.
func revisionMetadataAD(revision *storedpb.ContentRevision) ([]byte, error) {
	material, err := revisionMaterial(revision)
	if err != nil {
		return nil, err
	}

	deriver := hkdf.New(
		sha256.New, material, nil, []byte("usercontent/metadata-ad"),
	)
	ad := make([]byte, sha256.Size)
	if _, err := io.ReadFull(deriver, ad); err != nil {
		return nil, err
	}

	return ad, nil
}

// deriveFileIV produces a per-file IV from the base IV key and filename.
func deriveFileIV(ivKey []byte, name string) ([]byte, error) {
	if len(ivKey) == 0 {
		return nil, errors.New("usercontent: missing iv key")
	}
	deriver := hkdf.New(
		sha256.New, ivKey, nil, []byte("usercontent/file-iv/"+name),
	)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(deriver, iv); err != nil {
		return nil, err
	}
	return iv, nil
}

// writeEncryptedFile streams a file through the XOR keystream and writes the ciphertext.
func writeEncryptedFile(w io.Writer, desc fileDescriptor,
	xor XORKeyStreamAt, iv []byte) error {

	reader := io.NewSectionReader(desc.file.Body, 0, desc.file.Size)
	buf := make([]byte, 32*1024)
	offset := uint64(0)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			xor(chunk, chunk, iv, offset)
			if _, werr := w.Write(chunk); werr != nil {
				return werr
			}
			offset += uint64(n)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}

	return nil
}

// cipherFile wraps an encrypted section and applies the XOR keystream on reads.
type cipherFile struct {
	src    io.ReaderAt
	xor    XORKeyStreamAt
	iv     []byte
	offset int64
	length int64
	size   int64
}

// newCipherFile constructs a reader that decrypts on the fly using XOR.
func newCipherFile(src io.ReaderAt, xor XORKeyStreamAt, iv []byte,
	offset, size int64) (*cipherFile, error) {

	if offset < 0 || size < 0 {
		return nil, errors.New("usercontent: invalid file lengths")
	}

	return &cipherFile{
		src:    src,
		xor:    xor,
		iv:     iv,
		offset: offset,
		size:   size,
	}, nil
}

// ReadAt reads from the encrypted file, applying the keystream for the given offset.
func (cf *cipherFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("usercontent: negative offset")
	}
	if off >= cf.size {
		return 0, io.EOF
	}

	if int64(len(p)) > cf.size-off {
		p = p[:cf.size-off]
	}

	n, err := cf.src.ReadAt(p, cf.offset+off)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}

	cf.xor(p[:n], p[:n], cf.iv, uint64(off))
	if int64(n)+off >= cf.size || n < len(p) {
		return n, io.EOF
	}

	return n, nil
}

// readUint32 reads a uint32 in big-endian order from the reader at offset.
func readUint32(r io.ReaderAt, offset int64, out *uint32) error {
	buf := make([]byte, 4)
	if _, err := r.ReadAt(buf, offset); err != nil {
		return err
	}
	*out = binary.BigEndian.Uint32(buf)
	return nil
}

// readUint64 reads a uint64 in big-endian order from the reader at offset.
func readUint64(r io.ReaderAt, offset int64, out *uint64) error {
	buf := make([]byte, 8)
	if _, err := r.ReadAt(buf, offset); err != nil {
		return err
	}
	*out = binary.BigEndian.Uint64(buf)
	return nil
}

// verifyFileHash compares the stored hash with the hash of the decrypted file.
func verifyFileHash(expected []byte, file File) error {
	if len(expected) == 0 {
		return errInvalidContent
	}
	sum, err := hashFile(file)
	if err != nil {
		return err
	}
	if !bytes.Equal(sum, expected) {
		return errInvalidContent
	}
	return nil
}

// paddingNeeded returns the number of bytes required to align the size to the
// contentSizeAlignment boundary.
func paddingNeeded(size int64) int64 {
	rem := size % contentSizeAlignment
	if rem == 0 {
		return 0
	}
	return contentSizeAlignment - rem
}

// writePadding emits encrypted zero bytes using the provided IV and offset so
// ciphertext size reaches the alignment boundary.
func writePadding(w io.Writer, xor XORKeyStreamAt, iv []byte, offset uint64,
	length int64) error {

	if length == 0 {
		return nil
	}
	buf := make([]byte, 32*1024)
	var written int64
	for written < length {
		chunk := buf
		if remaining := length - written; remaining < int64(len(chunk)) {
			chunk = chunk[:remaining]
		}
		for i := range chunk {
			chunk[i] = 0
		}
		xor(chunk, chunk, iv, offset+uint64(written))
		n, err := w.Write(chunk)
		written += int64(n)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("usercontent: short write during padding")
		}
	}

	return nil
}
