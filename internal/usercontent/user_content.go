package usercontent

import (
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

const (
	headerMagic    = "UCNT"
	currentVersion = 1
)

var (
	errInvalidMagic   = errors.New("usercontent: invalid magic")
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
func metadataFromUserContent(uc UserContent) ([]byte, []fileDescriptor, *storedpb.ContentRevision, error) {
	names := make([]string, 0, len(uc.Files))
	for name := range uc.Files {
		names = append(names, name)
	}
	sort.Strings(names)

	meta := &storedpb.Metadata{
		Peers: append([]*storedpb.Peer(nil), uc.Peers...),
	}
	revision := &storedpb.ContentRevision{
		CreatedAt:   uc.CreatedAt.Unix(),
		CreatedAtNs: int64(uc.CreatedAt.Nanosecond()),
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
	revision.MetadataAeadLength = int64(len(metaPlain) + siv.TagSize)
	return metaPlain, descriptors, revision, nil
}

// WriteContentFile encodes user content to w using the provided primitives and
// returns the generated content ID.
func WriteContentFile(w io.Writer, uc UserContent, contentSeal, metadataSeal SealFunc, xor XORKeyStreamAt) ([]byte, error) {
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
	revision.MetadataAeadLength = int64(len(metaCipher))

	ivKey, err := revisionIVKey(revision)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("usercontent: unexpected content id length %d", len(contentID))
	}
	if _, err := w.Write(contentID); err != nil {
		return nil, err
	}

	if _, err := w.Write(metaCipher); err != nil {
		return nil, err
	}

	for _, desc := range descriptors {
		if err := writeEncryptedFile(w, desc, xor, ivKey); err != nil {
			return nil, err
		}
	}

	return contentID, nil
}

// ParseContentFile decodes user content from r and returns the content and
// serialized content identifier.
func ParseContentFile(r io.ReaderAt, contentOpen, metadataOpen OpenFunc, xor XORKeyStreamAt) (UserContent, []byte, error) {
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
		return result, nil, fmt.Errorf("usercontent: unsupported version %d", header[len(headerMagic)])
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

	ivKey, err := revisionIVKey(revision)
	if err != nil {
		return result, nil, err
	}

	metaLen := revision.GetMetadataAeadLength()
	if metaLen < 0 {
		return result, nil, errInvalidContent
	}
	if metaLen > int64(int(^uint(0)>>1)) {
		return result, nil, fmt.Errorf("usercontent: metadata ciphertext too large: %d", metaLen)
	}
	length := int(metaLen)
	metaBuf := make([]byte, length)
	if _, err := r.ReadAt(metaBuf, offset); err != nil {
		return result, nil, err
	}
	offset += int64(length)

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

	result.CreatedAt = time.Unix(revision.GetCreatedAt(), revision.GetCreatedAtNs())
	result.Peers = metadata.GetPeers()
	result.Files = make(map[string]File, len(metadata.GetFiles()))

	names := orderedNames(&metadata)
	for _, name := range names {
		var cipherLen uint64
		if err := readUint64(r, offset, &cipherLen); err != nil {
			return result, nil, err
		}
		offset += 8
		plainLen := findFileLength(&metadata, name)
		file, err := newCipherFile(r, xor, ivKey, name, offset, int64(cipherLen), plainLen)
		if err != nil {
			return result, nil, err
		}
		result.Files[name] = File{Body: file, Size: plainLen}
		offset += int64(cipherLen)
	}

	return result, cid, nil
}

// --- helper structures ---

type fileDescriptor struct {
	name string
	file File
}

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

func orderedNames(metadata *storedpb.Metadata) []string {
	names := make([]string, 0, len(metadata.GetFiles()))
	for _, fh := range metadata.GetFiles() {
		names = append(names, fh.GetName())
	}
	sort.Strings(names)
	return names
}

func findFileLength(metadata *storedpb.Metadata, name string) int64 {
	for _, fh := range metadata.GetFiles() {
		if fh.GetName() == name {
			return fh.GetFileLength()
		}
	}
	return 0
}

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

func revisionIVKey(revision *storedpb.ContentRevision) ([]byte, error) {
	material, err := revisionMaterial(revision)
	if err != nil {
		return nil, err
	}
	deriver := hkdf.New(sha256.New, material, nil, []byte("usercontent/file-iv"))
	key := make([]byte, sha256.Size)
	if _, err := io.ReadFull(deriver, key); err != nil {
		return nil, err
	}
	return key, nil
}

func revisionMetadataAD(revision *storedpb.ContentRevision) ([]byte, error) {
	material, err := revisionMaterial(revision)
	if err != nil {
		return nil, err
	}
	deriver := hkdf.New(sha256.New, material, nil, []byte("usercontent/metadata-ad"))
	ad := make([]byte, sha256.Size)
	if _, err := io.ReadFull(deriver, ad); err != nil {
		return nil, err
	}
	return ad, nil
}

func writeEncryptedFile(w io.Writer, desc fileDescriptor, xor XORKeyStreamAt, ivKey []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint64(desc.file.Size)); err != nil {
		return err
	}
	iv, err := deriveFileIV(ivKey, desc.name, aes.BlockSize)
	if err != nil {
		return err
	}
	reader := io.NewSectionReader(desc.file.Body, 0, desc.file.Size)
	buf := make([]byte, 32*1024)
	offset := uint64(0)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			xor(chunk, buf[:n], iv, offset)
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

type cipherFile struct {
	src    io.ReaderAt
	xor    XORKeyStreamAt
	iv     []byte
	offset int64
	length int64
	size   int64
}

func newCipherFile(src io.ReaderAt, xor XORKeyStreamAt, ivKey []byte, name string, offset, cipherLen, plainLen int64) (*cipherFile, error) {
	if plainLen < 0 || cipherLen < 0 {
		return nil, errors.New("usercontent: invalid file lengths")
	}
	iv, err := deriveFileIV(ivKey, name, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return &cipherFile{src: src, xor: xor, iv: iv, offset: offset, length: cipherLen, size: plainLen}, nil
}

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
	ciphertext := make([]byte, len(p))
	n, err := cf.src.ReadAt(ciphertext, cf.offset+off)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	cf.xor(p[:n], ciphertext[:n], cf.iv, uint64(off))
	if int64(n)+off >= cf.size || n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func deriveFileIV(ivKey []byte, name string, size int) ([]byte, error) {
	if len(ivKey) == 0 {
		return nil, errors.New("usercontent: empty iv key")
	}
	iv := make([]byte, size)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ivKey, nil, []byte("usercontent-iv:"+name)), iv); err != nil {
		return nil, err
	}
	return iv, nil
}

func readUint32(r io.ReaderAt, offset int64, out *uint32) error {
	buf := make([]byte, 4)
	if _, err := r.ReadAt(buf, offset); err != nil {
		return err
	}
	*out = binary.BigEndian.Uint32(buf)
	return nil
}

func readUint64(r io.ReaderAt, offset int64, out *uint64) error {
	buf := make([]byte, 8)
	if _, err := r.ReadAt(buf, offset); err != nil {
		return err
	}
	*out = binary.BigEndian.Uint64(buf)
	return nil
}
