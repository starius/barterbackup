package usercontent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"
	"time"

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

// MACFactory returns a fresh keyed MAC instance for computing integrity tags.
type MACFactory func() hash.Hash

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

// MetadataFromUserContent builds the metadata structure for the provided
// user content. The returned metadata has MostRecentContent populated with
// creation timestamps but not the AEAD length.
func MetadataFromUserContent(uc UserContent) (*storedpb.Metadata, []fileDescriptor, error) {
	names := make([]string, 0, len(uc.Files))
	for name := range uc.Files {
		names = append(names, name)
	}
	sort.Strings(names)

	meta := &storedpb.Metadata{
		MostRecentContent: &storedpb.ContentRevision{
			CreatedAt:   uc.CreatedAt.Unix(),
			CreatedAtNs: int64(uc.CreatedAt.Nanosecond()),
		},
		Peers: append([]*storedpb.Peer(nil), uc.Peers...),
	}

	descriptors := make([]fileDescriptor, 0, len(names))
	for _, name := range names {
		file, ok := uc.Files[name]
		if !ok {
			return nil, nil, fmt.Errorf("usercontent: missing file %q", name)
		}
		sum, err := hashFile(file)
		if err != nil {
			return nil, nil, err
		}
		meta.Files = append(meta.Files, &storedpb.FileHeader{
			Name:       name,
			FileLength: file.Size,
			FileSha256: sum,
		})
		descriptors = append(descriptors, fileDescriptor{name: name, file: file})
	}

	return meta, descriptors, nil
}

// WriteContentFile encodes user content to w using the provided primitives and
// returns the metadata (with AEAD length populated) and the generated content ID.
func WriteContentFile(w io.Writer, uc UserContent, contentBlock cipher.Block, macFactory MACFactory, metadataAEAD cipher.AEAD, xor XORKeyStreamAt, ivKey []byte) (*storedpb.Metadata, []byte, error) {
	if contentBlock == nil || macFactory == nil || metadataAEAD == nil {
		return nil, nil, errors.New("usercontent: encryption primitives must be provided")
	}
	if xor == nil {
		return nil, nil, errors.New("usercontent: XOR function missing")
	}

	metadata, descriptors, err := MetadataFromUserContent(uc)
	if err != nil {
		return nil, nil, err
	}

	nonceMeta := make([]byte, metadataAEAD.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonceMeta); err != nil {
		return nil, nil, err
	}
	metaPlain, err := proto.Marshal(metadata)
	if err != nil {
		return nil, nil, err
	}
	metaCipher := metadataAEAD.Seal(nil, nonceMeta, metaPlain, nil)
	metadata.MostRecentContent.MetadataAeadLength = int64(len(nonceMeta) + len(metaCipher))

	contentID, err := MakeContentID(metadata.MostRecentContent, contentBlock, macFactory)
	if err != nil {
		return nil, nil, err
	}

	if _, err := w.Write([]byte(headerMagic)); err != nil {
		return nil, nil, err
	}
	if _, err := w.Write([]byte{currentVersion}); err != nil {
		return nil, nil, err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(contentID))); err != nil {
		return nil, nil, err
	}
	if _, err := w.Write(contentID); err != nil {
		return nil, nil, err
	}

	if err := binary.Write(w, binary.BigEndian, uint32(len(nonceMeta)+len(metaCipher))); err != nil {
		return nil, nil, err
	}
	if _, err := w.Write(nonceMeta); err != nil {
		return nil, nil, err
	}
	if _, err := w.Write(metaCipher); err != nil {
		return nil, nil, err
	}

	for _, desc := range descriptors {
		if err := writeEncryptedFile(w, desc, xor, ivKey); err != nil {
			return nil, nil, err
		}
	}

	return metadata, contentID, nil
}

// ParseContentFile decodes user content from r, returning the content, metadata
// and the serialized content identifier.
func ParseContentFile(r io.ReaderAt, contentBlock cipher.Block, macFactory MACFactory, metadataAEAD cipher.AEAD, xor XORKeyStreamAt, ivKey []byte) (UserContent, *storedpb.Metadata, []byte, error) {
	var result UserContent
	if contentBlock == nil || macFactory == nil || metadataAEAD == nil {
		return result, nil, nil, errors.New("usercontent: encryption primitives must be provided")
	}
	if xor == nil {
		return result, nil, nil, errors.New("usercontent: XOR function missing")
	}

	header := make([]byte, len(headerMagic)+1)
	if _, err := r.ReadAt(header, 0); err != nil {
		return result, nil, nil, err
	}
	if string(header[:len(headerMagic)]) != headerMagic {
		return result, nil, nil, errInvalidMagic
	}
	if header[len(headerMagic)] != currentVersion {
		return result, nil, nil, fmt.Errorf("usercontent: unsupported version %d", header[len(headerMagic)])
	}

	offset := int64(len(header))
	var cidLen uint32
	if err := readUint32(r, offset, &cidLen); err != nil {
		return result, nil, nil, err
	}
	offset += 4
	cid := make([]byte, cidLen)
	if _, err := r.ReadAt(cid, offset); err != nil {
		return result, nil, nil, err
	}
	offset += int64(cidLen)

	revision, err := ParseContentID(cid, contentBlock, macFactory)
	if err != nil {
		return result, nil, nil, err
	}

	var metaLen uint32
	if err := readUint32(r, offset, &metaLen); err != nil {
		return result, nil, nil, err
	}
	offset += 4
	if int64(metaLen) != revision.GetMetadataAeadLength() {
		return result, nil, nil, errInvalidContent
	}
	metaBuf := make([]byte, metaLen)
	if _, err := r.ReadAt(metaBuf, offset); err != nil {
		return result, nil, nil, err
	}
	offset += int64(metaLen)

	nonceSize := metadataAEAD.NonceSize()
	if len(metaBuf) < nonceSize {
		return result, nil, nil, errInvalidContent
	}
	nonce := metaBuf[:nonceSize]
	encMeta := metaBuf[nonceSize:]
	metaPlain, err := metadataAEAD.Open(nil, nonce, encMeta, nil)
	if err != nil {
		return result, nil, nil, err
	}
	var metadata storedpb.Metadata
	if err := proto.Unmarshal(metaPlain, &metadata); err != nil {
		return result, nil, nil, err
	}

	result.CreatedAt = time.Unix(revision.GetCreatedAt(), revision.GetCreatedAtNs())
	result.Peers = metadata.GetPeers()
	result.Files = make(map[string]File, len(metadata.GetFiles()))

	names := orderedNames(&metadata)
	for _, name := range names {
		var cipherLen uint64
		if err := readUint64(r, offset, &cipherLen); err != nil {
			return result, nil, nil, err
		}
		offset += 8
		plainLen := findFileLength(&metadata, name)
		file, err := newCipherFile(r, xor, ivKey, name, offset, int64(cipherLen), plainLen)
		if err != nil {
			return result, nil, nil, err
		}
		result.Files[name] = File{Body: file, Size: plainLen}
		offset += int64(cipherLen)
	}

	metadata.MostRecentContent = revision
	return result, &metadata, cid, nil
}

// --- helper structures ---

type fileDescriptor struct {
	name string
	file File
}

func hashFile(file File) ([]byte, error) {
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
