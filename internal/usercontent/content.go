package usercontent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
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

var errInvalidMagic = errors.New("usercontent: invalid magic")

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

// WriteContentFile writes an encoded representation of user content to w.
func WriteContentFile(w io.Writer, uc UserContent, contentIDKey, filesKey []byte) error {
	metadata, descriptors, err := buildMetadata(uc)
	if err != nil {
		return err
	}
	if len(contentIDKey) == 0 || len(filesKey) == 0 {
		return errors.New("usercontent: keys must be non-empty")
	}

	contentID, err := MakeContentID(uc.CreatedAt, contentIDKey)
	if err != nil {
		return err
	}

	metaKey, fileKey, err := deriveKeys(filesKey)
	if err != nil {
		return err
	}

	nonce, encMeta, err := encryptMetadata(metaKey, metadata)
	if err != nil {
		return err
	}
	metadata.MostRecentContent.MetadataAeadLength = int64(len(nonce) + len(encMeta))

	if _, err := w.Write([]byte(headerMagic)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{currentVersion}); err != nil {
		return err
	}
	if _, err := w.Write(contentID); err != nil {
		return err
	}

	metaLen := uint32(len(nonce) + len(encMeta))
	if err := binary.Write(w, binary.BigEndian, metaLen); err != nil {
		return err
	}
	if _, err := w.Write(nonce); err != nil {
		return err
	}
	if _, err := w.Write(encMeta); err != nil {
		return err
	}

	for _, desc := range descriptors {
		if err := writeEncryptedFile(w, fileKey, desc); err != nil {
			return err
		}
	}

	return nil
}

// ParseContentFile parses an encoded content file from r.
func ParseContentFile(r io.ReaderAt, contentIDKey, filesKey []byte) (UserContent, error) {
	var result UserContent
	if len(contentIDKey) == 0 || len(filesKey) == 0 {
		return result, errors.New("usercontent: keys must be non-empty")
	}

	header := make([]byte, len(headerMagic)+1+contentIDSize)
	if _, err := r.ReadAt(header, 0); err != nil {
		return result, err
	}
	if string(header[:len(headerMagic)]) != headerMagic {
		return result, errInvalidMagic
	}
	if header[len(headerMagic)] != currentVersion {
		return result, fmt.Errorf("usercontent: unsupported version %d", header[len(headerMagic)])
	}
	contentID := header[len(headerMagic)+1:]
	createdAt, err := ParseContentID(contentID, contentIDKey)
	if err != nil {
		return result, err
	}

	offset := int64(len(header))
	metaLenBytes := make([]byte, 4)
	if _, err := r.ReadAt(metaLenBytes, offset); err != nil {
		return result, err
	}
	offset += 4
	metaLen := binary.BigEndian.Uint32(metaLenBytes)

	metaBuf := make([]byte, metaLen)
	if _, err := r.ReadAt(metaBuf, offset); err != nil {
		return result, err
	}
	offset += int64(metaLen)

	nonce := metaBuf[:12]
	encMeta := metaBuf[12:]

	metaKey, fileKey, err := deriveKeys(filesKey)
	if err != nil {
		return result, err
	}
	metadata, err := decryptMetadata(metaKey, nonce, encMeta)
	if err != nil {
		return result, err
	}

	result.CreatedAt = createdAt
	result.Peers = metadata.GetPeers()
	result.Files = make(map[string]File, len(metadata.GetFiles()))

	order := orderedNames(metadata)
	for _, name := range order {
		lenBuf := make([]byte, 8)
		if _, err := r.ReadAt(lenBuf, offset); err != nil {
			return result, err
		}
		offset += 8
		cipherLen := int64(binary.BigEndian.Uint64(lenBuf))

		plainLen := findFileLength(metadata, name)
		file, err := newCipherFile(r, fileKey, name, offset, cipherLen, plainLen)
		if err != nil {
			return result, err
		}
		result.Files[name] = File{Body: file, Size: plainLen}
		offset += cipherLen
	}

	return result, nil
}

// --- Helpers ---

type fileDescriptor struct {
	name string
	file File
	hash []byte
}

func buildMetadata(uc UserContent) (*storedpb.Metadata, []fileDescriptor, error) {
	if uc.Files == nil {
		return nil, nil, errors.New("usercontent: no files provided")
	}
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
		descriptors = append(descriptors, fileDescriptor{name: name, file: file, hash: sum})
	}

	return meta, descriptors, nil
}

// MetadataFromUserContent produces the stored metadata representation for the
// provided user content.
func MetadataFromUserContent(uc UserContent) (*storedpb.Metadata, error) {
	meta, _, err := buildMetadata(uc)
	return meta, err
}

func hashFile(file File) ([]byte, error) {
	hasher := sha256.New()
	reader := io.NewSectionReader(file.Body, 0, file.Size)
	if _, err := io.Copy(hasher, reader); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func deriveKeys(filesKey []byte) ([]byte, []byte, error) {
	if len(filesKey) == 0 {
		return nil, nil, errors.New("usercontent: empty files key")
	}
	metaKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, filesKey, nil, []byte("usercontent-metadata")), metaKey); err != nil {
		return nil, nil, err
	}
	fileKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, filesKey, nil, []byte("usercontent-file")), fileKey); err != nil {
		return nil, nil, err
	}
	return metaKey, fileKey, nil
}

func deriveFileIV(fileKey []byte, name string) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, fileKey, nil, []byte("usercontent-iv:"+name)), iv); err != nil {
		return nil, err
	}
	return iv, nil
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

type cipherFile struct {
	src       io.ReaderAt
	offset    int64
	cipherLen int64
	plainLen  int64
	fileKey   []byte
	name      string
}

func newCipherFile(src io.ReaderAt, fileKey []byte, name string, offset, cipherLen, plainLen int64) (*cipherFile, error) {
	if plainLen < 0 || cipherLen < 0 {
		return nil, errors.New("usercontent: invalid file lengths")
	}
	return &cipherFile{
		src:       src,
		offset:    offset,
		cipherLen: cipherLen,
		plainLen:  plainLen,
		fileKey:   append([]byte(nil), fileKey...),
		name:      name,
	}, nil
}

func (cf *cipherFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("usercontent: negative offset")
	}
	if off >= cf.plainLen {
		return 0, io.EOF
	}
	if int64(len(p)) > cf.plainLen-off {
		p = p[:cf.plainLen-off]
	}
	ciphertext := make([]byte, len(p))
	n, err := cf.src.ReadAt(ciphertext, cf.offset+off)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	plaintext, err := decryptSlice(ciphertext[:n], cf.fileKey, cf.name, off)
	if err != nil {
		return 0, err
	}
	copy(p, plaintext)
	if int64(n)+off >= cf.plainLen || n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func decryptSlice(ciphertext []byte, fileKey []byte, name string, off int64) ([]byte, error) {
	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return nil, err
	}
	iv, err := deriveFileIV(fileKey, name)
	if err != nil {
		return nil, err
	}
	keystream := make([]byte, len(ciphertext))
	xorAt(block, iv, keystream, off)
	for i := range ciphertext {
		keystream[i] ^= ciphertext[i]
	}
	return keystream, nil
}

func xorAt(block cipher.Block, iv []byte, dst []byte, off int64) {
	blockSize := block.BlockSize()
	counter := make([]byte, blockSize)
	copy(counter, iv)
	blocksToSkip := off / int64(blockSize)
	addCounter(counter, uint64(blocksToSkip))

	buf := make([]byte, blockSize)
	skip := int(off % int64(blockSize))
	written := 0

	for written < len(dst) {
		block.Encrypt(buf, counter)
		for i := skip; i < blockSize && written < len(dst); i++ {
			dst[written] = buf[i]
			written++
		}
		skip = 0
		addCounter(counter, 1)
	}
}

func addCounter(counter []byte, delta uint64) {
	carry := delta
	for i := len(counter) - 1; i >= 0 && carry > 0; i-- {
		sum := uint64(counter[i]) + (carry & 0xff)
		counter[i] = byte(sum)
		carry = carry>>8 + sum>>8
	}
}

func encryptMetadata(metaKey []byte, metadata *storedpb.Metadata) ([]byte, []byte, error) {
	block, err := aes.NewCipher(metaKey)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	buf, err := proto.Marshal(metadata)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, buf, nil)
	return nonce, ciphertext, nil
}

func decryptMetadata(metaKey []byte, nonce, ciphertext []byte) (*storedpb.Metadata, error) {
	block, err := aes.NewCipher(metaKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	var metadata storedpb.Metadata
	if err := proto.Unmarshal(plaintext, &metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

func writeEncryptedFile(w io.Writer, fileKey []byte, desc fileDescriptor) error {
	if desc.file.Size < 0 || desc.file.Size > math.MaxInt64 {
		return fmt.Errorf("usercontent: invalid file size for %s", desc.name)
	}
	if err := binary.Write(w, binary.BigEndian, uint64(desc.file.Size)); err != nil {
		return err
	}
	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return err
	}
	iv, err := deriveFileIV(fileKey, desc.name)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(block, iv)
	reader := io.NewSectionReader(desc.file.Body, 0, desc.file.Size)
	buf := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			stream.XORKeyStream(chunk, chunk)
			if _, werr := w.Write(chunk); werr != nil {
				return werr
			}
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
