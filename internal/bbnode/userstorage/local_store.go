package userstorage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/starius/barterbackup/internal/keys"
	"github.com/starius/barterbackup/storedpb"
	"google.golang.org/protobuf/proto"
)

const (
	storageFileName   = "content.bin"
	storageMagicBytes = "BBST"
	storageVersion    = 1
	saltSize          = 32
)

type localStore struct {
	dir      string
	master   []byte
	content  []byte
	files    map[string][]byte
	metadata *storedpb.Metadata
}

func newLocalStore(dir string, master []byte) (*localStore, error) {
	if dir == "" {
		return nil, errors.New("storage dir is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create storage dir: %w", err)
	}
	s := &localStore{
		dir:    dir,
		master: append([]byte{}, master...),
		files:  make(map[string][]byte),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *localStore) storagePath() string {
	return filepath.Join(s.dir, storageFileName)
}

func (s *localStore) load() error {
	path := s.storagePath()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read storage: %w", err)
	}
	meta, files, err := s.decryptContent(data)
	if err != nil {
		return err
	}
	s.metadata = meta
	s.files = files
	s.content = data
	return nil
}

func (s *localStore) decryptContent(blob []byte) (*storedpb.Metadata, map[string][]byte, error) {
	r := bytes.NewReader(blob)

	magic := make([]byte, len(storageMagicBytes))
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, nil, fmt.Errorf("read magic: %w", err)
	}
	if string(magic) != storageMagicBytes {
		return nil, nil, errors.New("invalid storage magic")
	}

	var version uint8
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return nil, nil, fmt.Errorf("read version: %w", err)
	}
	if version != storageVersion {
		return nil, nil, fmt.Errorf("unsupported storage version %d", version)
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, nil, fmt.Errorf("read salt: %w", err)
	}

	var metadataLen uint32
	if err := binary.Read(r, binary.BigEndian, &metadataLen); err != nil {
		return nil, nil, fmt.Errorf("read metadata length: %w", err)
	}

	if metadataLen < 12 {
		return nil, nil, errors.New("metadata length too small")
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, nil, fmt.Errorf("read metadata nonce: %w", err)
	}

	cipherLen := int(metadataLen) - len(nonce)
	if cipherLen < 0 {
		return nil, nil, errors.New("negative metadata cipher length")
	}
	metaCipher := make([]byte, cipherLen)
	if _, err := io.ReadFull(r, metaCipher); err != nil {
		return nil, nil, fmt.Errorf("read metadata cipher: %w", err)
	}

	metaKey, err := deriveMetadataKey(s.master, salt)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(metaKey)
	if err != nil {
		return nil, nil, fmt.Errorf("metadata cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("metadata GCM init: %w", err)
	}
	metaPlain, err := gcm.Open(nil, nonce, metaCipher, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("metadata decrypt: %w", err)
	}
	var metadata storedpb.Metadata
	if err := proto.Unmarshal(metaPlain, &metadata); err != nil {
		return nil, nil, fmt.Errorf("metadata decode: %w", err)
	}

	filesKey, err := deriveFilesKey(s.master, salt)
	if err != nil {
		return nil, nil, err
	}
	fileBlock, err := aes.NewCipher(filesKey)
	if err != nil {
		return nil, nil, fmt.Errorf("file cipher init: %w", err)
	}

	files := make(map[string][]byte, len(metadata.GetFiles()))
	for _, fh := range metadata.GetFiles() {
		length := fh.GetFileLength()
		if length < 0 {
			return nil, nil, fmt.Errorf("negative file length for %q", fh.GetName())
		}
		enc := make([]byte, length)
		if _, err := io.ReadFull(r, enc); err != nil {
			return nil, nil, fmt.Errorf("read encrypted file %q: %w", fh.GetName(), err)
		}
		iv, err := deriveFileIV(s.master, salt, fh.GetName())
		if err != nil {
			return nil, nil, err
		}
		plain := make([]byte, length)
		stream := cipher.NewCTR(fileBlock, iv)
		stream.XORKeyStream(plain, enc)

		sum := sha256.Sum256(plain)
		if !bytes.Equal(sum[:], fh.GetFileSha256()) {
			return nil, nil, fmt.Errorf("file %q hash mismatch", fh.GetName())
		}
		files[fh.GetName()] = plain
	}

	return &metadata, files, nil
}

func (s *localStore) setFile(name string, data []byte) error {
	if name == "" {
		return errors.New("file name is empty")
	}
	if s.files == nil {
		s.files = make(map[string][]byte)
	}
	s.files[name] = append([]byte(nil), data...)
	return s.persist()
}

func (s *localStore) getFile(name string) ([]byte, error) {
	data, ok := s.files[name]
	if !ok {
		return nil, ErrFileNotFound
	}
	return append([]byte(nil), data...), nil
}

func (s *localStore) deleteFile(name string) error {
	if s.files == nil {
		return ErrFileNotFound
	}
	if _, ok := s.files[name]; !ok {
		return ErrFileNotFound
	}
	delete(s.files, name)
	return s.persist()
}

func (s *localStore) listFiles() []string {
	names := make([]string, 0, len(s.files))
	for name := range s.files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (s *localStore) persist() error {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("salt: %w", err)
	}

	metaKey, err := deriveMetadataKey(s.master, salt)
	if err != nil {
		return err
	}
	filesKey, err := deriveFilesKey(s.master, salt)
	if err != nil {
		return err
	}

	fileHeaders := make([]*storedpb.FileHeader, 0, len(s.files))
	names := make([]string, 0, len(s.files))
	for name := range s.files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := s.files[name]
		sum := sha256.Sum256(data)
		fileHeaders = append(fileHeaders, &storedpb.FileHeader{
			Name:       name,
			FileLength: int64(len(data)),
			FileSha256: sum[:],
		})
	}

	now := time.Now()
	metadata := &storedpb.Metadata{
		Files: fileHeaders,
	}
	if s.metadata != nil {
		metadata.Peers = s.metadata.GetPeers()
	}
	contentRev := &storedpb.ContentRevision{
		CreatedAt: int64(now.Unix()),
		CreatedAtNs: func() int64 {
			return int64(now.Nanosecond())
		}(),
	}
	metadata.MostRecentContent = contentRev

	var (
		nonce      []byte
		cipherMeta []byte
		metaLen    int
	)
	for i := 0; i < 5; i++ {
		nonce, cipherMeta, metaLen, err = encryptMetadata(metadata, metaKey)
		if err != nil {
			return err
		}
		if metadata.GetMostRecentContent().GetMetadataAeadLength() == int64(metaLen) {
			break
		}
		metadata.MostRecentContent.MetadataAeadLength = int64(metaLen)
		if i == 4 {
			return errors.New("metadata AEAD length did not stabilize")
		}
	}
	metadata.MostRecentContent.MetadataAeadLength = int64(metaLen)

	fileBlock, err := aes.NewCipher(filesKey)
	if err != nil {
		return fmt.Errorf("file cipher init: %w", err)
	}

	buf := bytes.NewBuffer(make([]byte, 0, len(storageMagicBytes)+1+saltSize+4+len(nonce)+len(cipherMeta)))
	buf.WriteString(storageMagicBytes)
	if err := buf.WriteByte(storageVersion); err != nil {
		return fmt.Errorf("buffer write version: %w", err)
	}
	buf.Write(salt)
	if err := binary.Write(buf, binary.BigEndian, uint32(metaLen)); err != nil {
		return fmt.Errorf("buffer write metadata len: %w", err)
	}
	buf.Write(nonce)
	buf.Write(cipherMeta)

	for _, name := range names {
		data := s.files[name]
		iv, err := deriveFileIV(s.master, salt, name)
		if err != nil {
			return err
		}
		enc := make([]byte, len(data))
		stream := cipher.NewCTR(fileBlock, iv)
		stream.XORKeyStream(enc, data)
		buf.Write(enc)
	}

	content := buf.Bytes()
	path := s.storagePath()

	if err := writeAtomic(path, content, 0o600); err != nil {
		return err
	}

	s.content = append([]byte(nil), content...)
	s.metadata = metadata

	return nil
}

func encryptMetadata(metadata *storedpb.Metadata, key []byte) ([]byte, []byte, int, error) {
	plain, err := proto.Marshal(metadata)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("metadata marshal: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("metadata cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("metadata GCM init: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, 0, fmt.Errorf("metadata nonce: %w", err)
	}
	out := gcm.Seal(nil, nonce, plain, nil)
	metaLen := len(nonce) + len(out)
	return nonce, out, metaLen, nil
}

func deriveMetadataKey(master, salt []byte) ([]byte, error) {
	return keys.DeriveKey(master, "bbnode/metadata:"+hex.EncodeToString(salt), 32)
}

func deriveFilesKey(master, salt []byte) ([]byte, error) {
	return keys.DeriveKey(master, "bbnode/files:"+hex.EncodeToString(salt), 32)
}

func deriveFileIV(master []byte, salt []byte, name string) ([]byte, error) {
	return keys.DeriveKey(master, "bbnode/file-iv:"+hex.EncodeToString(salt)+":"+name, aes.BlockSize)
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "tmp-content-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp: %w", err)
	}
	return nil
}
