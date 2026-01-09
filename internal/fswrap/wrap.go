package fswrap

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"sync"
	"time"

	"github.com/starius/aesctrat"
	"github.com/starius/barterbackup/internal/bbnode/userstorage"
	"github.com/starius/barterbackup/internal/keys"
	"github.com/starius/barterbackup/internal/usercontent"
	"golang.org/x/crypto/hkdf"
)

const (
	nameNonceString = "fswrap-name"
)

// Wrapper applies deterministic encryption to filenames and file contents so our
// locally stored blobs look like every other peer's files in the shared directory.
type Wrapper struct {
	// under is the wrapped filesystem.
	under userstorage.Filesystem

	// nameSeal seals plaintext filenames.
	nameSeal usercontent.SealFunc

	// nameOpen opens sealed filenames.
	nameOpen usercontent.OpenFunc

	// ctrKey encrypts file bodies.
	ctrKey []byte

	// hashes caches plaintext SHA-256 digests keyed by plaintext filename.
	hashes map[string][]byte

	// lastTS tracks the last timestamp used for deriving per-file IVs.
	lastTS uint64

	mu sync.RWMutex
}

// New constructs a wrapped filesystem with the provided master key.
func New(fsys userstorage.Filesystem, master []byte) (*Wrapper, error) {
	if fsys == nil {
		return nil, errors.New("fswrap: filesystem is nil")
	}
	if len(master) < 32 {
		return nil, errors.New("fswrap: master key too short")
	}

	nameKey, err := keys.DeriveKey(master, "fswrap/name", 32)
	if err != nil {
		return nil, err
	}
	contentKey, err := keys.DeriveKey(master, "fswrap/content", 32)
	if err != nil {
		return nil, err
	}
	nameSeal, nameOpen, err := usercontent.NewAEAD(nameKey)
	if err != nil {
		return nil, err
	}

	return &Wrapper{
		under:    fsys,
		nameSeal: nameSeal,
		nameOpen: nameOpen,
		ctrKey:   contentKey,
		hashes:   make(map[string][]byte),
	}, nil
}

// OpenRead locates the newest encrypted file for the plaintext name and returns
// a reader that decrypts contents on the fly.
func (w *Wrapper) OpenRead(name string) (userstorage.ReadFile, error) {
	encName, ts, err := w.lookupEncryptedName(name)
	if err != nil {
		return nil, err
	}

	r, err := w.under.OpenRead(encName)
	if err != nil {
		return nil, err
	}

	xor := aesctrat.NewAesCtr(w.ctrKey).XORKeyStreamAt

	iv, err := deriveIV(w.ctrKey, ts)
	if err != nil {
		_ = r.Close()
		return nil, err
	}

	return &reader{under: r, xor: xor, iv: iv}, nil
}

// OpenWrite returns a writer that encrypts content and defers visibility until Finalize.
func (w *Wrapper) OpenWrite() (userstorage.WriteFile, error) {
	ts := uint64(time.Now().Unix())
	w.mu.Lock()
	if ts <= w.lastTS {
		ts = w.lastTS + 1
	}
	w.lastTS = ts
	w.mu.Unlock()

	wr, err := w.under.OpenWrite()
	if err != nil {
		return nil, err
	}

	xor := aesctrat.NewAesCtr(w.ctrKey).XORKeyStreamAt
	iv, err := deriveIV(w.ctrKey, ts)
	if err != nil {
		return nil, err
	}

	return &writer{
		under:  wr,
		xor:    xor,
		iv:     iv,
		ts:     ts,
		parent: w,
	}, nil
}

// Remove deletes the encrypted filename associated with the plaintext name.
func (w *Wrapper) Remove(name string) error {
	encName, _, err := w.lookupEncryptedName(name)
	if err != nil {
		return err
	}

	if err := w.under.Remove(encName); err != nil {
		return err
	}
	w.mu.Lock()
	delete(w.hashes, name)
	w.mu.Unlock()
	return nil
}

// List returns decrypted filenames; entries whose name cannot be decrypted are skipped.
func (w *Wrapper) List() ([]string, error) {
	names, err := w.under.List()
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(names))
	seen := make(map[string]struct{})
	for _, enc := range names {
		plain, _, err := w.decryptName(enc)
		if err != nil {
			continue
		}
		if _, ok := seen[plain]; ok {
			continue
		}
		seen[plain] = struct{}{}
		out = append(out, plain)
	}

	return out, nil
}

func (w *Wrapper) lookupEncryptedName(name string) (string, uint64, error) {
	names, err := w.under.List()
	if err != nil {
		return "", 0, err
	}
	var (
		bestName string
		bestTS   uint64
		found    bool
	)
	for _, enc := range names {
		plain, ts, err := w.decryptName(enc)
		if err != nil || plain != name {
			continue
		}
		if !found || ts > bestTS {
			found = true
			bestTS = ts
			bestName = enc
		}
	}
	if !found {
		return "", 0, fs.ErrNotExist
	}
	return bestName, bestTS, nil
}

// Hash returns the SHA-256 of the plaintext stored at name. The result is
// cached until the file is modified or removed.
func (w *Wrapper) Hash(name string) ([]byte, error) {
	w.mu.RLock()
	if sum, ok := w.hashes[name]; ok {
		out := append([]byte(nil), sum...)
		w.mu.RUnlock()
		return out, nil
	}
	w.mu.RUnlock()

	reader, err := w.OpenRead(name)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	hasher := sha256.New()
	buf := make([]byte, 32*1024)
	var off int64
	for off < reader.Size() {
		n, err := reader.ReadAt(buf, off)
		if n > 0 {
			if _, werr := hasher.Write(buf[:n]); werr != nil {
				return nil, werr
			}
			off += int64(n)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, errors.New("fswrap: short read while hashing")
		}
	}

	sum := hasher.Sum(nil)
	w.mu.Lock()
	w.hashes[name] = append([]byte(nil), sum...)
	w.mu.Unlock()

	return sum, nil
}

// reader decrypts file content during reads.
type reader struct {
	under userstorage.ReadFile
	xor   func(dst, src, iv []byte, offset uint64)
	iv    []byte
}

// ReadAt decrypts into p from the wrapped reader.
func (r *reader) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.under.ReadAt(p, off)
	if n > 0 {
		r.xor(p[:n], p[:n], r.iv, uint64(off))
	}

	return n, err
}

// Size reports the underlying size.
func (r *reader) Size() int64 {
	return r.under.Size()
}

// Close closes the underlying reader.
func (r *reader) Close() error {
	return r.under.Close()
}

// writer encrypts bytes before writing.
type writer struct {
	under  userstorage.WriteFile
	xor    func(dst, src, iv []byte, offset uint64)
	iv     []byte
	offset uint64
	parent *Wrapper
	ts     uint64
}

// Write encrypts p and forwards to the underlying writer.
func (w *writer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	w.xor(buf, buf, w.iv, w.offset)
	n, err := w.under.Write(buf)
	w.offset += uint64(n)
	return n, err
}

// Finalize closes and publishes the encrypted file.
func (w *writer) Finalize(name string) error {
	if name == "" {
		_ = w.under.Abort()
		return errors.New("fswrap: empty name")
	}
	encName, err := w.parent.encryptName(w.ts, name)
	if err != nil {
		_ = w.under.Abort()
		return err
	}

	prevName, _, lookupErr := w.parent.lookupEncryptedName(name)

	if err := w.under.Finalize(encName); err != nil {
		return err
	}

	w.parent.mu.Lock()
	delete(w.parent.hashes, name)
	w.parent.mu.Unlock()

	if lookupErr == nil && prevName != encName {
		if err := w.parent.under.Remove(prevName); err != nil {
			return err
		}
	}

	return nil
}

func (w *writer) Abort() error {
	return w.under.Abort()
}

// encryptName seals a plaintext filename alongside its timestamp deterministically.
func (w *Wrapper) encryptName(ts uint64, name string) (string, error) {
	var tsBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tsBuf[:], ts)
	plain := make([]byte, n+len(name))
	copy(plain, tsBuf[:n])
	copy(plain[n:], name)

	ct, err := w.nameSeal(plain, []byte(nameNonceString))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ct), nil
}

// decryptName opens a wrapped filename into plaintext and timestamp.
func (w *Wrapper) decryptName(enc string) (string, uint64, error) {
	data, err := hex.DecodeString(enc)
	if err != nil {
		return "", 0, err
	}

	pt, err := w.nameOpen(data, []byte(nameNonceString))
	if err != nil {
		return "", 0, err
	}
	ts, n := binary.Uvarint(pt)
	if n <= 0 {
		return "", 0, errors.New("fswrap: invalid timestamp prefix")
	}

	return string(pt[n:]), ts, nil
}

// deriveIV deterministically derives a CTR IV from the per-file timestamp.
func deriveIV(key []byte, ts uint64) ([]byte, error) {
	var tsBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tsBuf[:], ts)

	info := make([]byte, 0, len("fswrap/iv")+n)
	info = append(info, []byte("fswrap/iv")...)
	info = append(info, tsBuf[:n]...)

	deriver := hkdf.New(sha256.New, key, nil, info)
	iv := make([]byte, aesctrat.BlockSize)
	if _, err := io.ReadFull(deriver, iv); err != nil {
		return nil, err
	}

	return iv, nil
}
