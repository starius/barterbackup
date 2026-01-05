package fswrap

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/starius/aesctrat"
	"github.com/starius/barterbackup/internal/bbnode/userstorage"
	"github.com/starius/barterbackup/internal/keys"
	"github.com/starius/barterbackup/internal/usercontent"
	"golang.org/x/crypto/hkdf"
)

const (
	nameNonceString = "fswrap-name"
)

// Wrapper applies deterministic encryption to filenames and file contents for privacy.
type Wrapper struct {
	// under is the wrapped filesystem.
	under userstorage.Filesystem

	// nameSeal seals plaintext filenames.
	nameSeal usercontent.SealFunc

	// nameOpen opens sealed filenames.
	nameOpen usercontent.OpenFunc

	// ctrKey encrypts file bodies.
	ctrKey []byte
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
	}, nil
}

// OpenRead decrypts the filename and returns a reader that decrypts contents on the fly.
func (w *Wrapper) OpenRead(name string) (userstorage.ReadFile, error) {
	encName, err := w.encryptName(name)
	if err != nil {
		return nil, err
	}

	r, err := w.under.OpenRead(encName)
	if err != nil {
		return nil, err
	}

	xor := aesctrat.NewAesCtr(w.ctrKey).XORKeyStreamAt

	iv, err := deriveIV([]byte(name))
	if err != nil {
		_ = r.Close()
		return nil, err
	}

	return &reader{under: r, xor: xor, iv: iv}, nil
}

// OpenWrite encrypts the filename and returns a writer that encrypts contents.
func (w *Wrapper) OpenWrite(name string) (userstorage.WriteFile, error) {
	encName, err := w.encryptName(name)
	if err != nil {
		return nil, err
	}

	wr, err := w.under.OpenWrite(encName)
	if err != nil {
		return nil, err
	}

	xor := aesctrat.NewAesCtr(w.ctrKey).XORKeyStreamAt

	iv, err := deriveIV([]byte(name))
	if err != nil {
		_ = wr.Close()
		return nil, err
	}

	return &writer{under: wr, xor: xor, iv: iv}, nil
}

// Remove deletes the encrypted filename.
func (w *Wrapper) Remove(name string) error {
	encName, err := w.encryptName(name)
	if err != nil {
		return err
	}

	return w.under.Remove(encName)
}

// List returns decrypted filenames; entries whose name cannot be decrypted are skipped.
func (w *Wrapper) List() ([]string, error) {
	names, err := w.under.List()
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(names))
	for _, enc := range names {
		plain, err := w.decryptName(enc)
		if err != nil {
			continue
		}
		out = append(out, plain)
	}

	return out, nil
}

// Rename renames encrypted filenames.
func (w *Wrapper) Rename(oldName, newName string) error {
	encOld, err := w.encryptName(oldName)
	if err != nil {
		return err
	}
	encNew, err := w.encryptName(newName)
	if err != nil {
		return err
	}

	return w.under.Rename(encOld, encNew)
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

func (w *writer) Sync() error {
	return w.under.Sync()
}

// Close closes the underlying writer.
func (w *writer) Close() error {
	return w.under.Close()
}

// encryptName seals a plaintext filename deterministically.
func (w *Wrapper) encryptName(name string) (string, error) {
	ct, err := w.nameSeal([]byte(name), []byte(nameNonceString))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ct), nil
}

// decryptName opens a wrapped filename into plaintext.
func (w *Wrapper) decryptName(enc string) (string, error) {
	data, err := hex.DecodeString(enc)
	if err != nil {
		return "", err
	}

	pt, err := w.nameOpen(data, []byte(nameNonceString))
	if err != nil {
		return "", err
	}

	return string(pt), nil
}

// deriveIV deterministically derives a CTR IV from the filename.
func deriveIV(name []byte) ([]byte, error) {
	deriver := hkdf.New(sha256.New, name, nil, []byte("fswrap/iv"))
	iv := make([]byte, aesctrat.BlockSize)
	if _, err := io.ReadFull(deriver, iv); err != nil {
		return nil, err
	}

	return iv, nil
}
