package userstorage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/starius/aesctrat"
	"github.com/starius/barterbackup/internal/keys"
	"github.com/starius/barterbackup/internal/usercontent"
	"github.com/starius/barterbackup/storedpb"
	"google.golang.org/protobuf/proto"
)

// Filesystem abstracts persistent storage operations for user data using streams.
type Filesystem interface {
	OpenRead(name string) (ReadFile, error)
	OpenWrite(name string) (WriteFile, error)
	Remove(name string) error
	List() ([]string, error)
	Rename(oldName, newName string) error
}

// ReadFile provides random access to a persisted object.
type ReadFile interface {
	io.ReaderAt
	Size() int64
	Close() error
}

// WriteFile allows streaming writes with explicit fsync.
type WriteFile interface {
	io.Writer
	Sync() error
	Close() error
}

// ErrFileNotFound signals missing files in storage.
var ErrFileNotFound = errors.New("file not found")

// contentSnapshot captures responder content metadata for quick access.
type contentSnapshot struct {
	// id is the current content identifier.
	id []byte

	// length is the byte length of the persisted content blob.
	length int64
}

// Store maintains the encrypted user content metadata and files on disk.
type Store struct {
	// fs is the backing filesystem implementation.
	fs Filesystem

	// files holds the file bodies keyed by name.
	files map[string]usercontent.File

	// contentID is the last persisted content identifier.
	contentID []byte

	// contentSeal seals content IDs.
	contentSeal usercontent.SealFunc

	// contentOpen opens content IDs.
	contentOpen usercontent.OpenFunc

	// metadataSeal seals metadata blobs.
	metadataSeal usercontent.SealFunc

	// metadataOpen opens metadata blobs.
	metadataOpen usercontent.OpenFunc

	// xor is the per-file keystream function.
	xor usercontent.XORKeyStreamAt

	// peers are the last persisted peers.
	peers []*storedpb.Peer

	// contentLen is the byte length of the stored content blob.
	contentLen int64

	// contentRead keeps the current content file open for random access.
	contentRead ReadFile

	// contentName is the filename of the current content blob.
	contentName string
}

// Close releases the current content reader if present.
func (s *Store) Close() error {
	if s.contentRead != nil {
		return s.contentRead.Close()
	}
	return nil
}

type contentCandidate struct {
	// name is the filename on disk.
	name string

	// size is the byte length of the file.
	size int64

	// revision describes the content revision if valid.
	revision *storedpb.ContentRevision

	// content is the parsed user content if valid.
	content usercontent.UserContent

	// cid is the parsed content identifier.
	cid []byte

	// reader holds the open file handle when valid.
	reader ReadFile

	// valid reports whether the file parsed successfully.
	valid bool

	// err captures the parse error for invalid files.
	err error
}

// NewStore loads persisted state from the provided filesystem.
func NewStore(fsys Filesystem, master []byte) (*Store, error) {
	if fsys == nil {
		return nil, errors.New("filesystem is nil")
	}
	if len(master) < 32 {
		return nil, errors.New("master key too short")
	}
	contentKey, err := keys.DeriveKey(master, "usercontent/content-id", 32)
	if err != nil {
		return nil, err
	}
	metaKey, err := keys.DeriveKey(master, "usercontent/metadata", 32)
	if err != nil {
		return nil, err
	}
	fileKey, err := keys.DeriveKey(master, "usercontent/files", 32)
	if err != nil {
		return nil, err
	}
	contentSeal, contentOpen, err := usercontent.NewAEAD(contentKey)
	if err != nil {
		return nil, err
	}
	metadataSeal, metadataOpen, err := usercontent.NewAEAD(metaKey)
	if err != nil {
		return nil, err
	}
	xor := aesctrat.NewAesCtr(fileKey).XORKeyStreamAt

	store := &Store{
		fs:           fsys,
		files:        make(map[string]usercontent.File),
		contentSeal:  contentSeal,
		contentOpen:  contentOpen,
		metadataSeal: metadataSeal,
		metadataOpen: metadataOpen,
		xor:          xor,
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	if err := store.loadPeersMetadata(); err != nil {
		return nil, err
	}

	return store, nil
}

// load hydrates the in-memory store from persisted content if present.
func (s *Store) load() error {
	valid, invalid, err := s.scanContentFiles()
	if err != nil {
		return err
	}

	if len(valid) == 0 {
		if len(invalid) == 0 {
			return nil
		}
		return errors.New("no valid content files found")
	}

	if len(valid) == 1 && len(invalid) == 0 {
		v := valid[0]
		return s.replaceContent(v.reader, v.cid, v.name, v.revision, v.content)
	}

	if len(valid) == 2 && len(invalid) == 0 {
		newest := chooseLatest(valid[0], valid[1])
		var older contentCandidate
		if newest.name == valid[0].name {
			older = valid[1]
		} else {
			older = valid[0]
		}
		if err := older.reader.Close(); err != nil {
			return err
		}
		if err := s.fs.Remove(older.name); err != nil {
			return err
		}
		return s.replaceContent(
			newest.reader, newest.cid, newest.name,
			newest.revision, newest.content,
		)
	}

	for _, v := range valid {
		if err := v.reader.Close(); err != nil {
			return err
		}
	}

	return errors.New("ambiguous content files present; run recovery")
}

// SetFile persists or updates a file.
func (s *Store) SetFile(_ context.Context, name string, data []byte) error {
	if name == "" {
		return errors.New("file name is empty")
	}
	s.files[name] = usercontent.File{
		Body: bytes.NewReader(data),
		Size: int64(len(data)),
	}

	return s.persist()
}

// GetFile retrieves a persisted file by name.
func (s *Store) GetFile(_ context.Context, name string) ([]byte, error) {
	data, ok := s.files[name]
	if !ok {
		return nil, ErrFileNotFound
	}

	buf := make([]byte, data.Size)
	read := int64(0)
	for read < data.Size {
		n, err := data.Body.ReadAt(buf[read:], read)
		read += int64(n)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if err == io.EOF {
			break
		}
	}
	if read != data.Size {
		return nil, errors.New("short read")
	}

	return buf, nil
}

// DeleteFile removes a file from persistent state.
func (s *Store) DeleteFile(_ context.Context, name string) error {
	if _, ok := s.files[name]; !ok {
		return ErrFileNotFound
	}
	delete(s.files, name)

	return s.persist()
}

// ListFiles returns the sorted list of file names.
func (s *Store) ListFiles(_ context.Context) ([]string, error) {
	names := make([]string, 0, len(s.files))
	for name := range s.files {
		names = append(names, name)
	}
	sort.Strings(names)

	return names, nil
}

// CurrentContentID returns the latest persisted content identifier.
func (s *Store) CurrentContentID() []byte {
	return append([]byte(nil), s.contentID...)
}

// ContentLength returns the byte length of the current persisted content blob.
func (s *Store) ContentLength() int64 {
	return s.contentLen
}

const peersMetadataName = "metadata"

// ContentHash returns the SHA-256 of the current content if the filesystem supports hashing.
// If no content is present, ErrFileNotFound is returned.
func (s *Store) ContentHash() ([]byte, error) {
	if s.contentName == "" {
		return nil, ErrFileNotFound
	}
	type hasher interface {
		Hash(name string) ([]byte, error)
	}
	if h, ok := s.fs.(hasher); ok {
		return h.Hash(s.contentName)
	}
	return nil, errors.New("hash not supported")
}

func (s *Store) persistPeersMetadata() error {
	peersCopy := make([]*storedpb.Peer, 0, len(s.peers))
	for _, p := range s.peers {
		cp := *p
		cp.OnionPubkey = append([]byte(nil), p.GetOnionPubkey()...)
		cp.ContentId = append([]byte(nil), p.GetContentId()...)
		peersCopy = append(peersCopy, &cp)
	}
	meta := &storedpb.Metadata{
		Files: nil,
		Peers: peersCopy,
	}
	data, err := proto.Marshal(meta)
	if err != nil {
		return err
	}

	w, err := s.fs.OpenWrite(peersMetadataName)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		if !success {
			_ = s.fs.Remove(peersMetadataName)
		}
	}()

	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Sync(); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	success = true
	return nil
}

func (s *Store) loadPeersMetadata() error {
	reader, err := s.fs.OpenRead(peersMetadataName)
	if err != nil {
		return nil
	}
	defer reader.Close()

	buf := make([]byte, reader.Size())
	n, err := reader.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if int64(n) != reader.Size() {
		return errors.New("short read peers metadata")
	}

	var meta storedpb.Metadata
	if err := proto.Unmarshal(buf, &meta); err != nil {
		return err
	}
	s.peers = meta.GetPeers()
	return nil
}

// SetPeerContentID updates or adds a peer entry and persists metadata.
func (s *Store) SetPeerContentID(pub, cid []byte) error {
	if len(pub) == 0 {
		return errors.New("peer pubkey is empty")
	}
	if len(cid) == 0 {
		return errors.New("peer content id is empty")
	}
	found := false
	for _, p := range s.peers {
		if bytes.Equal(p.GetOnionPubkey(), pub) {
			p.ContentId = append([]byte(nil), cid...)
			found = true
			break
		}
	}
	if !found {
		s.peers = append(s.peers, &storedpb.Peer{
			OnionPubkey: append([]byte(nil), pub...),
			ContentId:   append([]byte(nil), cid...),
		})
	}
	return s.persistPeersMetadata()
}

// RemovePeerContent deletes a peer entry if present and persists metadata.
func (s *Store) RemovePeerContent(pub []byte) error {
	if len(pub) == 0 {
		return errors.New("peer pubkey is empty")
	}
	out := s.peers[:0]
	removed := false
	for _, p := range s.peers {
		if bytes.Equal(p.GetOnionPubkey(), pub) {
			removed = true
			continue
		}
		out = append(out, p)
	}
	if !removed {
		return nil
	}
	s.peers = out
	return s.persistPeersMetadata()
}

// Peers returns a copy of persisted peers.
func (s *Store) Peers() []*storedpb.Peer {
	out := make([]*storedpb.Peer, 0, len(s.peers))
	for _, p := range s.peers {
		cp := *p
		cp.ContentId = append([]byte(nil), p.GetContentId()...)
		cp.OnionPubkey = append([]byte(nil), p.GetOnionPubkey()...)
		out = append(out, &cp)
	}
	return out
}

// OpenContent returns a fresh reader for the current content file along with its ID.
func (s *Store) OpenContent() (ReadFile, []byte, error) {
	if s.contentName == "" {
		return nil, nil, ErrFileNotFound
	}
	reader, err := s.fs.OpenRead(s.contentName)
	if err != nil {
		return nil, nil, err
	}
	return reader, append([]byte(nil), s.contentID...), nil
}

// persist encodes the current state to the backing filesystem.
func (s *Store) persist() error {
	uc := usercontent.UserContent{
		CreatedAt: time.Now(),
		Files:     s.files,
	}
	if len(s.peers) > 0 {
		uc.Peers = append([]*storedpb.Peer(nil), s.peers...)
	}

	tmpName := "tmp"
	writer, err := s.fs.OpenWrite(tmpName)
	if err != nil {
		return err
	}
	closed := false
	success := false
	defer func() {
		if !closed {
			_ = writer.Close()
		}
		if !success {
			_ = s.fs.Remove(tmpName)
		}
	}()

	cw := &countingWriter{w: writer}
	cid, err := usercontent.WriteContentFile(
		cw, uc, s.contentSeal, s.metadataSeal, s.xor,
	)
	if err != nil {
		if cerr := writer.Close(); cerr != nil {
			return fmt.Errorf("write failed: %v (close error: %w)", err, cerr)
		}
		return err
	}

	if err := writer.Sync(); err != nil {
		if cerr := writer.Close(); cerr != nil {
			return fmt.Errorf("sync failed: %v (close error: %w)", err, cerr)
		}
		return err
	}
	s.contentLen = cw.n
	if err := writer.Close(); err != nil {
		return err
	}
	closed = true

	newName := contentFileNameFor(cid)
	if err := s.fs.Rename(tmpName, newName); err != nil {
		return err
	}

	reader, err := s.fs.OpenRead(newName)
	if err != nil {
		return err
	}
	if err := s.replaceContent(reader, cid, newName, nil, uc); err != nil {
		return err
	}

	if s.contentName != "" && s.contentName != newName {
		if err := s.fs.Remove(s.contentName); err != nil {
			return err
		}
	}
	s.contentName = newName
	success = true

	return nil
}

// snapshot captures the current content ID and length.
func (s *Store) snapshot() contentSnapshot {
	return contentSnapshot{
		id:     append([]byte(nil), s.contentID...),
		length: s.contentLen,
	}
}

// countingWriter wraps an io.Writer to track bytes written.
type countingWriter struct {
	w io.Writer
	n int64
}

// Write proxies to the underlying writer and accumulates the byte count.
func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n += int64(n)

	return n, err
}

// replaceContent swaps in a new content reader and rebuilds in-memory state.
func (s *Store) replaceContent(reader ReadFile, cid []byte, name string,
	revision *storedpb.ContentRevision, uc usercontent.UserContent) error {

	if revision == nil {
		rev, err := usercontent.ParseContentID(cid, s.contentOpen)
		if err != nil {
			_ = reader.Close()
			return err
		}
		revision = rev
	}
	if s.contentRead != nil {
		if err := s.contentRead.Close(); err != nil {
			return err
		}
	}
	s.contentRead = reader
	s.contentLen = reader.Size()
	s.files = uc.Files
	s.contentID = append([]byte(nil), cid...)
	s.peers = append([]*storedpb.Peer(nil), uc.Peers...)
	s.contentName = name

	return nil
}

func contentFileNameFor(cid []byte) string {
	// Filenames are the raw content ID bytes so our content is indistinguishable
	// from peers' files once the filesystem wrapper encrypts names.
	return string(cid)
}

func chooseLatest(a, b contentCandidate) contentCandidate {
	if a.revision.GetCreatedAt() > b.revision.GetCreatedAt() {
		return a
	}
	if a.revision.GetCreatedAt() < b.revision.GetCreatedAt() {
		return b
	}
	if a.revision.GetCreatedAtNs() > b.revision.GetCreatedAtNs() {
		return a
	}
	if a.revision.GetCreatedAtNs() < b.revision.GetCreatedAtNs() {
		return b
	}
	if a.name > b.name {
		return a
	}
	return b
}

// scanContentFiles enumerates persisted content files and categorizes them.
func (s *Store) scanContentFiles() ([]contentCandidate, []contentCandidate, error) {
	names, err := s.fs.List()
	if err != nil {
		return nil, nil, err
	}

	valid := make([]contentCandidate, 0)
	invalid := make([]contentCandidate, 0)
	for _, name := range names {
		if name == peersMetadataName {
			continue
		}

		// Skip files whose names are not decryptable as our content IDs (likely peers' blobs).
		if _, err := usercontent.ParseContentID([]byte(name), s.contentOpen); err != nil {
			continue
		}
		reader, err := s.fs.OpenRead(name)
		if err != nil {
			continue
		}

		uc, cid, perr := usercontent.ParseContentFile(
			reader, s.contentOpen, s.metadataOpen, s.xor,
		)
		if perr != nil {
			if cerr := reader.Close(); cerr != nil {
				return nil, nil, cerr
			}
			invalid = append(invalid, contentCandidate{
				name:  name,
				size:  reader.Size(),
				err:   perr,
				valid: false,
			})
			continue
		}
		expectedName := contentFileNameFor(cid)
		if expectedName != name {
			if cerr := reader.Close(); cerr != nil {
				return nil, nil, cerr
			}
			invalid = append(invalid, contentCandidate{
				name:  name,
				size:  reader.Size(),
				err:   fmt.Errorf("content id mismatch; expected %s", expectedName),
				valid: false,
			})
			continue
		}

		revision, _ := usercontent.ParseContentID(cid, s.contentOpen)
		if !bytes.Equal(cid, []byte(name)) {
			if cerr := reader.Close(); cerr != nil {
				return nil, nil, cerr
			}
			invalid = append(invalid, contentCandidate{
				name:  name,
				size:  reader.Size(),
				err:   fmt.Errorf("content id mismatch; expected %s", expectedName),
				valid: false,
			})
			continue
		}
		valid = append(valid, contentCandidate{
			name:     name,
			size:     reader.Size(),
			revision: revision,
			content:  uc,
			cid:      cid,
			reader:   reader,
			valid:    true,
		})
	}

	return valid, invalid, nil
}

// RecoveryInfo summarizes on-disk content files and recommends an action if clear.
func (s *Store) RecoveryInfo() (string, error) {
	valid, invalid, err := s.scanContentFiles()
	if err != nil {
		return "", err
	}

	var b strings.Builder
	if len(valid)+len(invalid) == 0 {
		b.WriteString("No content files found.\n")
		return b.String(), nil
	}

	b.WriteString("Content files:\n")
	for _, v := range valid {
		ts := time.Unix(
			v.revision.GetCreatedAt(),
			v.revision.GetCreatedAtNs(),
		).UTC()
		fmt.Fprintf(&b, "- %s: size=%d valid created_at=%s\n",
			v.name, v.size, ts.Format(time.RFC3339Nano))
		if err := v.reader.Close(); err != nil {
			return "", err
		}
	}
	for _, iv := range invalid {
		fmt.Fprintf(&b, "- %s: size=%d invalid: %v\n",
			iv.name, iv.size, iv.err)
	}

	if len(valid) == 2 && len(invalid) == 0 {
		newest := chooseLatest(valid[0], valid[1])
		var older contentCandidate
		if newest.name == valid[0].name {
			older = valid[1]
		} else {
			older = valid[0]
		}
		fmt.Fprintf(&b, "Recommendation: keep %s, remove %s.\n",
			newest.name, older.name)
	} else {
		b.WriteString("Recommendation: manual intervention required.\n")
	}

	return b.String(), nil
}
