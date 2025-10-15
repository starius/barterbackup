package userstorage

import (
	"context"
	"errors"
	"sync"
)

// Exposed errors to translate into gRPC status codes.
var (
	ErrFileNotFound = errors.New("file not found")
	ErrStopped      = errors.New("storage stopped")
)

// Storage manages encrypted local storage via an event-driven goroutine.
type Storage struct {
	setCh    chan setRequest
	getCh    chan getRequest
	deleteCh chan deleteRequest
	listCh   chan listRequest
	doneCh   chan struct{}

	startOnce sync.Once

	state *localStore
}

func New(storageDir string, master []byte) (*Storage, error) {
	state, err := newLocalStore(storageDir, master)
	if err != nil {
		return nil, err
	}
	return &Storage{
		setCh:    make(chan setRequest),
		getCh:    make(chan getRequest),
		deleteCh: make(chan deleteRequest),
		listCh:   make(chan listRequest),
		doneCh:   make(chan struct{}),
		state:    state,
	}, nil
}

func (l *Storage) Start(ctx context.Context) {
	l.startOnce.Do(func() {
		go l.run(ctx)
	})
}

func (l *Storage) WaitForShutdown() {
	<-l.doneCh
}

func (l *Storage) run(ctx context.Context) {
	defer close(l.doneCh)
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-l.setCh:
			l.handleSet(req)
		case req := <-l.getCh:
			l.handleGet(req)
		case req := <-l.deleteCh:
			l.handleDelete(req)
		case req := <-l.listCh:
			l.handleList(req)
		}
	}
}

type setRequest struct {
	name   string
	data   []byte
	resp   chan<- setResponse
	cancel <-chan struct{}
}

type setResponse struct {
	err error
}

type getRequest struct {
	name   string
	resp   chan<- getResponse
	cancel <-chan struct{}
}

type getResponse struct {
	data []byte
	err  error
}

type deleteRequest struct {
	name   string
	resp   chan<- deleteResponse
	cancel <-chan struct{}
}

type deleteResponse struct {
	err error
}

type listRequest struct {
	resp   chan<- listResponse
	cancel <-chan struct{}
}

type listResponse struct {
	names []string
	err   error
}

func (s *Storage) handleSet(req setRequest) {
	err := s.state.setFile(req.name, req.data)
	s.respondSet(req, setResponse{err: err})
}

func (s *Storage) handleGet(req getRequest) {
	data, err := s.state.getFile(req.name)
	s.respondGet(req, getResponse{data: data, err: err})
}

func (s *Storage) handleDelete(req deleteRequest) {
	err := s.state.deleteFile(req.name)
	s.respondDelete(req, deleteResponse{err: err})
}

func (s *Storage) handleList(req listRequest) {
	names := s.state.listFiles()
	s.respondList(req, listResponse{names: names})
}

func (s *Storage) respondSet(req setRequest, resp setResponse) {
	if req.resp == nil {
		return
	}
	select {
	case <-req.cancel:
		return
	case <-s.doneCh:
		return
	case req.resp <- resp:
	}
}

func (s *Storage) respondGet(req getRequest, resp getResponse) {
	if req.resp == nil {
		return
	}
	select {
	case <-req.cancel:
		return
	case <-s.doneCh:
		return
	case req.resp <- resp:
	}
}

func (s *Storage) respondDelete(req deleteRequest, resp deleteResponse) {
	if req.resp == nil {
		return
	}
	select {
	case <-req.cancel:
		return
	case <-s.doneCh:
		return
	case req.resp <- resp:
	}
}

func (s *Storage) respondList(req listRequest, resp listResponse) {
	if req.resp == nil {
		return
	}
	select {
	case <-req.cancel:
		return
	case <-s.doneCh:
		return
	case req.resp <- resp:
	}
}

func (s *Storage) enqueueSet(ctx context.Context, req setRequest) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.doneCh:
		return ErrStopped
	case s.setCh <- req:
		return nil
	}
}

func (s *Storage) enqueueGet(ctx context.Context, req getRequest) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.doneCh:
		return ErrStopped
	case s.getCh <- req:
		return nil
	}
}

func (s *Storage) enqueueDelete(ctx context.Context, req deleteRequest) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.doneCh:
		return ErrStopped
	case s.deleteCh <- req:
		return nil
	}
}

func (s *Storage) enqueueList(ctx context.Context, req listRequest) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.doneCh:
		return ErrStopped
	case s.listCh <- req:
		return nil
	}
}

func (s *Storage) awaitSet(ctx context.Context, respCh <-chan setResponse) (setResponse, error) {
	var zero setResponse
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case <-s.doneCh:
		return zero, ErrStopped
	case resp := <-respCh:
		return resp, nil
	}
}

func (s *Storage) awaitGet(ctx context.Context, respCh <-chan getResponse) (getResponse, error) {
	var zero getResponse
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case <-s.doneCh:
		return zero, ErrStopped
	case resp := <-respCh:
		return resp, nil
	}
}

func (s *Storage) awaitDelete(ctx context.Context, respCh <-chan deleteResponse) (deleteResponse, error) {
	var zero deleteResponse
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case <-s.doneCh:
		return zero, ErrStopped
	case resp := <-respCh:
		return resp, nil
	}
}

func (s *Storage) awaitList(ctx context.Context, respCh <-chan listResponse) (listResponse, error) {
	var zero listResponse
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case <-s.doneCh:
		return zero, ErrStopped
	case resp := <-respCh:
		return resp, nil
	}
}

// SetFile stores or updates an encrypted file.
func (s *Storage) SetFile(ctx context.Context, name string, data []byte) error {
	respCh := make(chan setResponse)
	req := setRequest{
		name:   name,
		data:   append([]byte(nil), data...),
		resp:   respCh,
		cancel: ctx.Done(),
	}
	if err := s.enqueueSet(ctx, req); err != nil {
		return err
	}
	resp, err := s.awaitSet(ctx, respCh)
	if err != nil {
		return err
	}
	return resp.err
}

// GetFile returns the decrypted file bytes for a given name.
func (s *Storage) GetFile(ctx context.Context, name string) ([]byte, error) {
	respCh := make(chan getResponse)
	req := getRequest{
		name:   name,
		resp:   respCh,
		cancel: ctx.Done(),
	}
	if err := s.enqueueGet(ctx, req); err != nil {
		return nil, err
	}
	resp, err := s.awaitGet(ctx, respCh)
	if err != nil {
		return nil, err
	}
	return resp.data, resp.err
}

// DeleteFile removes a file from the current content set.
func (s *Storage) DeleteFile(ctx context.Context, name string) error {
	respCh := make(chan deleteResponse)
	req := deleteRequest{
		name:   name,
		resp:   respCh,
		cancel: ctx.Done(),
	}
	if err := s.enqueueDelete(ctx, req); err != nil {
		return err
	}
	resp, err := s.awaitDelete(ctx, respCh)
	if err != nil {
		return err
	}
	return resp.err
}

// ListFiles returns the list of file names stored in the current content blob.
func (s *Storage) ListFiles(ctx context.Context) ([]string, error) {
	respCh := make(chan listResponse)
	req := listRequest{
		resp:   respCh,
		cancel: ctx.Done(),
	}
	if err := s.enqueueList(ctx, req); err != nil {
		return nil, err
	}
	resp, err := s.awaitList(ctx, respCh)
	if err != nil {
		return nil, err
	}
	return resp.names, resp.err
}
