package bbnode

import (
	"context"
	"errors"

	"github.com/starius/barterbackup/internal/bbnode/userstorage"
)

// ErrStopped indicates the node storage/event loop has been stopped.
var ErrStopped = errors.New("storage stopped")

// nodeState mediates access to mutable node data via the Node event loop.
type nodeState interface {
	SetFile(ctx context.Context, name string, data []byte) error
	DeleteFile(ctx context.Context, name string) error
	GetFile(ctx context.Context, name string) ([]byte, error)
	ListFiles(ctx context.Context) ([]string, error)
	Close()
}

type eventState struct {
	store *userstorage.Store

	setCh    chan setReq
	deleteCh chan deleteReq
	getCh    chan getReq
	listCh   chan listReq

	stopCh chan struct{}
	doneCh chan struct{}
}

type setReq struct {
	ctx  context.Context
	name string
	data []byte
	resp chan error
}

type deleteReq struct {
	ctx  context.Context
	name string
	resp chan error
}

type getReq struct {
	ctx  context.Context
	name string
	resp chan getResp
}

type getResp struct {
	data []byte
	err  error
}

type listReq struct {
	ctx  context.Context
	resp chan listResp
}

type listResp struct {
	names []string
	err   error
}

func newEventState(store *userstorage.Store) *eventState {
	es := &eventState{
		store:    store,
		setCh:    make(chan setReq),
		deleteCh: make(chan deleteReq),
		getCh:    make(chan getReq),
		listCh:   make(chan listReq),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
	go es.loop()
	return es
}

func (es *eventState) loop() {
	defer close(es.doneCh)
	for {
		select {
		case <-es.stopCh:
			return
		case req := <-es.setCh:
			err := es.store.SetFile(req.ctx, req.name, req.data)
			es.respondError(req.ctx, req.resp, err)
		case req := <-es.deleteCh:
			err := es.store.DeleteFile(req.ctx, req.name)
			es.respondError(req.ctx, req.resp, err)
		case req := <-es.getCh:
			data, err := es.store.GetFile(req.ctx, req.name)
			es.respondGet(req, data, err)
		case req := <-es.listCh:
			names, err := es.store.ListFiles(req.ctx)
			es.respondList(req, names, err)
		}
	}
}

func (es *eventState) respondError(ctx context.Context, resp chan error, err error) {
	select {
	case <-ctx.Done():
	case <-es.stopCh:
	case resp <- err:
	}
}

func (es *eventState) respondGet(req getReq, data []byte, err error) {
	resp := getResp{data: data, err: err}
	select {
	case <-req.ctx.Done():
	case <-es.stopCh:
	case req.resp <- resp:
	}
}

func (es *eventState) respondList(req listReq, names []string, err error) {
	resp := listResp{names: names, err: err}
	select {
	case <-req.ctx.Done():
	case <-es.stopCh:
	case req.resp <- resp:
	}
}

func (es *eventState) SetFile(ctx context.Context, name string, data []byte) error {
	resp := make(chan error, 1)
	req := setReq{ctx: ctx, name: name, data: data, resp: resp}
	if err := es.sendSet(ctx, req); err != nil {
		return err
	}
	return es.waitError(ctx, resp)
}

func (es *eventState) sendSet(ctx context.Context, req setReq) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-es.doneCh:
		return ErrStopped
	case es.setCh <- req:
		return nil
	}
}

func (es *eventState) DeleteFile(ctx context.Context, name string) error {
	resp := make(chan error, 1)
	req := deleteReq{ctx: ctx, name: name, resp: resp}
	if err := es.sendDelete(ctx, req); err != nil {
		return err
	}
	return es.waitError(ctx, resp)
}

func (es *eventState) sendDelete(ctx context.Context, req deleteReq) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-es.doneCh:
		return ErrStopped
	case es.deleteCh <- req:
		return nil
	}
}

func (es *eventState) GetFile(ctx context.Context, name string) ([]byte, error) {
	resp := make(chan getResp, 1)
	req := getReq{ctx: ctx, name: name, resp: resp}
	if err := es.sendGet(ctx, req); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-es.doneCh:
		return nil, ErrStopped
	case r := <-resp:
		if r.err != nil {
			return nil, r.err
		}
		return r.data, nil
	}
}

func (es *eventState) sendGet(ctx context.Context, req getReq) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-es.doneCh:
		return ErrStopped
	case es.getCh <- req:
		return nil
	}
}

func (es *eventState) ListFiles(ctx context.Context) ([]string, error) {
	resp := make(chan listResp, 1)
	req := listReq{ctx: ctx, resp: resp}
	if err := es.sendList(ctx, req); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-es.doneCh:
		return nil, ErrStopped
	case r := <-resp:
		return r.names, r.err
	}
}

func (es *eventState) sendList(ctx context.Context, req listReq) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-es.doneCh:
		return ErrStopped
	case es.listCh <- req:
		return nil
	}
}

func (es *eventState) waitError(ctx context.Context, resp chan error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-es.doneCh:
		return ErrStopped
	case err := <-resp:
		return err
	}
}

func (es *eventState) Close() {
	select {
	case <-es.doneCh:
		return
	default:
		close(es.stopCh)
		<-es.doneCh
	}
}
