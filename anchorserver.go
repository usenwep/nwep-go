package nwep

/*
#include <nwep/nwep.h>

extern nwep_anchor_server_settings make_anchor_server_settings(void *ud);
extern void* handle_to_ptr(uintptr_t h);
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

type AnchorServer struct {
	c      *C.nwep_anchor_server
	handle cgo.Handle
}

type anchorServerState struct {
	onProposal func(cp *Checkpoint) error
}

type AnchorServerSettings struct {
	// OnProposal is called when a checkpoint proposal is received.
	// If nil, all valid proposals are signed.
	OnProposal func(cp *Checkpoint) error
}

func NewAnchorServer(keypair *BLSKeypair, anchors *AnchorSet, settings *AnchorServerSettings) (*AnchorServer, error) {
	as := &AnchorServer{}

	if settings != nil && settings.OnProposal != nil {
		state := &anchorServerState{onProposal: settings.OnProposal}
		as.handle = cgo.NewHandle(state)
		csettings := C.make_anchor_server_settings(C.handle_to_ptr(C.uintptr_t(as.handle)))
		rv := C.nwep_anchor_server_new(&as.c, &keypair.c, anchors.c, &csettings)
		if err := errorFromCode(int(rv)); err != nil {
			as.handle.Delete()
			return nil, err
		}
	} else {
		rv := C.nwep_anchor_server_new(&as.c, &keypair.c, anchors.c, nil)
		if err := errorFromCode(int(rv)); err != nil {
			return nil, err
		}
	}

	return as, nil
}

func (as *AnchorServer) Free() {
	if as.c != nil {
		C.nwep_anchor_server_free(as.c)
		as.c = nil
	}
	if as.handle != 0 {
		as.handle.Delete()
		as.handle = 0
	}
}

func (as *AnchorServer) HandleRequest(stream *C.nwep_stream, req *C.nwep_request) error {
	return errorFromCode(int(C.nwep_anchor_server_handle_request(as.c, stream, req)))
}

func (as *AnchorServer) AddCheckpoint(cp *Checkpoint) error {
	ccp := checkpointToC(cp)
	return errorFromCode(int(C.nwep_anchor_server_add_checkpoint(as.c, &ccp)))
}

func (as *AnchorServer) GetLatest() (*Checkpoint, error) {
	var ccp C.nwep_checkpoint
	rv := C.nwep_anchor_server_get_latest(as.c, &ccp)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return checkpointFromC(&ccp), nil
}

func (as *AnchorServer) GetCheckpoint(epoch uint64) (*Checkpoint, error) {
	var ccp C.nwep_checkpoint
	rv := C.nwep_anchor_server_get_checkpoint(as.c, C.uint64_t(epoch), &ccp)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return checkpointFromC(&ccp), nil
}

func (as *AnchorServer) CreateProposal(log *MerkleLog, epoch uint64, timestamp Tstamp) (*Checkpoint, error) {
	var ccp C.nwep_checkpoint
	rv := C.nwep_anchor_server_create_proposal(as.c, log.c, C.uint64_t(epoch), C.nwep_tstamp(timestamp), &ccp)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return checkpointFromC(&ccp), nil
}

func (as *AnchorServer) SignProposal(cp *Checkpoint) error {
	ccp := checkpointToC(cp)
	rv := C.nwep_anchor_server_sign_proposal(as.c, &ccp)
	if err := errorFromCode(int(rv)); err != nil {
		return err
	}
	*cp = *checkpointFromC(&ccp)
	return nil
}

//export goAnchorProposal
func goAnchorProposal(userData unsafe.Pointer, cp *C.nwep_checkpoint) C.int {
	state := cgo.Handle(userData).Value().(*anchorServerState)
	if state.onProposal == nil {
		return 0
	}
	goCP := checkpointFromC(cp)
	if err := state.onProposal(goCP); err != nil {
		return C.int(ErrProtoUnauthorized)
	}
	return 0
}
