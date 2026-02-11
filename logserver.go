package nwep

/*
#include <nwep/nwep.h>

extern nwep_log_server_settings make_log_server_settings(void *ud);
extern void* handle_to_ptr(uintptr_t h);
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

type LogServer struct {
	c      *C.nwep_log_server
	handle cgo.Handle
}

type logServerState struct {
	authorize func(nodeid NodeID, entry *MerkleEntry) error
}

type LogServerSettings struct {
	// Authorize is called before accepting write requests.
	// If nil, only read operations are allowed.
	Authorize func(nodeid NodeID, entry *MerkleEntry) error
}

func NewLogServer(log *MerkleLog, settings *LogServerSettings) (*LogServer, error) {
	ls := &LogServer{}

	if settings != nil && settings.Authorize != nil {
		state := &logServerState{authorize: settings.Authorize}
		ls.handle = cgo.NewHandle(state)
		csettings := C.make_log_server_settings(C.handle_to_ptr(C.uintptr_t(ls.handle)))
		rv := C.nwep_log_server_new(&ls.c, log.c, &csettings)
		if err := errorFromCode(int(rv)); err != nil {
			ls.handle.Delete()
			return nil, err
		}
	} else {
		rv := C.nwep_log_server_new(&ls.c, log.c, nil)
		if err := errorFromCode(int(rv)); err != nil {
			return nil, err
		}
	}

	return ls, nil
}

func (ls *LogServer) Free() {
	if ls.c != nil {
		C.nwep_log_server_free(ls.c)
		ls.c = nil
	}
	if ls.handle != 0 {
		ls.handle.Delete()
		ls.handle = 0
	}
}

func (ls *LogServer) HandleRequest(stream *C.nwep_stream, req *C.nwep_request) error {
	return errorFromCode(int(C.nwep_log_server_handle_request(ls.c, stream, req)))
}

func (ls *LogServer) GetLog() *C.nwep_merkle_log {
	return C.nwep_log_server_get_log(ls.c)
}

//export goLogAuthorize
func goLogAuthorize(userData unsafe.Pointer, nodeid *C.nwep_nodeid, entry *C.nwep_merkle_entry) C.int {
	state := cgo.Handle(userData).Value().(*logServerState)
	if state.authorize == nil {
		return 0
	}
	nid := nodeIDFromC(nodeid)
	goEntry := merkleEntryFromC(entry)
	if err := state.authorize(nid, goEntry); err != nil {
		return C.int(ErrProtoUnauthorized)
	}
	return 0
}
