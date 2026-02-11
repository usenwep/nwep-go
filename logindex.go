package nwep

/*
#include <nwep/nwep.h>
#include <string.h>

extern int goIndexGet(void *user_data, nwep_nodeid *nodeid, nwep_log_index_entry *entry);
extern int goIndexPut(void *user_data, nwep_log_index_entry *entry);

nwep_log_index_storage make_index_storage(void *ud);
extern void* handle_to_ptr(uintptr_t h);
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

type LogIndexEntry struct {
	NodeID   NodeID
	Pubkey   [32]byte
	LogIndex uint64
	Revoked  bool
}

type LogIndexStorage interface {
	Get(nodeid NodeID) (*LogIndexEntry, error)
	Put(entry *LogIndexEntry) error
}

type LogIndex struct {
	c       *C.nwep_log_index
	handle  cgo.Handle
	storage LogIndexStorage
}

func NewLogIndex(storage LogIndexStorage) (*LogIndex, error) {
	li := &LogIndex{storage: storage}
	li.handle = cgo.NewHandle(li)

	cs := C.make_index_storage(C.handle_to_ptr(C.uintptr_t(li.handle)))

	rv := C.nwep_log_index_new(&li.c, &cs)
	if err := errorFromCode(int(rv)); err != nil {
		li.handle.Delete()
		return nil, err
	}
	return li, nil
}

func (li *LogIndex) Free() {
	if li.c != nil {
		C.nwep_log_index_free(li.c)
		li.c = nil
	}
	li.handle.Delete()
}

func (li *LogIndex) Lookup(nodeid NodeID) (*LogIndexEntry, error) {
	cnid := nodeid.toCNodeID()
	var ce C.nwep_log_index_entry
	rv := C.nwep_log_index_lookup(li.c, &cnid, &ce)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return logIndexEntryFromC(&ce), nil
}

func (li *LogIndex) Update(entry *MerkleEntry, logIdx uint64) error {
	ce := merkleEntryToC(entry)
	return errorFromCode(int(C.nwep_log_index_update(li.c, &ce, C.uint64_t(logIdx))))
}

//export goIndexGet
func goIndexGet(userData unsafe.Pointer, nodeid *C.nwep_nodeid, entry *C.nwep_log_index_entry) C.int {
	li := cgo.Handle(userData).Value().(*LogIndex)
	nid := nodeIDFromC(nodeid)
	result, err := li.storage.Get(nid)
	if err != nil {
		return C.int(ErrStorageKeyNotFound)
	}
	C.memcpy(unsafe.Pointer(&entry.nodeid.data[0]), unsafe.Pointer(&result.NodeID[0]), 32)
	C.memcpy(unsafe.Pointer(&entry.pubkey[0]), unsafe.Pointer(&result.Pubkey[0]), 32)
	entry.log_index = C.uint64_t(result.LogIndex)
	if result.Revoked {
		entry.revoked = 1
	} else {
		entry.revoked = 0
	}
	return 0
}

//export goIndexPut
func goIndexPut(userData unsafe.Pointer, entry *C.nwep_log_index_entry) C.int {
	li := cgo.Handle(userData).Value().(*LogIndex)
	e := logIndexEntryFromC(entry)
	if err := li.storage.Put(e); err != nil {
		return -1
	}
	return 0
}

func logIndexEntryFromC(ce *C.nwep_log_index_entry) *LogIndexEntry {
	e := &LogIndexEntry{
		LogIndex: uint64(ce.log_index),
		Revoked:  ce.revoked != 0,
	}
	C.memcpy(unsafe.Pointer(&e.NodeID[0]), unsafe.Pointer(&ce.nodeid.data[0]), 32)
	C.memcpy(unsafe.Pointer(&e.Pubkey[0]), unsafe.Pointer(&ce.pubkey[0]), 32)
	return e
}
