package nwep

/*
#include <nwep/nwep.h>
#include <string.h>

extern int goLogAppend(void *user_data, uint64_t index, uint8_t *entry, size_t entry_len);
extern ptrdiff_t goLogGet(void *user_data, uint64_t index, uint8_t *buf, size_t buflen);
extern uint64_t goLogSize(void *user_data);

nwep_log_storage make_log_storage(void *ud);
extern void* handle_to_ptr(uintptr_t h);
*/
import "C"

import (
	"runtime/cgo"
	"sync"
	"unsafe"
)

const (
	LogEntryMaxSize     = C.NWEP_LOG_ENTRY_MAX_SIZE
	MerkleProofMaxDepth = C.NWEP_MERKLE_PROOF_MAX_DEPTH
	MerkleProofMaxSize  = 8 + 8 + 32 + 4 + MerkleProofMaxDepth*32
)

type MerkleEntryType int

const (
	LogEntryKeyBinding   MerkleEntryType = C.NWEP_LOG_ENTRY_KEY_BINDING
	LogEntryKeyRotation  MerkleEntryType = C.NWEP_LOG_ENTRY_KEY_ROTATION
	LogEntryRevocation   MerkleEntryType = C.NWEP_LOG_ENTRY_REVOCATION
	LogEntryAnchorChange MerkleEntryType = C.NWEP_LOG_ENTRY_ANCHOR_CHANGE
)

type MerkleEntry struct {
	Type           MerkleEntryType
	Timestamp      Tstamp
	NodeID         NodeID
	Pubkey         [32]byte
	PrevPubkey     [32]byte
	RecoveryPubkey [32]byte
	Signature      [64]byte
}

type MerkleHash [32]byte

type MerkleProof struct {
	Index    uint64
	LogSize  uint64
	LeafHash MerkleHash
	Siblings []MerkleHash
}

func MerkleEntryEncode(entry *MerkleEntry) ([]byte, error) {
	ce := merkleEntryToC(entry)
	var buf [LogEntryMaxSize]byte
	n := C.nwep_merkle_entry_encode((*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.size_t(LogEntryMaxSize), &ce)
	if n < 0 {
		return nil, errorFromCode(int(n))
	}
	return append([]byte(nil), buf[:n]...), nil
}

func MerkleEntryDecode(data []byte) (*MerkleEntry, error) {
	var ce C.nwep_merkle_entry
	rv := C.nwep_merkle_entry_decode(&ce, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return merkleEntryFromC(&ce), nil
}

func MerkleLeafHash(entry *MerkleEntry) (MerkleHash, error) {
	ce := merkleEntryToC(entry)
	var ch C.nwep_merkle_hash
	rv := C.nwep_merkle_leaf_hash(&ch, &ce)
	if err := errorFromCode(int(rv)); err != nil {
		return MerkleHash{}, err
	}
	return merkleHashFromC(&ch), nil
}

func MerkleNodeHash(left, right MerkleHash) (MerkleHash, error) {
	cl := merkleHashToC(left)
	cr := merkleHashToC(right)
	var out C.nwep_merkle_hash
	rv := C.nwep_merkle_node_hash(&out, &cl, &cr)
	if err := errorFromCode(int(rv)); err != nil {
		return MerkleHash{}, err
	}
	return merkleHashFromC(&out), nil
}

func MerkleProofVerify(proof *MerkleProof, root MerkleHash) error {
	cp := merkleProofToC(proof)
	cr := merkleHashToC(root)
	return errorFromCode(int(C.nwep_merkle_proof_verify(&cp, &cr)))
}

func MerkleProofEncode(proof *MerkleProof) ([]byte, error) {
	cp := merkleProofToC(proof)
	buf := make([]byte, MerkleProofMaxSize)
	n := C.nwep_merkle_proof_encode((*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.size_t(len(buf)), &cp)
	if n < 0 {
		return nil, errorFromCode(int(n))
	}
	return buf[:n], nil
}

func MerkleProofDecode(data []byte) (*MerkleProof, error) {
	var cp C.nwep_merkle_proof
	rv := C.nwep_merkle_proof_decode(&cp, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return merkleProofFromC(&cp), nil
}

// LogStorage is the interface for persistent Merkle log storage.
// Implementations must be safe for use from a single goroutine.
type LogStorage interface {
	Append(index uint64, entry []byte) error
	Get(index uint64, buf []byte) (int, error)
	Size() uint64
}

// MerkleLog wraps the C Merkle log with Go-managed storage.
type MerkleLog struct {
	c       *C.nwep_merkle_log
	handle  cgo.Handle
	storage LogStorage
}

var merkleLogMu sync.Mutex

func NewMerkleLog(storage LogStorage) (*MerkleLog, error) {
	ml := &MerkleLog{storage: storage}
	ml.handle = cgo.NewHandle(ml)

	cs := C.make_log_storage(C.handle_to_ptr(C.uintptr_t(ml.handle)))

	merkleLogMu.Lock()
	defer merkleLogMu.Unlock()

	rv := C.nwep_merkle_log_new(&ml.c, &cs)
	if err := errorFromCode(int(rv)); err != nil {
		ml.handle.Delete()
		return nil, err
	}
	return ml, nil
}

func (ml *MerkleLog) Free() {
	if ml.c != nil {
		C.nwep_merkle_log_free(ml.c)
		ml.c = nil
	}
	ml.handle.Delete()
}

func (ml *MerkleLog) Append(entry *MerkleEntry) (uint64, error) {
	ce := merkleEntryToC(entry)
	var idx C.uint64_t
	rv := C.nwep_merkle_log_append(ml.c, &ce, &idx)
	if err := errorFromCode(int(rv)); err != nil {
		return 0, err
	}
	return uint64(idx), nil
}

func (ml *MerkleLog) Get(index uint64) (*MerkleEntry, error) {
	var ce C.nwep_merkle_entry
	rv := C.nwep_merkle_log_get(ml.c, C.uint64_t(index), &ce)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return merkleEntryFromC(&ce), nil
}

func (ml *MerkleLog) Size() uint64 {
	return uint64(C.nwep_merkle_log_size(ml.c))
}

func (ml *MerkleLog) Root() (MerkleHash, error) {
	var ch C.nwep_merkle_hash
	rv := C.nwep_merkle_log_root(ml.c, &ch)
	if err := errorFromCode(int(rv)); err != nil {
		return MerkleHash{}, err
	}
	return merkleHashFromC(&ch), nil
}

func (ml *MerkleLog) Prove(index uint64) (*MerkleProof, error) {
	var cp C.nwep_merkle_proof
	rv := C.nwep_merkle_log_prove(ml.c, C.uint64_t(index), &cp)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return merkleProofFromC(&cp), nil
}

// C callback exports for log storage.

//export goLogAppend
func goLogAppend(userData unsafe.Pointer, index C.uint64_t, entry *C.uint8_t, entryLen C.size_t) C.int {
	ml := cgo.Handle(userData).Value().(*MerkleLog)
	data := C.GoBytes(unsafe.Pointer(entry), C.int(entryLen))
	if err := ml.storage.Append(uint64(index), data); err != nil {
		return -1
	}
	return 0
}

//export goLogGet
func goLogGet(userData unsafe.Pointer, index C.uint64_t, buf *C.uint8_t, bufLen C.size_t) C.ptrdiff_t {
	ml := cgo.Handle(userData).Value().(*MerkleLog)
	gobuf := make([]byte, bufLen)
	n, err := ml.storage.Get(uint64(index), gobuf)
	if err != nil || n < 0 {
		return -1
	}
	C.memcpy(unsafe.Pointer(buf), unsafe.Pointer(&gobuf[0]), C.size_t(n))
	return C.ptrdiff_t(n)
}

//export goLogSize
func goLogSize(userData unsafe.Pointer) C.uint64_t {
	ml := cgo.Handle(userData).Value().(*MerkleLog)
	return C.uint64_t(ml.storage.Size())
}

// Conversion helpers.

func merkleEntryToC(e *MerkleEntry) C.nwep_merkle_entry {
	var ce C.nwep_merkle_entry
	ce._type = C.nwep_merkle_entry_type(e.Type)
	ce.timestamp = C.nwep_tstamp(e.Timestamp)
	C.memcpy(unsafe.Pointer(&ce.nodeid.data[0]), unsafe.Pointer(&e.NodeID[0]), 32)
	C.memcpy(unsafe.Pointer(&ce.pubkey[0]), unsafe.Pointer(&e.Pubkey[0]), 32)
	C.memcpy(unsafe.Pointer(&ce.prev_pubkey[0]), unsafe.Pointer(&e.PrevPubkey[0]), 32)
	C.memcpy(unsafe.Pointer(&ce.recovery_pubkey[0]), unsafe.Pointer(&e.RecoveryPubkey[0]), 32)
	C.memcpy(unsafe.Pointer(&ce.signature[0]), unsafe.Pointer(&e.Signature[0]), 64)
	return ce
}

func merkleEntryFromC(ce *C.nwep_merkle_entry) *MerkleEntry {
	e := &MerkleEntry{
		Type:      MerkleEntryType(ce._type),
		Timestamp: Tstamp(ce.timestamp),
	}
	C.memcpy(unsafe.Pointer(&e.NodeID[0]), unsafe.Pointer(&ce.nodeid.data[0]), 32)
	C.memcpy(unsafe.Pointer(&e.Pubkey[0]), unsafe.Pointer(&ce.pubkey[0]), 32)
	C.memcpy(unsafe.Pointer(&e.PrevPubkey[0]), unsafe.Pointer(&ce.prev_pubkey[0]), 32)
	C.memcpy(unsafe.Pointer(&e.RecoveryPubkey[0]), unsafe.Pointer(&ce.recovery_pubkey[0]), 32)
	C.memcpy(unsafe.Pointer(&e.Signature[0]), unsafe.Pointer(&ce.signature[0]), 64)
	return e
}

func merkleHashToC(h MerkleHash) C.nwep_merkle_hash {
	var ch C.nwep_merkle_hash
	C.memcpy(unsafe.Pointer(&ch.data[0]), unsafe.Pointer(&h[0]), 32)
	return ch
}

func merkleHashFromC(ch *C.nwep_merkle_hash) MerkleHash {
	var h MerkleHash
	C.memcpy(unsafe.Pointer(&h[0]), unsafe.Pointer(&ch.data[0]), 32)
	return h
}

func merkleProofToC(p *MerkleProof) C.nwep_merkle_proof {
	var cp C.nwep_merkle_proof
	cp.index = C.uint64_t(p.Index)
	cp.log_size = C.uint64_t(p.LogSize)
	cp.leaf_hash = merkleHashToC(p.LeafHash)
	cp.depth = C.size_t(len(p.Siblings))
	for i, s := range p.Siblings {
		cp.siblings[i] = merkleHashToC(s)
	}
	return cp
}

func merkleProofFromC(cp *C.nwep_merkle_proof) *MerkleProof {
	p := &MerkleProof{
		Index:    uint64(cp.index),
		LogSize:  uint64(cp.log_size),
		LeafHash: merkleHashFromC(&cp.leaf_hash),
	}
	for i := 0; i < int(cp.depth); i++ {
		p.Siblings = append(p.Siblings, merkleHashFromC(&cp.siblings[i]))
	}
	return p
}
