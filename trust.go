package nwep

/*
#include <nwep/nwep.h>
#include <string.h>

extern nwep_trust_storage make_trust_storage(void *ud);
extern void* handle_to_ptr(uintptr_t h);
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

const (
	StalenessWarningNS = 3600 * Seconds
	StalenessRejectNS  = 86400 * Seconds
	IdentityCacheTTL   = 3600 * Seconds
)

// Staleness indicates checkpoint freshness status.
type Staleness int

const (
	StalenessFresh   Staleness = C.NWEP_STALENESS_FRESH
	StalenessWarning Staleness = C.NWEP_STALENESS_WARNING
	StalenessReject  Staleness = C.NWEP_STALENESS_REJECT
)

type TrustSettings struct {
	StalenessWarningNS Duration
	StalenessRejectNS  Duration
	IdentityCacheTTL   Duration
	AnchorThreshold    int
}

func TrustSettingsDefault() *TrustSettings {
	var cs C.nwep_trust_settings
	C.nwep_trust_settings_default(&cs)
	return &TrustSettings{
		StalenessWarningNS: Duration(cs.staleness_warning_ns),
		StalenessRejectNS:  Duration(cs.staleness_reject_ns),
		IdentityCacheTTL:   Duration(cs.identity_cache_ttl),
		AnchorThreshold:    int(cs.anchor_threshold),
	}
}

type VerifiedIdentity struct {
	NodeID          NodeID
	Pubkey          [32]byte
	LogIndex        uint64
	CheckpointEpoch uint64
	VerifiedAt      Tstamp
	Revoked         bool
}

type Equivocation struct {
	Anchor BLSPubkey
	Epoch  uint64
	Root1  MerkleHash
	Root2  MerkleHash
}

type TrustStorage struct {
	AnchorLoad     func() ([]BLSPubkey, error)
	AnchorSave     func(anchors []BLSPubkey) error
	CheckpointLoad func() ([]*Checkpoint, error)
	CheckpointSave func(cp *Checkpoint) error
}

type trustStorageState struct {
	storage *TrustStorage
}

type TrustStore struct {
	c             *C.nwep_trust_store
	storageHandle cgo.Handle
}

func NewTrustStore(settings *TrustSettings) (*TrustStore, error) {
	return NewTrustStoreWithStorage(settings, nil)
}

func NewTrustStoreWithStorage(settings *TrustSettings, storage *TrustStorage) (*TrustStore, error) {
	ts := &TrustStore{}
	var cs *C.nwep_trust_settings
	var csettings C.nwep_trust_settings
	if settings != nil {
		csettings.staleness_warning_ns = C.nwep_duration(settings.StalenessWarningNS)
		csettings.staleness_reject_ns = C.nwep_duration(settings.StalenessRejectNS)
		csettings.identity_cache_ttl = C.nwep_duration(settings.IdentityCacheTTL)
		csettings.anchor_threshold = C.size_t(settings.AnchorThreshold)
		cs = &csettings
	}

	if storage != nil {
		state := &trustStorageState{storage: storage}
		ts.storageHandle = cgo.NewHandle(state)
		cstorage := C.make_trust_storage(C.handle_to_ptr(C.uintptr_t(ts.storageHandle)))
		rv := C.nwep_trust_store_new(&ts.c, cs, &cstorage)
		if err := errorFromCode(int(rv)); err != nil {
			ts.storageHandle.Delete()
			return nil, err
		}
	} else {
		rv := C.nwep_trust_store_new(&ts.c, cs, nil)
		if err := errorFromCode(int(rv)); err != nil {
			return nil, err
		}
	}

	return ts, nil
}

func (ts *TrustStore) Free() {
	if ts.c != nil {
		C.nwep_trust_store_free(ts.c)
		ts.c = nil
	}
	if ts.storageHandle != 0 {
		ts.storageHandle.Delete()
		ts.storageHandle = 0
	}
}

func (ts *TrustStore) AddAnchor(pk BLSPubkey, builtin bool) error {
	cpk := blsPubkeyToC(pk)
	b := C.int(0)
	if builtin {
		b = 1
	}
	return errorFromCode(int(C.nwep_trust_store_add_anchor(ts.c, &cpk, b)))
}

func (ts *TrustStore) RemoveAnchor(pk BLSPubkey) error {
	cpk := blsPubkeyToC(pk)
	return errorFromCode(int(C.nwep_trust_store_remove_anchor(ts.c, &cpk)))
}

// Anchors returns the anchor set owned by the trust store.
// The returned AnchorSet must not be freed by the caller.
func (ts *TrustStore) Anchors() *AnchorSet {
	cas := C.nwep_trust_store_get_anchors(ts.c)
	if cas == nil {
		return nil
	}
	return &AnchorSet{c: (*C.nwep_anchor_set)(unsafe.Pointer(cas))}
}

func (ts *TrustStore) AddCheckpoint(cp *Checkpoint) error {
	ccp := checkpointToC(cp)
	return errorFromCode(int(C.nwep_trust_store_add_checkpoint(ts.c, &ccp)))
}

func (ts *TrustStore) LatestCheckpoint() (*Checkpoint, error) {
	var ccp C.nwep_checkpoint
	rv := C.nwep_trust_store_get_latest_checkpoint(ts.c, &ccp)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return checkpointFromC(&ccp), nil
}

func (ts *TrustStore) GetCheckpoint(epoch uint64) (*Checkpoint, error) {
	var ccp C.nwep_checkpoint
	rv := C.nwep_trust_store_get_checkpoint(ts.c, C.uint64_t(epoch), &ccp)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return checkpointFromC(&ccp), nil
}

func (ts *TrustStore) CheckpointCount() int {
	return int(C.nwep_trust_store_checkpoint_count(ts.c))
}

func (ts *TrustStore) CheckStaleness(now Tstamp) Staleness {
	return Staleness(C.nwep_trust_store_check_staleness(ts.c, C.nwep_tstamp(now)))
}

func (ts *TrustStore) StalenessAge(now Tstamp) Duration {
	return Duration(C.nwep_trust_store_get_staleness_age(ts.c, C.nwep_tstamp(now)))
}

func (ts *TrustStore) VerifyIdentity(entry *MerkleEntry, proof *MerkleProof, cp *Checkpoint, now Tstamp) (*VerifiedIdentity, error) {
	ce := merkleEntryToC(entry)
	cproof := merkleProofToC(proof)

	var ccpPtr *C.nwep_checkpoint
	if cp != nil {
		ccp := checkpointToC(cp)
		ccpPtr = &ccp
	}

	var cvi C.nwep_verified_identity
	rv := C.nwep_trust_store_verify_identity(ts.c, &ce, &cproof, ccpPtr, C.nwep_tstamp(now), &cvi)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return verifiedIdentityFromC(&cvi), nil
}

func (ts *TrustStore) CacheIdentity(vi *VerifiedIdentity) error {
	cvi := verifiedIdentityToC(vi)
	return errorFromCode(int(C.nwep_trust_store_cache_identity(ts.c, &cvi)))
}

func (ts *TrustStore) LookupIdentity(nodeid NodeID, now Tstamp) (*VerifiedIdentity, error) {
	cnid := nodeid.toCNodeID()
	var cvi C.nwep_verified_identity
	rv := C.nwep_trust_store_lookup_identity(ts.c, &cnid, C.nwep_tstamp(now), &cvi)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return verifiedIdentityFromC(&cvi), nil
}

func (ts *TrustStore) CheckEquivocation(cp *Checkpoint) (*Equivocation, error) {
	ccp := checkpointToC(cp)
	var ceq C.nwep_equivocation
	rv := C.nwep_trust_store_check_equivocation(ts.c, &ccp, &ceq)
	if err := errorFromCode(int(rv)); err != nil {
		eq := &Equivocation{
			Anchor: blsPubkeyFromC(&ceq.anchor),
			Epoch:  uint64(ceq.epoch),
			Root1:  merkleHashFromC(&ceq.root1),
			Root2:  merkleHashFromC(&ceq.root2),
		}
		return eq, err
	}
	return nil, nil
}

func verifiedIdentityToC(vi *VerifiedIdentity) C.nwep_verified_identity {
	var cvi C.nwep_verified_identity
	C.memcpy(unsafe.Pointer(&cvi.nodeid.data[0]), unsafe.Pointer(&vi.NodeID[0]), 32)
	C.memcpy(unsafe.Pointer(&cvi.pubkey[0]), unsafe.Pointer(&vi.Pubkey[0]), 32)
	cvi.log_index = C.uint64_t(vi.LogIndex)
	cvi.checkpoint_epoch = C.uint64_t(vi.CheckpointEpoch)
	cvi.verified_at = C.nwep_tstamp(vi.VerifiedAt)
	if vi.Revoked {
		cvi.revoked = 1
	}
	return cvi
}

func verifiedIdentityFromC(cvi *C.nwep_verified_identity) *VerifiedIdentity {
	vi := &VerifiedIdentity{
		LogIndex:        uint64(cvi.log_index),
		CheckpointEpoch: uint64(cvi.checkpoint_epoch),
		VerifiedAt:      Tstamp(cvi.verified_at),
		Revoked:         cvi.revoked != 0,
	}
	C.memcpy(unsafe.Pointer(&vi.NodeID[0]), unsafe.Pointer(&cvi.nodeid.data[0]), 32)
	C.memcpy(unsafe.Pointer(&vi.Pubkey[0]), unsafe.Pointer(&cvi.pubkey[0]), 32)
	return vi
}

// Trust storage callback exports.

//export goTrustAnchorLoad
func goTrustAnchorLoad(userData unsafe.Pointer, anchors *C.nwep_bls_pubkey, maxAnchors C.size_t) C.int {
	state := cgo.Handle(userData).Value().(*trustStorageState)
	if state.storage.AnchorLoad == nil {
		return 0
	}
	loaded, err := state.storage.AnchorLoad()
	if err != nil {
		return C.int(ErrStorageReadError)
	}
	n := len(loaded)
	if n > int(maxAnchors) {
		n = int(maxAnchors)
	}
	for i := 0; i < n; i++ {
		dst := (*C.nwep_bls_pubkey)(unsafe.Pointer(uintptr(unsafe.Pointer(anchors)) + uintptr(i)*unsafe.Sizeof(C.nwep_bls_pubkey{})))
		cpk := blsPubkeyToC(loaded[i])
		*dst = cpk
	}
	return C.int(n)
}

//export goTrustAnchorSave
func goTrustAnchorSave(userData unsafe.Pointer, anchors *C.nwep_bls_pubkey, count C.size_t) C.int {
	state := cgo.Handle(userData).Value().(*trustStorageState)
	if state.storage.AnchorSave == nil {
		return 0
	}
	pks := make([]BLSPubkey, int(count))
	for i := range pks {
		src := (*C.nwep_bls_pubkey)(unsafe.Pointer(uintptr(unsafe.Pointer(anchors)) + uintptr(i)*unsafe.Sizeof(C.nwep_bls_pubkey{})))
		pks[i] = blsPubkeyFromC(src)
	}
	if err := state.storage.AnchorSave(pks); err != nil {
		return C.int(ErrStorageWriteError)
	}
	return 0
}

//export goTrustCheckpointLoad
func goTrustCheckpointLoad(userData unsafe.Pointer, checkpoints *C.nwep_checkpoint, maxCheckpoints C.size_t) C.int {
	state := cgo.Handle(userData).Value().(*trustStorageState)
	if state.storage.CheckpointLoad == nil {
		return 0
	}
	loaded, err := state.storage.CheckpointLoad()
	if err != nil {
		return C.int(ErrStorageReadError)
	}
	n := len(loaded)
	if n > int(maxCheckpoints) {
		n = int(maxCheckpoints)
	}
	for i := 0; i < n; i++ {
		dst := (*C.nwep_checkpoint)(unsafe.Pointer(uintptr(unsafe.Pointer(checkpoints)) + uintptr(i)*unsafe.Sizeof(C.nwep_checkpoint{})))
		*dst = checkpointToC(loaded[i])
	}
	return C.int(n)
}

//export goTrustCheckpointSave
func goTrustCheckpointSave(userData unsafe.Pointer, cp *C.nwep_checkpoint) C.int {
	state := cgo.Handle(userData).Value().(*trustStorageState)
	if state.storage.CheckpointSave == nil {
		return 0
	}
	goCP := checkpointFromC(cp)
	if err := state.storage.CheckpointSave(goCP); err != nil {
		return C.int(ErrStorageWriteError)
	}
	return 0
}
