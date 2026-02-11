package nwep

/*
#include <nwep/nwep.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"encoding/hex"
	"unsafe"
)

type Keypair struct {
	c C.nwep_keypair
}

func GenerateKeypair() (*Keypair, error) {
	kp := &Keypair{}
	rv := C.nwep_keypair_generate(&kp.c)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return kp, nil
}

func KeypairFromSeed(seed [32]byte) (*Keypair, error) {
	kp := &Keypair{}
	rv := C.nwep_keypair_from_seed(&kp.c, (*C.uint8_t)(unsafe.Pointer(&seed[0])))
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return kp, nil
}

func KeypairFromPrivkey(privkey [64]byte) (*Keypair, error) {
	kp := &Keypair{}
	rv := C.nwep_keypair_from_privkey(&kp.c, (*C.uint8_t)(unsafe.Pointer(&privkey[0])))
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return kp, nil
}

func (kp *Keypair) PublicKey() [32]byte {
	var out [32]byte
	C.memcpy(unsafe.Pointer(&out[0]), unsafe.Pointer(&kp.c.pubkey[0]), 32)
	return out
}

// Seed returns the 32-byte Ed25519 seed (first half of the private key).
func (kp *Keypair) Seed() [32]byte {
	var out [32]byte
	C.memcpy(unsafe.Pointer(&out[0]), unsafe.Pointer(&kp.c.privkey[0]), 32)
	return out
}

// PrivateKey returns the 64-byte Ed25519 expanded private key (seed || pubkey).
func (kp *Keypair) PrivateKey() [64]byte {
	var out [64]byte
	C.memcpy(unsafe.Pointer(&out[0]), unsafe.Pointer(&kp.c.privkey[0]), 64)
	return out
}

func (kp *Keypair) NodeID() (NodeID, error) {
	var nid C.nwep_nodeid
	rv := C.nwep_nodeid_from_keypair(&nid, &kp.c)
	if err := errorFromCode(int(rv)); err != nil {
		return NodeID{}, err
	}
	var out NodeID
	C.memcpy(unsafe.Pointer(&out[0]), unsafe.Pointer(&nid.data[0]), 32)
	return out, nil
}

func (kp *Keypair) Clear() {
	C.nwep_keypair_clear(&kp.c)
}

// NodeID is a 32-byte identifier derived from a public key: SHA-256(pubkey || "WEB/1").
type NodeID [32]byte

func NodeIDFromPubkey(pubkey [32]byte) (NodeID, error) {
	var nid C.nwep_nodeid
	rv := C.nwep_nodeid_from_pubkey(&nid, (*C.uint8_t)(unsafe.Pointer(&pubkey[0])))
	if err := errorFromCode(int(rv)); err != nil {
		return NodeID{}, err
	}
	var out NodeID
	C.memcpy(unsafe.Pointer(&out[0]), unsafe.Pointer(&nid.data[0]), 32)
	return out, nil
}

func (n NodeID) String() string {
	return hex.EncodeToString(n[:])
}

func (n NodeID) Equal(other NodeID) bool {
	return n == other
}

func (n NodeID) IsZero() bool {
	for _, b := range n {
		if b != 0 {
			return false
		}
	}
	return true
}

func (n NodeID) toCNodeID() C.nwep_nodeid {
	var cnid C.nwep_nodeid
	C.memcpy(unsafe.Pointer(&cnid.data[0]), unsafe.Pointer(&n[0]), 32)
	return cnid
}

func nodeIDFromC(cnid *C.nwep_nodeid) NodeID {
	var out NodeID
	C.memcpy(unsafe.Pointer(&out[0]), unsafe.Pointer(&cnid.data[0]), 32)
	return out
}

type Identity struct {
	PublicKey [32]byte
	NodeID    NodeID
}

func identityFromC(ci *C.nwep_identity) Identity {
	var id Identity
	C.memcpy(unsafe.Pointer(&id.PublicKey[0]), unsafe.Pointer(&ci.pubkey[0]), 32)
	id.NodeID = nodeIDFromC(&ci.nodeid)
	if id.NodeID.IsZero() {
		if derived, err := NodeIDFromPubkey(id.PublicKey); err == nil {
			id.NodeID = derived
		}
	}
	return id
}

// Key rotation constants.
const (
	KeyOverlapSeconds = C.NWEP_KEY_OVERLAP_SECONDS
	MaxActiveKeys     = C.NWEP_MAX_ACTIVE_KEYS
)

type TimedKeypair struct {
	Keypair     Keypair
	ActivatedAt Tstamp
	ExpiresAt   Tstamp
	Active      bool
}

type Revocation struct {
	NodeID          NodeID
	Timestamp       Tstamp
	RecoveryPubkey  [32]byte
	Signature       [64]byte
}

type ManagedIdentity struct {
	c C.nwep_managed_identity
}

func NewManagedIdentity(kp *Keypair, ra *RecoveryAuthority) (*ManagedIdentity, error) {
	mi := &ManagedIdentity{}
	var raPtr *C.nwep_recovery_authority
	if ra != nil {
		raPtr = &ra.c
	}
	now := C.nwep_tstamp(nowNanos())
	rv := C.nwep_managed_identity_new(&mi.c, &kp.c, raPtr, now)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return mi, nil
}

func (mi *ManagedIdentity) Rotate() error {
	now := C.nwep_tstamp(nowNanos())
	return errorFromCode(int(C.nwep_managed_identity_rotate(&mi.c, now)))
}

func (mi *ManagedIdentity) Update() {
	now := C.nwep_tstamp(nowNanos())
	C.nwep_managed_identity_update(&mi.c, now)
}

func (mi *ManagedIdentity) ActiveKeypair() *Keypair {
	ckp := C.nwep_managed_identity_get_active(&mi.c)
	if ckp == nil {
		return nil
	}
	kp := &Keypair{}
	C.memcpy(unsafe.Pointer(&kp.c), unsafe.Pointer(ckp), C.size_t(unsafe.Sizeof(kp.c)))
	return kp
}

func (mi *ManagedIdentity) IsRevoked() bool {
	return C.nwep_managed_identity_is_revoked(&mi.c) != 0
}

func (mi *ManagedIdentity) Revoke(ra *RecoveryAuthority) error {
	now := C.nwep_tstamp(nowNanos())
	return errorFromCode(int(C.nwep_managed_identity_revoke(&mi.c, &ra.c, now)))
}

func (mi *ManagedIdentity) NodeID() NodeID {
	return nodeIDFromC(&mi.c.nodeid)
}

func (mi *ManagedIdentity) ActiveKeys() []*Keypair {
	var ptrs [MaxActiveKeys]*C.nwep_keypair
	n := C.nwep_managed_identity_get_active_keys(&mi.c,
		(**C.nwep_keypair)(unsafe.Pointer(&ptrs[0])), C.size_t(MaxActiveKeys))
	keys := make([]*Keypair, int(n))
	for i := range keys {
		kp := &Keypair{}
		C.memcpy(unsafe.Pointer(&kp.c), unsafe.Pointer(ptrs[i]), C.size_t(unsafe.Sizeof(kp.c)))
		keys[i] = kp
	}
	return keys
}

func (mi *ManagedIdentity) Clear() {
	C.nwep_managed_identity_clear(&mi.c)
}

func VerifyRevocation(rev *Revocation) error {
	var crev C.nwep_revocation
	C.memcpy(unsafe.Pointer(&crev.nodeid.data[0]), unsafe.Pointer(&rev.NodeID[0]), 32)
	crev.timestamp = C.nwep_tstamp(rev.Timestamp)
	C.memcpy(unsafe.Pointer(&crev.recovery_pubkey[0]), unsafe.Pointer(&rev.RecoveryPubkey[0]), 32)
	C.memcpy(unsafe.Pointer(&crev.signature[0]), unsafe.Pointer(&rev.Signature[0]), 64)
	return errorFromCode(int(C.nwep_managed_identity_verify_revocation(&crev)))
}

type RecoveryAuthority struct {
	c C.nwep_recovery_authority
}

func NewRecoveryAuthority() (*RecoveryAuthority, error) {
	ra := &RecoveryAuthority{}
	rv := C.nwep_recovery_authority_new(&ra.c)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return ra, nil
}

func RecoveryAuthorityFromKeypair(kp *Keypair) (*RecoveryAuthority, error) {
	ra := &RecoveryAuthority{}
	rv := C.nwep_recovery_authority_from_keypair(&ra.c, &kp.c)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return ra, nil
}

func (ra *RecoveryAuthority) PublicKey() [32]byte {
	var out [32]byte
	pk := C.nwep_recovery_authority_get_pubkey(&ra.c)
	if pk != nil {
		C.memcpy(unsafe.Pointer(&out[0]), unsafe.Pointer(pk), 32)
	}
	return out
}

func (ra *RecoveryAuthority) Clear() {
	C.nwep_recovery_authority_clear(&ra.c)
}
