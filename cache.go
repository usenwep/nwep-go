package nwep

/*
#include <nwep/nwep.h>
#include <string.h>
*/
import "C"

import "unsafe"

const (
	CacheDefaultCapacity = C.NWEP_CACHE_DEFAULT_CAPACITY
	CacheDefaultTTL      = 3600 * Seconds
)

func IdentityCacheSettingsDefault() *IdentityCacheSettings {
	var cs C.nwep_identity_cache_settings
	C.nwep_identity_cache_settings_default(&cs)
	return &IdentityCacheSettings{
		Capacity: int(cs.capacity),
		TTL:      Duration(cs.ttl_ns),
	}
}

type IdentityCacheSettings struct {
	Capacity int
	TTL      Duration
}

type CachedIdentity struct {
	NodeID     NodeID
	Pubkey     [32]byte
	LogIndex   uint64
	VerifiedAt Tstamp
	ExpiresAt  Tstamp
}

type CacheStats struct {
	Hits          uint64
	Misses        uint64
	Evictions     uint64
	Stores        uint64
	Invalidations uint64
}

type IdentityCache struct {
	c *C.nwep_identity_cache
}

func NewIdentityCache(settings *IdentityCacheSettings) (*IdentityCache, error) {
	ic := &IdentityCache{}
	var cs *C.nwep_identity_cache_settings
	var csettings C.nwep_identity_cache_settings
	if settings != nil {
		csettings.capacity = C.size_t(settings.Capacity)
		csettings.ttl_ns = C.nwep_tstamp(settings.TTL)
		cs = &csettings
	}
	rv := C.nwep_identity_cache_new(&ic.c, cs)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return ic, nil
}

func (ic *IdentityCache) Free() {
	if ic.c != nil {
		C.nwep_identity_cache_free(ic.c)
		ic.c = nil
	}
}

func (ic *IdentityCache) Lookup(nodeid NodeID, now Tstamp) (*CachedIdentity, error) {
	cnid := nodeid.toCNodeID()
	var cci C.nwep_cached_identity
	rv := C.nwep_identity_cache_lookup(ic.c, &cnid, C.nwep_tstamp(now), &cci)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return cachedIdentityFromC(&cci), nil
}

func (ic *IdentityCache) Store(nodeid NodeID, pubkey [32]byte, logIndex uint64, now Tstamp) error {
	cnid := nodeid.toCNodeID()
	return errorFromCode(int(C.nwep_identity_cache_store(ic.c, &cnid,
		(*C.uint8_t)(unsafe.Pointer(&pubkey[0])), C.uint64_t(logIndex), C.nwep_tstamp(now))))
}

func (ic *IdentityCache) Invalidate(nodeid NodeID) error {
	cnid := nodeid.toCNodeID()
	return errorFromCode(int(C.nwep_identity_cache_invalidate(ic.c, &cnid)))
}

func (ic *IdentityCache) Clear() {
	C.nwep_identity_cache_clear(ic.c)
}

func (ic *IdentityCache) Size() int {
	return int(C.nwep_identity_cache_size(ic.c))
}

func (ic *IdentityCache) Capacity() int {
	return int(C.nwep_identity_cache_capacity(ic.c))
}

func (ic *IdentityCache) OnRotation(nodeid NodeID, newPubkey [32]byte, newLogIndex uint64, now Tstamp) error {
	cnid := nodeid.toCNodeID()
	return errorFromCode(int(C.nwep_identity_cache_on_rotation(ic.c, &cnid,
		(*C.uint8_t)(unsafe.Pointer(&newPubkey[0])), C.uint64_t(newLogIndex), C.nwep_tstamp(now))))
}

func (ic *IdentityCache) OnRevocation(nodeid NodeID) error {
	cnid := nodeid.toCNodeID()
	return errorFromCode(int(C.nwep_identity_cache_on_revocation(ic.c, &cnid)))
}

func (ic *IdentityCache) Stats() CacheStats {
	var cs C.nwep_cache_stats
	C.nwep_identity_cache_get_stats(ic.c, &cs)
	return CacheStats{
		Hits:          uint64(cs.hits),
		Misses:        uint64(cs.misses),
		Evictions:     uint64(cs.evictions),
		Stores:        uint64(cs.stores),
		Invalidations: uint64(cs.invalidations),
	}
}

func (ic *IdentityCache) ResetStats() {
	C.nwep_identity_cache_reset_stats(ic.c)
}

func cachedIdentityFromC(cci *C.nwep_cached_identity) *CachedIdentity {
	ci := &CachedIdentity{
		LogIndex:   uint64(cci.log_index),
		VerifiedAt: Tstamp(cci.verified_at),
		ExpiresAt:  Tstamp(cci.expires_at),
	}
	C.memcpy(unsafe.Pointer(&ci.NodeID[0]), unsafe.Pointer(&cci.nodeid.data[0]), 32)
	C.memcpy(unsafe.Pointer(&ci.Pubkey[0]), unsafe.Pointer(&cci.pubkey[0]), 32)
	return ci
}
