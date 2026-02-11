package nwep

/*
#include <nwep/nwep.h>
#include <string.h>
*/
import "C"

const (
	MaxAnchors             = C.NWEP_MAX_ANCHORS
	DefaultAnchorThreshold = C.NWEP_DEFAULT_ANCHOR_THRESHOLD
)

type AnchorSet struct {
	c *C.nwep_anchor_set
}

func NewAnchorSet(threshold int) (*AnchorSet, error) {
	as := &AnchorSet{}
	rv := C.nwep_anchor_set_new(&as.c, C.size_t(threshold))
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return as, nil
}

func (as *AnchorSet) Free() {
	if as.c != nil {
		C.nwep_anchor_set_free(as.c)
		as.c = nil
	}
}

func (as *AnchorSet) Add(pk BLSPubkey, builtin bool) error {
	cpk := blsPubkeyToC(pk)
	b := C.int(0)
	if builtin {
		b = 1
	}
	return errorFromCode(int(C.nwep_anchor_set_add(as.c, &cpk, b)))
}

func (as *AnchorSet) Remove(pk BLSPubkey) error {
	cpk := blsPubkeyToC(pk)
	return errorFromCode(int(C.nwep_anchor_set_remove(as.c, &cpk)))
}

func (as *AnchorSet) Size() int {
	return int(C.nwep_anchor_set_size(as.c))
}

func (as *AnchorSet) Get(idx int) (BLSPubkey, bool, error) {
	var cpk C.nwep_bls_pubkey
	var builtin C.int
	rv := C.nwep_anchor_set_get(as.c, C.size_t(idx), &cpk, &builtin)
	if err := errorFromCode(int(rv)); err != nil {
		return BLSPubkey{}, false, err
	}
	return blsPubkeyFromC(&cpk), builtin != 0, nil
}

func (as *AnchorSet) Threshold() int {
	return int(C.nwep_anchor_set_threshold(as.c))
}

func (as *AnchorSet) Contains(pk BLSPubkey) bool {
	cpk := blsPubkeyToC(pk)
	return C.nwep_anchor_set_contains(as.c, &cpk) != 0
}

func (as *AnchorSet) cPtr() *C.nwep_anchor_set {
	return as.c
}
