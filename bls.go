package nwep

/*
#include <nwep/nwep.h>
#include <string.h>
*/
import "C"

import "unsafe"

const (
	BLSPubkeyLen  = C.NWEP_BLS_PUBKEY_LEN
	BLSPrivkeyLen = C.NWEP_BLS_PRIVKEY_LEN
	BLSSigLen     = C.NWEP_BLS_SIG_LEN
)

type BLSKeypair struct {
	c C.nwep_bls_keypair
}

type BLSPubkey [BLSPubkeyLen]byte
type BLSSig [BLSSigLen]byte

func BLSKeypairGenerate() (*BLSKeypair, error) {
	kp := &BLSKeypair{}
	rv := C.nwep_bls_keypair_generate(&kp.c)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return kp, nil
}

func BLSKeypairFromSeed(ikm []byte) (*BLSKeypair, error) {
	kp := &BLSKeypair{}
	rv := C.nwep_bls_keypair_from_seed(&kp.c,
		(*C.uint8_t)(unsafe.Pointer(&ikm[0])), C.size_t(len(ikm)))
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return kp, nil
}

func (kp *BLSKeypair) Pubkey() BLSPubkey {
	var out BLSPubkey
	C.memcpy(unsafe.Pointer(&out[0]), unsafe.Pointer(&kp.c.pubkey[0]), BLSPubkeyLen)
	return out
}

func BLSPubkeySerialize(pk *BLSPubkey) ([BLSPubkeyLen]byte, error) {
	var cpk C.nwep_bls_pubkey
	C.memcpy(unsafe.Pointer(&cpk.data[0]), unsafe.Pointer(&pk[0]), BLSPubkeyLen)
	var out [BLSPubkeyLen]byte
	rv := C.nwep_bls_pubkey_serialize((*C.uint8_t)(unsafe.Pointer(&out[0])), &cpk)
	if err := errorFromCode(int(rv)); err != nil {
		return [BLSPubkeyLen]byte{}, err
	}
	return out, nil
}

func BLSPubkeyDeserialize(data [BLSPubkeyLen]byte) (BLSPubkey, error) {
	var cpk C.nwep_bls_pubkey
	rv := C.nwep_bls_pubkey_deserialize(&cpk, (*C.uint8_t)(unsafe.Pointer(&data[0])))
	if err := errorFromCode(int(rv)); err != nil {
		return BLSPubkey{}, err
	}
	var out BLSPubkey
	C.memcpy(unsafe.Pointer(&out[0]), unsafe.Pointer(&cpk.data[0]), BLSPubkeyLen)
	return out, nil
}

func BLSSign(kp *BLSKeypair, msg []byte) (BLSSig, error) {
	var csig C.nwep_bls_sig
	var msgPtr *C.uint8_t
	if len(msg) > 0 {
		msgPtr = (*C.uint8_t)(unsafe.Pointer(&msg[0]))
	}
	rv := C.nwep_bls_sign(&csig, &kp.c, msgPtr, C.size_t(len(msg)))
	if err := errorFromCode(int(rv)); err != nil {
		return BLSSig{}, err
	}
	var out BLSSig
	C.memcpy(unsafe.Pointer(&out[0]), unsafe.Pointer(&csig.data[0]), BLSSigLen)
	return out, nil
}

func BLSVerify(pk BLSPubkey, sig BLSSig, msg []byte) error {
	var cpk C.nwep_bls_pubkey
	C.memcpy(unsafe.Pointer(&cpk.data[0]), unsafe.Pointer(&pk[0]), BLSPubkeyLen)
	var csig C.nwep_bls_sig
	C.memcpy(unsafe.Pointer(&csig.data[0]), unsafe.Pointer(&sig[0]), BLSSigLen)
	var msgPtr *C.uint8_t
	if len(msg) > 0 {
		msgPtr = (*C.uint8_t)(unsafe.Pointer(&msg[0]))
	}
	return errorFromCode(int(C.nwep_bls_verify(&cpk, &csig, msgPtr, C.size_t(len(msg)))))
}

func BLSAggregateSigs(sigs []BLSSig) (BLSSig, error) {
	csigs := make([]C.nwep_bls_sig, len(sigs))
	for i, s := range sigs {
		C.memcpy(unsafe.Pointer(&csigs[i].data[0]), unsafe.Pointer(&s[0]), BLSSigLen)
	}
	var out C.nwep_bls_sig
	rv := C.nwep_bls_aggregate_sigs(&out, &csigs[0], C.size_t(len(csigs)))
	if err := errorFromCode(int(rv)); err != nil {
		return BLSSig{}, err
	}
	var result BLSSig
	C.memcpy(unsafe.Pointer(&result[0]), unsafe.Pointer(&out.data[0]), BLSSigLen)
	return result, nil
}

func BLSVerifyAggregate(pks []BLSPubkey, sig BLSSig, msg []byte) error {
	cpks := make([]C.nwep_bls_pubkey, len(pks))
	for i, pk := range pks {
		C.memcpy(unsafe.Pointer(&cpks[i].data[0]), unsafe.Pointer(&pk[0]), BLSPubkeyLen)
	}
	var csig C.nwep_bls_sig
	C.memcpy(unsafe.Pointer(&csig.data[0]), unsafe.Pointer(&sig[0]), BLSSigLen)
	var msgPtr *C.uint8_t
	if len(msg) > 0 {
		msgPtr = (*C.uint8_t)(unsafe.Pointer(&msg[0]))
	}
	return errorFromCode(int(C.nwep_bls_verify_aggregate(&cpks[0], C.size_t(len(cpks)),
		&csig, msgPtr, C.size_t(len(msg)))))
}

func blsPubkeyToC(pk BLSPubkey) C.nwep_bls_pubkey {
	var cpk C.nwep_bls_pubkey
	C.memcpy(unsafe.Pointer(&cpk.data[0]), unsafe.Pointer(&pk[0]), BLSPubkeyLen)
	return cpk
}

func blsPubkeyFromC(cpk *C.nwep_bls_pubkey) BLSPubkey {
	var out BLSPubkey
	C.memcpy(unsafe.Pointer(&out[0]), unsafe.Pointer(&cpk.data[0]), BLSPubkeyLen)
	return out
}
