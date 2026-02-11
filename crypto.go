package nwep

/*
#include <nwep/nwep.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import "unsafe"

func Sign(kp *Keypair, msg []byte) ([64]byte, error) {
	var sig [64]byte
	var dummy C.uint8_t
	msgPtr := &dummy
	if len(msg) > 0 {
		msgPtr = (*C.uint8_t)(unsafe.Pointer(&msg[0]))
	}
	rv := C.nwep_sign((*C.uint8_t)(unsafe.Pointer(&sig[0])), (*C.uint8_t)(unsafe.Pointer(msgPtr)), C.size_t(len(msg)), &kp.c)
	if err := errorFromCode(int(rv)); err != nil {
		return [64]byte{}, err
	}
	return sig, nil
}

func Verify(pubkey [32]byte, sig [64]byte, msg []byte) error {
	var dummy C.uint8_t
	msgPtr := &dummy
	if len(msg) > 0 {
		msgPtr = (*C.uint8_t)(unsafe.Pointer(&msg[0]))
	}
	rv := C.nwep_verify((*C.uint8_t)(unsafe.Pointer(&sig[0])), (*C.uint8_t)(unsafe.Pointer(msgPtr)),
		C.size_t(len(msg)), (*C.uint8_t)(unsafe.Pointer(&pubkey[0])))
	return errorFromCode(int(rv))
}

func ChallengeGenerate() ([32]byte, error) {
	var challenge [32]byte
	rv := C.nwep_challenge_generate((*C.uint8_t)(unsafe.Pointer(&challenge[0])))
	if err := errorFromCode(int(rv)); err != nil {
		return [32]byte{}, err
	}
	return challenge, nil
}

func ChallengeSign(challenge [32]byte, kp *Keypair) ([64]byte, error) {
	var response [64]byte
	rv := C.nwep_challenge_sign((*C.uint8_t)(unsafe.Pointer(&response[0])),
		(*C.uint8_t)(unsafe.Pointer(&challenge[0])), &kp.c)
	if err := errorFromCode(int(rv)); err != nil {
		return [64]byte{}, err
	}
	return response, nil
}

func ChallengeVerify(response [64]byte, challenge [32]byte, pubkey [32]byte) error {
	rv := C.nwep_challenge_verify((*C.uint8_t)(unsafe.Pointer(&response[0])),
		(*C.uint8_t)(unsafe.Pointer(&challenge[0])),
		(*C.uint8_t)(unsafe.Pointer(&pubkey[0])))
	return errorFromCode(int(rv))
}

func RandomBytes(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	rv := C.nwep_random_bytes((*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b)))
	return errorFromCode(int(rv))
}

const (
	ShamirMaxShares    = C.NWEP_SHAMIR_MAX_SHARES
	ShamirMinThreshold = C.NWEP_SHAMIR_MIN_THRESHOLD
)

type ShamirShare struct {
	Index uint8
	Data  [32]byte
}

func ShamirSplit(secret [32]byte, n, t int) ([]ShamirShare, error) {
	cshares := make([]C.nwep_shamir_share, n)
	rv := C.nwep_shamir_split((*C.uint8_t)(unsafe.Pointer(&secret[0])),
		&cshares[0], C.size_t(n), C.size_t(t))
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	shares := make([]ShamirShare, n)
	for i := range shares {
		shares[i].Index = uint8(cshares[i].index)
		C.memcpy(unsafe.Pointer(&shares[i].Data[0]), unsafe.Pointer(&cshares[i].data[0]), 32)
	}
	return shares, nil
}

func ShamirCombine(shares []ShamirShare) ([32]byte, error) {
	cshares := make([]C.nwep_shamir_share, len(shares))
	for i, s := range shares {
		cshares[i].index = C.uint8_t(s.Index)
		C.memcpy(unsafe.Pointer(&cshares[i].data[0]), unsafe.Pointer(&s.Data[0]), 32)
	}
	var secret [32]byte
	rv := C.nwep_shamir_combine((*C.uint8_t)(unsafe.Pointer(&secret[0])),
		&cshares[0], C.size_t(len(shares)))
	if err := errorFromCode(int(rv)); err != nil {
		return [32]byte{}, err
	}
	return secret, nil
}
