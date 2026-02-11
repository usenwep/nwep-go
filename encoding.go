package nwep

/*
#include <nwep/nwep.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func Base58Encode(src []byte) string {
	if len(src) == 0 {
		return ""
	}
	destLen := C.nwep_base58_encode_len(C.size_t(len(src)))
	dest := make([]byte, destLen)
	n := C.nwep_base58_encode((*C.char)(unsafe.Pointer(&dest[0])), destLen,
		(*C.uint8_t)(unsafe.Pointer(&src[0])), C.size_t(len(src)))
	if n == 0 {
		return ""
	}
	return string(dest[:n])
}

func Base58Decode(src string) ([]byte, error) {
	if len(src) == 0 {
		return nil, nil
	}
	csrc := C.CString(src)
	defer C.free(unsafe.Pointer(csrc))
	destLen := C.nwep_base58_decode_len(C.size_t(len(src)))
	dest := make([]byte, destLen)
	n := C.nwep_base58_decode((*C.uint8_t)(unsafe.Pointer(&dest[0])), destLen, csrc)
	if n == 0 {
		return nil, fmt.Errorf("nwep: base58 decode failed")
	}
	return dest[:n], nil
}

func Base64Encode(src []byte) string {
	if len(src) == 0 {
		return ""
	}
	destLen := C.nwep_base64_encode_len(C.size_t(len(src)))
	dest := make([]byte, destLen)
	n := C.nwep_base64_encode((*C.char)(unsafe.Pointer(&dest[0])), destLen,
		(*C.uint8_t)(unsafe.Pointer(&src[0])), C.size_t(len(src)))
	if n == 0 {
		return ""
	}
	return string(dest[:n])
}

func Base64Decode(src string) ([]byte, error) {
	if len(src) == 0 {
		return nil, nil
	}
	csrc := C.CString(src)
	defer C.free(unsafe.Pointer(csrc))
	destLen := C.nwep_base64_decode_len(C.size_t(len(src)))
	dest := make([]byte, destLen)
	n := C.nwep_base64_decode((*C.uint8_t)(unsafe.Pointer(&dest[0])), destLen, csrc)
	if n == 0 {
		return nil, fmt.Errorf("nwep: base64 decode failed")
	}
	return dest[:n], nil
}

// Base64DecodeN decodes from a byte slice without requiring a null terminator.
func Base64DecodeN(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, nil
	}
	destLen := C.nwep_base64_decode_len(C.size_t(len(src)))
	dest := make([]byte, destLen)
	n := C.nwep_base64_decode_n((*C.uint8_t)(unsafe.Pointer(&dest[0])), destLen,
		(*C.char)(unsafe.Pointer(&src[0])), C.size_t(len(src)))
	if n == 0 {
		return nil, fmt.Errorf("nwep: base64 decode_n failed")
	}
	return dest[:n], nil
}
