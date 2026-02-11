package nwep

/*
#include <nwep/nwep.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import "unsafe"

const (
	MsgRequest  = C.NWEP_MSG_REQUEST
	MsgResponse = C.NWEP_MSG_RESPONSE
	MsgStream   = C.NWEP_MSG_STREAM
	MsgNotify   = C.NWEP_MSG_NOTIFY
)

const (
	FrameHeaderSize = C.NWEP_FRAME_HEADER_SIZE
	MsgTypeSize     = C.NWEP_MSG_TYPE_SIZE
)

type Header struct {
	Name  string
	Value string
}

type Msg struct {
	Type    uint8
	Headers []Header
	Body    []byte
}

func MsgInit(msgType uint8) *Msg {
	return &Msg{Type: msgType}
}

func MsgEncode(msg *Msg) ([]byte, error) {
	var cmsg C.nwep_msg
	C.nwep_msg_init(&cmsg, C.uint8_t(msg.Type))

	cheaders := make([]C.nwep_header, len(msg.Headers))
	cnames := make([]*C.char, len(msg.Headers))
	cvalues := make([]*C.char, len(msg.Headers))
	for i, h := range msg.Headers {
		cnames[i] = C.CString(h.Name)
		cvalues[i] = C.CString(h.Value)
		C.nwep_header_set(&cheaders[i], cnames[i], cvalues[i])
	}
	defer func() {
		for _, cn := range cnames {
			C.free(unsafe.Pointer(cn))
		}
		for _, cv := range cvalues {
			C.free(unsafe.Pointer(cv))
		}
	}()

	if len(cheaders) > 0 {
		cmsg.headers = &cheaders[0]
	}
	cmsg.header_count = C.size_t(len(cheaders))

	if len(msg.Body) > 0 {
		cmsg.body = (*C.uint8_t)(unsafe.Pointer(&msg.Body[0]))
		cmsg.body_len = C.size_t(len(msg.Body))
	}

	encLen := C.nwep_msg_encode_len(&cmsg)
	buf := make([]byte, encLen)
	n := C.nwep_msg_encode((*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &cmsg)
	if n == 0 {
		return nil, errorFromCode(ErrInternalUnknown)
	}
	return buf[:n], nil
}

func MsgDecode(data []byte) (*Msg, error) {
	if len(data) == 0 {
		return nil, errorFromCode(ErrProtoInvalidMessage)
	}
	var cmsg C.nwep_msg
	var cheaders [MaxHeaders]C.nwep_header
	rv := C.nwep_msg_decode(&cmsg, (*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)), &cheaders[0], C.size_t(MaxHeaders))
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}

	msg := &Msg{
		Type: uint8(cmsg._type),
	}

	for i := 0; i < int(cmsg.header_count); i++ {
		ch := cheaders[i]
		msg.Headers = append(msg.Headers, Header{
			Name:  C.GoStringN((*C.char)(unsafe.Pointer(ch.name)), C.int(ch.name_len)),
			Value: C.GoStringN((*C.char)(unsafe.Pointer(ch.value)), C.int(ch.value_len)),
		})
	}

	if cmsg.body != nil && cmsg.body_len > 0 {
		msg.Body = C.GoBytes(unsafe.Pointer(cmsg.body), C.int(cmsg.body_len))
	}

	return msg, nil
}

func MsgDecodeHeader(data []byte) (uint32, error) {
	if len(data) < FrameHeaderSize {
		return 0, errorFromCode(ErrProtoInvalidMessage)
	}
	var payloadLen C.uint32_t
	rv := C.nwep_msg_decode_header(&payloadLen, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if err := errorFromCode(int(rv)); err != nil {
		return 0, err
	}
	return uint32(payloadLen), nil
}

func MsgFindHeader(msg *Msg, name string) (string, bool) {
	for _, h := range msg.Headers {
		if h.Name == name {
			return h.Value, true
		}
	}
	return "", false
}

func PutUint32BE(p []byte, n uint32) {
	C.nwep_put_uint32be((*C.uint8_t)(unsafe.Pointer(&p[0])), C.uint32_t(n))
}

func GetUint32BE(p []byte) uint32 {
	var n C.uint32_t
	C.nwep_get_uint32be(&n, (*C.uint8_t)(unsafe.Pointer(&p[0])))
	return uint32(n)
}

func PutUint16BE(p []byte, n uint16) {
	C.nwep_put_uint16be((*C.uint8_t)(unsafe.Pointer(&p[0])), C.uint16_t(n))
}

func GetUint16BE(p []byte) uint16 {
	var n C.uint16_t
	C.nwep_get_uint16be(&n, (*C.uint8_t)(unsafe.Pointer(&p[0])))
	return uint16(n)
}
