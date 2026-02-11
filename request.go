package nwep

/*
#include <nwep/nwep.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import "unsafe"

type CRequest struct {
	Method    string
	Path      string
	Headers   []Header
	Body      []byte
	RequestID [16]byte
	TraceID   [16]byte
}

type CResponse struct {
	Status        string
	StatusDetails string
	Headers       []Header
	Body          []byte
}

type CNotify struct {
	Event       string
	Path        string
	NotifyID    [16]byte
	HasNotifyID bool
	Headers     []Header
	Body        []byte
}

func RequestBuild(method, path string, body []byte) (*Msg, error) {
	var cmsg C.nwep_msg
	var cheaders [MaxHeaders]C.nwep_header
	cmethod := C.CString(method)
	defer C.free(unsafe.Pointer(cmethod))
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	var bodyPtr *C.uint8_t
	if len(body) > 0 {
		bodyPtr = (*C.uint8_t)(unsafe.Pointer(&body[0]))
	}

	rv := C.nwep_request_build(&cmsg, &cheaders[0], C.size_t(MaxHeaders),
		cmethod, cpath, bodyPtr, C.size_t(len(body)))
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}

	return msgFromC(&cmsg, &cheaders), nil
}

func ResponseBuild(status, statusDetails string, body []byte) (*Msg, error) {
	var cmsg C.nwep_msg
	var cheaders [MaxHeaders]C.nwep_header
	cstatus := C.CString(status)
	defer C.free(unsafe.Pointer(cstatus))

	var cdetails *C.char
	if statusDetails != "" {
		cdetails = C.CString(statusDetails)
		defer C.free(unsafe.Pointer(cdetails))
	}

	var bodyPtr *C.uint8_t
	if len(body) > 0 {
		bodyPtr = (*C.uint8_t)(unsafe.Pointer(&body[0]))
	}

	rv := C.nwep_response_build(&cmsg, &cheaders[0], C.size_t(MaxHeaders),
		cstatus, cdetails, bodyPtr, C.size_t(len(body)))
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}

	return msgFromC(&cmsg, &cheaders), nil
}

func HeartbeatBuild() (*Msg, error) {
	var cmsg C.nwep_msg
	var cheaders [MaxHeaders]C.nwep_header
	rv := C.nwep_heartbeat_build(&cmsg, &cheaders[0], C.size_t(MaxHeaders))
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return msgFromC(&cmsg, &cheaders), nil
}

func HeartbeatResponseBuild() (*Msg, error) {
	var cmsg C.nwep_msg
	var cheaders [MaxHeaders]C.nwep_header
	rv := C.nwep_heartbeat_response_build(&cmsg, &cheaders[0], C.size_t(MaxHeaders))
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return msgFromC(&cmsg, &cheaders), nil
}

func StreamMsgBuild(data []byte, isFinal bool) (*Msg, error) {
	var cmsg C.nwep_msg
	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	fin := C.int(0)
	if isFinal {
		fin = 1
	}
	rv := C.nwep_stream_msg_build(&cmsg, dataPtr, C.size_t(len(data)), fin)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	msg := &Msg{Type: uint8(cmsg._type)}
	if cmsg.body != nil && cmsg.body_len > 0 {
		msg.Body = C.GoBytes(unsafe.Pointer(cmsg.body), C.int(cmsg.body_len))
	}
	return msg, nil
}

func NotifyBuild(event, path string, notifyID []byte, body []byte) (*Msg, error) {
	var cmsg C.nwep_msg
	var cheaders [MaxHeaders]C.nwep_header
	cevent := C.CString(event)
	defer C.free(unsafe.Pointer(cevent))
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	var nidPtr *C.uint8_t
	if len(notifyID) > 0 {
		nidPtr = (*C.uint8_t)(unsafe.Pointer(&notifyID[0]))
	}

	var bodyPtr *C.uint8_t
	if len(body) > 0 {
		bodyPtr = (*C.uint8_t)(unsafe.Pointer(&body[0]))
	}

	rv := C.nwep_notify_build(&cmsg, &cheaders[0], C.size_t(MaxHeaders),
		cevent, cpath, nidPtr, bodyPtr, C.size_t(len(body)))
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return msgFromC(&cmsg, &cheaders), nil
}

func RequestParse(msg *Msg) (*CRequest, error) {
	cmsg, cheaders, cleanup := msgToC(msg)
	defer cleanup()

	var creq C.nwep_request
	rv := C.nwep_request_parse(&creq, &cmsg)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	_ = cheaders

	req := &CRequest{
		Method: C.GoStringN(creq.method, C.int(creq.method_len)),
		Path:   C.GoStringN(creq.path, C.int(creq.path_len)),
	}
	C.memcpy(unsafe.Pointer(&req.RequestID[0]), unsafe.Pointer(&creq.request_id[0]), 16)
	C.memcpy(unsafe.Pointer(&req.TraceID[0]), unsafe.Pointer(&creq.trace_id[0]), 16)

	for i := 0; i < int(creq.header_count); i++ {
		ch := (*[1 << 20]C.nwep_header)(unsafe.Pointer(creq.headers))[i]
		req.Headers = append(req.Headers, Header{
			Name:  C.GoStringN((*C.char)(unsafe.Pointer(ch.name)), C.int(ch.name_len)),
			Value: C.GoStringN((*C.char)(unsafe.Pointer(ch.value)), C.int(ch.value_len)),
		})
	}

	if creq.body != nil && creq.body_len > 0 {
		req.Body = C.GoBytes(unsafe.Pointer(creq.body), C.int(creq.body_len))
	}

	return req, nil
}

func ResponseParse(msg *Msg) (*CResponse, error) {
	cmsg, cheaders, cleanup := msgToC(msg)
	defer cleanup()

	var cresp C.nwep_response
	rv := C.nwep_response_parse(&cresp, &cmsg)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	_ = cheaders

	resp := &CResponse{
		Status: C.GoStringN(cresp.status, C.int(cresp.status_len)),
	}
	if cresp.status_details != nil && cresp.status_details_len > 0 {
		resp.StatusDetails = C.GoStringN(cresp.status_details, C.int(cresp.status_details_len))
	}

	for i := 0; i < int(cresp.header_count); i++ {
		ch := (*[1 << 20]C.nwep_header)(unsafe.Pointer(cresp.headers))[i]
		resp.Headers = append(resp.Headers, Header{
			Name:  C.GoStringN((*C.char)(unsafe.Pointer(ch.name)), C.int(ch.name_len)),
			Value: C.GoStringN((*C.char)(unsafe.Pointer(ch.value)), C.int(ch.value_len)),
		})
	}

	if cresp.body != nil && cresp.body_len > 0 {
		resp.Body = C.GoBytes(unsafe.Pointer(cresp.body), C.int(cresp.body_len))
	}

	return resp, nil
}

func NotifyParse(msg *Msg) (*CNotify, error) {
	cmsg, cheaders, cleanup := msgToC(msg)
	defer cleanup()

	var cnotify C.nwep_notify
	rv := C.nwep_notify_parse(&cnotify, &cmsg)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	_ = cheaders

	notify := &CNotify{
		Event:       C.GoStringN(cnotify.event, C.int(cnotify.event_len)),
		Path:        C.GoStringN(cnotify.path, C.int(cnotify.path_len)),
		HasNotifyID: cnotify.has_notify_id != 0,
	}
	if notify.HasNotifyID {
		C.memcpy(unsafe.Pointer(&notify.NotifyID[0]), unsafe.Pointer(&cnotify.notify_id[0]), 16)
	}

	for i := 0; i < int(cnotify.header_count); i++ {
		ch := (*[1 << 20]C.nwep_header)(unsafe.Pointer(cnotify.headers))[i]
		notify.Headers = append(notify.Headers, Header{
			Name:  C.GoStringN((*C.char)(unsafe.Pointer(ch.name)), C.int(ch.name_len)),
			Value: C.GoStringN((*C.char)(unsafe.Pointer(ch.value)), C.int(ch.value_len)),
		})
	}

	if cnotify.body != nil && cnotify.body_len > 0 {
		notify.Body = C.GoBytes(unsafe.Pointer(cnotify.body), C.int(cnotify.body_len))
	}

	return notify, nil
}

func msgFromC(cmsg *C.nwep_msg, cheaders *[MaxHeaders]C.nwep_header) *Msg {
	msg := &Msg{Type: uint8(cmsg._type)}
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
	return msg
}

// msgToC converts a Go Msg to C, returning the msg, headers, and a cleanup func for C strings.
func msgToC(msg *Msg) (C.nwep_msg, []C.nwep_header, func()) {
	var cmsg C.nwep_msg
	C.nwep_msg_init(&cmsg, C.uint8_t(msg.Type))

	cheaders := make([]C.nwep_header, len(msg.Headers))
	var cstrings []unsafe.Pointer

	for i, h := range msg.Headers {
		cn := C.CString(h.Name)
		cv := C.CString(h.Value)
		cstrings = append(cstrings, unsafe.Pointer(cn), unsafe.Pointer(cv))
		C.nwep_header_set(&cheaders[i], cn, cv)
	}

	if len(cheaders) > 0 {
		cmsg.headers = &cheaders[0]
	}
	cmsg.header_count = C.size_t(len(cheaders))

	if len(msg.Body) > 0 {
		cmsg.body = (*C.uint8_t)(unsafe.Pointer(&msg.Body[0]))
		cmsg.body_len = C.size_t(len(msg.Body))
	}

	cleanup := func() {
		for _, p := range cstrings {
			C.free(p)
		}
	}

	return cmsg, cheaders, cleanup
}
