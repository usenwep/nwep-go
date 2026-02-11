package nwep

/*
#include <nwep/nwep.h>
#include <stdlib.h>
*/
import "C"

import "unsafe"

const (
	MethodRead         = "read"
	MethodWrite        = "write"
	MethodUpdate       = "update"
	MethodDelete       = "delete"
	MethodConnect      = "connect"
	MethodAuthenticate = "authenticate"
	MethodHeartbeat    = "heartbeat"
)

const (
	StatusOK            = "ok"
	StatusCreated       = "created"
	StatusAccepted      = "accepted"
	StatusNoContent     = "no_content"
	StatusBadRequest    = "bad_request"
	StatusUnauthorized  = "unauthorized"
	StatusForbidden     = "forbidden"
	StatusNotFound      = "not_found"
	StatusConflict      = "conflict"
	StatusRateLimited   = "rate_limited"
	StatusInternalError = "internal_error"
	StatusUnavailable   = "unavailable"
)

const (
	HdrMethod          = ":method"
	HdrPath            = ":path"
	HdrVersion         = ":version"
	HdrStatus          = ":status"
	HdrRequestID       = "request-id"
	HdrClientID        = "client-id"
	HdrServerID        = "server-id"
	HdrChallenge       = "challenge"
	HdrChallengeResp   = "challenge-response"
	HdrServerChallenge = "server-challenge"
	HdrAuthResponse    = "auth-response"
	HdrMaxStreams      = "max-streams"
	HdrMaxMessageSize  = "max-message-size"
	HdrCompression     = "compression"
	HdrRoles           = "roles"
	HdrTranscriptSig   = "transcript-signature"
	HdrStatusDetails   = "status-details"
	HdrRetryAfter      = "retry-after"
	HdrTraceID         = "trace-id"
	HdrEvent           = ":event"
	HdrNotifyID        = "notify-id"
)

func MethodIsValid(method string) bool {
	cs := C.CString(method)
	defer C.free(unsafe.Pointer(cs))
	return C.nwep_method_is_valid(cs) != 0
}

// MethodIsIdempotent returns true for read, delete, and heartbeat.
func MethodIsIdempotent(method string) bool {
	cs := C.CString(method)
	defer C.free(unsafe.Pointer(cs))
	return C.nwep_method_is_idempotent(cs) != 0
}

// MethodAllowed0RTT returns true only for read.
func MethodAllowed0RTT(method string) bool {
	cs := C.CString(method)
	defer C.free(unsafe.Pointer(cs))
	return C.nwep_method_allowed_0rtt(cs) != 0
}

func StatusIsValid(status string) bool {
	cs := C.CString(status)
	defer C.free(unsafe.Pointer(cs))
	return C.nwep_status_is_valid(cs) != 0
}

func StatusIsSuccess(status string) bool {
	cs := C.CString(status)
	defer C.free(unsafe.Pointer(cs))
	return C.nwep_status_is_success(cs) != 0
}

func StatusIsError(status string) bool {
	cs := C.CString(status)
	defer C.free(unsafe.Pointer(cs))
	return C.nwep_status_is_error(cs) != 0
}

func TraceIDGenerate() ([16]byte, error) {
	var id [16]byte
	rv := C.nwep_trace_id_generate((*C.uint8_t)(unsafe.Pointer(&id[0])))
	if err := errorFromCode(int(rv)); err != nil {
		return [16]byte{}, err
	}
	return id, nil
}

func RequestIDGenerate() ([16]byte, error) {
	var id [16]byte
	rv := C.nwep_request_id_generate((*C.uint8_t)(unsafe.Pointer(&id[0])))
	if err := errorFromCode(int(rv)); err != nil {
		return [16]byte{}, err
	}
	return id, nil
}
