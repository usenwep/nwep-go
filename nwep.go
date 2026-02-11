package nwep

/*
#cgo CFLAGS: -I${SRCDIR}/third_party/nwep/current/include -DNWEP_STATICLIB
#cgo LDFLAGS: -L${SRCDIR}/third_party/nwep/current/lib -lnwep_packed
#cgo linux LDFLAGS: -lpthread -ldl
#cgo darwin LDFLAGS: -lpthread -ldl
#cgo windows LDFLAGS: -lws2_32
#include <nwep/nwep.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import "time"

type Tstamp = uint64
type Duration = uint64

const (
	Nanoseconds  Duration = 1
	Microseconds Duration = 1000 * Nanoseconds
	Milliseconds Duration = 1000 * Microseconds
	Seconds      Duration = 1000 * Milliseconds
)

const (
	ProtoVer    = "WEB/1"
	ALPN        = "WEB/1"
	ALPNLen     = 5
	DefaultPort = 4433
)

const (
	DefaultMaxMessageSize = 25165824
	MaxHeaders            = 128
	MaxHeaderSize         = 8192
	DefaultMaxStreams     = 100
	DefaultTimeout        = 30 * Seconds
)

const (
	Ed25519PubkeyLen  = 32
	Ed25519PrivkeyLen = 32
	Ed25519SigLen     = 64
	NodeIDLen         = 32
	ChallengeLen      = 32
	RequestIDLen      = 16
	TraceIDLen        = 16
	NotifyIDLen       = 16
)

const (
	Base58AddrLen = C.NWEP_BASE58_ADDR_LEN
	URLMaxLen     = C.NWEP_URL_MAX_LEN
)

// Init must be called before any other nwep functions.
func Init() error {
	rv := C.nwep_init()
	return errorFromCode(int(rv))
}

func Version() string {
	return C.GoString(C.nwep_version())
}

func nowNanos() uint64 {
	return uint64(time.Now().UnixNano())
}
