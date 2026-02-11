package nwep

/*
#include <nwep/nwep.h>
#include <string.h>
#include <stdlib.h>

extern void goLogCallback(nwep_log_entry *entry, void *user_data);
void cLogCallback(const nwep_log_entry *entry, void *ud);

// Non-variadic wrappers for cgo (defined in callbacks.c).
extern void nwep_log_write_str(nwep_log_level level, const uint8_t *trace_id,
                                const char *component, const char *msg);
extern void nwep_log_trace_str(const uint8_t *trace_id, const char *component,
                                const char *msg);
extern void nwep_log_debug_str(const uint8_t *trace_id, const char *component,
                                const char *msg);
extern void nwep_log_info_str(const uint8_t *trace_id, const char *component,
                               const char *msg);
extern void nwep_log_warn_str(const uint8_t *trace_id, const char *component,
                               const char *msg);
extern void nwep_log_error_str(const uint8_t *trace_id, const char *component,
                                const char *msg);
*/
import "C"

import (
	"sync"
	"unsafe"
)

type LogLevel int

const (
	LogTrace LogLevel = C.NWEP_LOG_TRACE
	LogDebug LogLevel = C.NWEP_LOG_DEBUG
	LogInfo  LogLevel = C.NWEP_LOG_INFO
	LogWarn  LogLevel = C.NWEP_LOG_WARN
	LogError LogLevel = C.NWEP_LOG_ERROR
)

type LogEntry struct {
	Level       LogLevel
	TimestampNS uint64
	TraceID     [16]byte
	Component   string
	Message     string
}

func LogLevelStr(level LogLevel) string {
	return C.GoString(C.nwep_log_level_str(C.nwep_log_level(level)))
}

func SetLogLevel(level LogLevel) {
	C.nwep_log_set_level(C.nwep_log_level(level))
}

func GetLogLevel() LogLevel {
	return LogLevel(C.nwep_log_get_level())
}

func SetLogJSON(enabled bool) {
	v := C.int(0)
	if enabled {
		v = 1
	}
	C.nwep_log_set_json(v)
}

func SetLogStderr(enabled bool) {
	v := C.int(0)
	if enabled {
		v = 1
	}
	C.nwep_log_set_stderr(v)
}

type LogCallback func(entry *LogEntry)

var (
	logCallbackMu   sync.Mutex
	globalLogCallback LogCallback
)

func SetLogCallback(cb LogCallback) {
	logCallbackMu.Lock()
	globalLogCallback = cb
	logCallbackMu.Unlock()

	if cb != nil {
		C.nwep_log_set_callback(C.nwep_log_callback(C.cLogCallback), nil)
	} else {
		C.nwep_log_set_callback(nil, nil)
	}
}

//export goLogCallback
func goLogCallback(entry *C.nwep_log_entry, userData unsafe.Pointer) {
	logCallbackMu.Lock()
	cb := globalLogCallback
	logCallbackMu.Unlock()

	if cb == nil {
		return
	}

	e := &LogEntry{
		Level:       LogLevel(entry.level),
		TimestampNS: uint64(entry.timestamp_ns),
	}
	C.memcpy(unsafe.Pointer(&e.TraceID[0]), unsafe.Pointer(&entry.trace_id[0]), 16)
	if entry.component != nil {
		e.Component = C.GoString(entry.component)
	}
	if entry.message != nil {
		e.Message = C.GoString(entry.message)
	}

	cb(e)
}

func WriteLog(level LogLevel, traceID [16]byte, component, msg string) {
	ccomp := C.CString(component)
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(ccomp))
	defer C.free(unsafe.Pointer(cmsg))
	C.nwep_log_write_str(C.nwep_log_level(level), (*C.uint8_t)(unsafe.Pointer(&traceID[0])), ccomp, cmsg)
}

func WriteTrace(traceID [16]byte, component, msg string) {
	ccomp := C.CString(component)
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(ccomp))
	defer C.free(unsafe.Pointer(cmsg))
	C.nwep_log_trace_str((*C.uint8_t)(unsafe.Pointer(&traceID[0])), ccomp, cmsg)
}

func WriteDebug(traceID [16]byte, component, msg string) {
	ccomp := C.CString(component)
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(ccomp))
	defer C.free(unsafe.Pointer(cmsg))
	C.nwep_log_debug_str((*C.uint8_t)(unsafe.Pointer(&traceID[0])), ccomp, cmsg)
}

func WriteInfo(traceID [16]byte, component, msg string) {
	ccomp := C.CString(component)
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(ccomp))
	defer C.free(unsafe.Pointer(cmsg))
	C.nwep_log_info_str((*C.uint8_t)(unsafe.Pointer(&traceID[0])), ccomp, cmsg)
}

func WriteWarn(traceID [16]byte, component, msg string) {
	ccomp := C.CString(component)
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(ccomp))
	defer C.free(unsafe.Pointer(cmsg))
	C.nwep_log_warn_str((*C.uint8_t)(unsafe.Pointer(&traceID[0])), ccomp, cmsg)
}

func WriteError(traceID [16]byte, component, msg string) {
	ccomp := C.CString(component)
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(ccomp))
	defer C.free(unsafe.Pointer(cmsg))
	C.nwep_log_error_str((*C.uint8_t)(unsafe.Pointer(&traceID[0])), ccomp, cmsg)
}

func LogFormatJSON(entry *LogEntry) string {
	var ce C.nwep_log_entry
	ce.level = C.nwep_log_level(entry.Level)
	ce.timestamp_ns = C.uint64_t(entry.TimestampNS)
	C.memcpy(unsafe.Pointer(&ce.trace_id[0]), unsafe.Pointer(&entry.TraceID[0]), 16)

	var ccomp, cmsg *C.char
	if entry.Component != "" {
		ccomp = C.CString(entry.Component)
		defer C.free(unsafe.Pointer(ccomp))
	}
	if entry.Message != "" {
		cmsg = C.CString(entry.Message)
		defer C.free(unsafe.Pointer(cmsg))
	}
	ce.component = ccomp
	ce.message = cmsg

	var buf [1024]C.char
	n := C.nwep_log_format_json((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &ce)
	return C.GoStringN((*C.char)(unsafe.Pointer(&buf[0])), C.int(n))
}
