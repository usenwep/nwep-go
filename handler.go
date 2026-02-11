package nwep

/*
#include <nwep/nwep.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"sync"
	"unsafe"
)

type Handler interface {
	ServeNWEP(w *ResponseWriter, r *Request)
}

// HandlerFunc is an adapter to allow the use of ordinary functions as handlers.
type HandlerFunc func(w *ResponseWriter, r *Request)

func (f HandlerFunc) ServeNWEP(w *ResponseWriter, r *Request) {
	f(w, r)
}

type Request struct {
	Method    string
	Path      string
	Body      []byte
	RequestID [16]byte
	TraceID   [16]byte
	headers   []Header
	Conn      *Conn
}

func (r *Request) Header(name string) (string, bool) {
	for _, h := range r.headers {
		if h.Name == name {
			return h.Value, true
		}
	}
	return "", false
}

func (r *Request) Headers() []Header {
	return r.headers
}

// requestFromC builds a Request from C types. Copies all data so the
// C memory can be reused after the callback returns.
func requestFromC(creq *C.nwep_request, conn *Conn) *Request {
	r := &Request{
		Conn: conn,
	}
	if creq.method != nil {
		r.Method = C.GoStringN(creq.method, C.int(creq.method_len))
	}
	if creq.path != nil {
		r.Path = C.GoStringN(creq.path, C.int(creq.path_len))
	}
	if creq.body != nil && creq.body_len > 0 {
		r.Body = C.GoBytes(unsafe.Pointer(creq.body), C.int(creq.body_len))
	}
	C.memcpy(unsafe.Pointer(&r.RequestID[0]), unsafe.Pointer(&creq.request_id[0]), 16)
	C.memcpy(unsafe.Pointer(&r.TraceID[0]), unsafe.Pointer(&creq.trace_id[0]), 16)
	for i := C.size_t(0); i < creq.header_count; i++ {
		hdr := (*C.nwep_header)(unsafe.Pointer(uintptr(unsafe.Pointer(creq.headers)) + uintptr(i)*unsafe.Sizeof(C.nwep_header{})))
		r.headers = append(r.headers, Header{
			Name:  C.GoStringN((*C.char)(unsafe.Pointer(hdr.name)), C.int(hdr.name_len)),
			Value: C.GoStringN((*C.char)(unsafe.Pointer(hdr.value)), C.int(hdr.value_len)),
		})
	}
	return r
}

// ResponseWriter wraps a C nwep_stream for writing responses.
type ResponseWriter struct {
	stream  *C.nwep_stream
	status  string
	headers []Header
	sent    bool
	mu      sync.Mutex
}

func (w *ResponseWriter) SetStatus(status string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status = status
}

func (w *ResponseWriter) SetHeader(name, value string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.headers = append(w.headers, Header{Name: name, Value: value})
}

// Write sends a response with the previously set status and headers, plus body.
// If no status was set, uses "ok". Can only be called once.
func (w *ResponseWriter) Write(body []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.sent {
		return nil
	}
	w.sent = true

	status := w.status
	if status == "" {
		status = "ok"
	}
	return w.sendLocked(status, body)
}

// Respond sends a complete response with the given status and body in one call.
func (w *ResponseWriter) Respond(status string, body []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.sent {
		return nil
	}
	w.sent = true
	return w.sendLocked(status, body)
}

func (w *ResponseWriter) sendLocked(status string, body []byte) error {
	var resp C.nwep_response
	cstatus := C.CString(status)
	defer C.free(unsafe.Pointer(cstatus))
	resp.status = cstatus
	resp.status_len = C.size_t(len(status))

	// Build C headers
	var cheaders []C.nwep_header
	var cstrs []unsafe.Pointer
	for _, h := range w.headers {
		var ch C.nwep_header
		cname := C.CString(h.Name)
		cval := C.CString(h.Value)
		cstrs = append(cstrs, unsafe.Pointer(cname), unsafe.Pointer(cval))
		ch.name = (*C.uint8_t)(unsafe.Pointer(cname))
		ch.name_len = C.size_t(len(h.Name))
		ch.value = (*C.uint8_t)(unsafe.Pointer(cval))
		ch.value_len = C.size_t(len(h.Value))
		cheaders = append(cheaders, ch)
	}
	defer func() {
		for _, p := range cstrs {
			C.free(p)
		}
	}()

	if len(cheaders) > 0 {
		// Allocate headers array in C memory to avoid cgo "Go pointer to Go pointer" panic.
		hdrSize := C.size_t(len(cheaders)) * C.size_t(unsafe.Sizeof(C.nwep_header{}))
		chdrs := (*C.nwep_header)(C.malloc(hdrSize))
		defer C.free(unsafe.Pointer(chdrs))
		C.memcpy(unsafe.Pointer(chdrs), unsafe.Pointer(&cheaders[0]), hdrSize)
		resp.headers = chdrs
		resp.header_count = C.size_t(len(cheaders))
	}
	if len(body) > 0 {
		// Copy body to C memory to avoid cgo "Go pointer to Go pointer" panic.
		cbody := C.CBytes(body)
		defer C.free(cbody)
		resp.body = (*C.uint8_t)(cbody)
		resp.body_len = C.size_t(len(body))
	}

	rv := C.nwep_stream_respond(w.stream, &resp)
	if err := errorFromCode(int(rv)); err != nil {
		return err
	}
	rv = C.nwep_stream_end(w.stream)
	return errorFromCode(int(rv))
}

// StreamWrite writes body data to the stream without ending it.
func (w *ResponseWriter) StreamWrite(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	n := C.nwep_stream_write(w.stream, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if n < 0 {
		return 0, errorFromCode(int(n))
	}
	return int(n), nil
}

// StreamClose sends a RESET to close the stream with an error code.
func (w *ResponseWriter) StreamClose(errCode int) {
	C.nwep_stream_close(w.stream, C.int(errCode))
}

func (w *ResponseWriter) StreamID() int64 {
	return int64(C.nwep_stream_get_id(w.stream))
}

func (w *ResponseWriter) StreamUserData() unsafe.Pointer {
	return C.nwep_stream_get_user_data(w.stream)
}

func (w *ResponseWriter) SetStreamUserData(data unsafe.Pointer) {
	C.nwep_stream_set_user_data(w.stream, data)
}

func (w *ResponseWriter) StreamGetConn() *C.nwep_conn {
	return C.nwep_stream_get_conn(w.stream)
}

func (w *ResponseWriter) IsServerInitiated() bool {
	return C.nwep_stream_is_server_initiated(w.stream) != 0
}

// sendDefault sends a 404 if the handler didn't write anything.
func (w *ResponseWriter) sendDefault() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.sent {
		return
	}
	w.sent = true
	w.sendLocked("not_found", nil)
}

type prefixRoute struct {
	prefix  string
	handler Handler
}

// Router dispatches requests by path, supporting exact and prefix matches.
type Router struct {
	mu       sync.RWMutex
	routes   map[string]Handler
	prefixes []prefixRoute
}

func NewRouter() *Router {
	return &Router{routes: make(map[string]Handler)}
}

func (r *Router) Handle(path string, h Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes[path] = h
}

func (r *Router) HandleFunc(path string, fn func(*ResponseWriter, *Request)) {
	r.Handle(path, HandlerFunc(fn))
}

// HandlePrefix registers a handler for all paths starting with prefix.
func (r *Router) HandlePrefix(prefix string, h Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prefixes = append(r.prefixes, prefixRoute{prefix: prefix, handler: h})
}

func (r *Router) ServeNWEP(w *ResponseWriter, req *Request) {
	r.mu.RLock()
	h, ok := r.routes[req.Path]
	if !ok {
		bestLen := 0
		for _, pr := range r.prefixes {
			if len(pr.prefix) > bestLen && len(req.Path) >= len(pr.prefix) && req.Path[:len(pr.prefix)] == pr.prefix {
				if len(req.Path) == len(pr.prefix) || req.Path[len(pr.prefix)] == '/' {
					h = pr.handler
					bestLen = len(pr.prefix)
					ok = true
				}
			}
		}
	}
	r.mu.RUnlock()
	if ok {
		h.ServeNWEP(w, req)
	} else {
		w.Respond("not_found", nil)
	}
}
