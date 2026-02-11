package nwep

/*
#include <nwep/nwep.h>
#include <stdlib.h>
#include <string.h>

// Shim functions defined in callbacks.c (cast away const for cgo exports).
extern int cClientOnConnect(nwep_conn *conn, const nwep_identity *peer, void *ud);
extern void cClientOnDisconnect(nwep_conn *conn, int error, void *ud);
extern int cClientOnResponse(nwep_conn *conn, nwep_stream *stream, const nwep_response *resp, void *ud);
extern int cClientOnNotify(nwep_conn *conn, nwep_stream *stream, const nwep_notify *notify, void *ud);
extern int cClientOnStreamData(nwep_conn *conn, nwep_stream *stream, const uint8_t *data, size_t len, void *ud);
extern int cClientOnStreamEnd(nwep_conn *conn, nwep_stream *stream, void *ud);
extern int cClientRand(uint8_t *dest, size_t len, void *ud);
extern void* handle_to_ptr(uintptr_t h);
*/
import "C"

import (
	"fmt"
	"net"
	"runtime/cgo"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type ClientOption func(*Client)

func WithOnNotify(fn func(*Notification)) ClientOption {
	return func(c *Client) { c.onNotify = fn }
}

func WithClientSettings(s Settings) ClientOption {
	return func(c *Client) { c.userSettings = &s }
}

type Response struct {
	Status        string
	StatusDetails string
	Headers       []Header
	Body          []byte
}

func (r *Response) Header(name string) (string, bool) {
	for _, h := range r.Headers {
		if h.Name == name {
			return h.Value, true
		}
	}
	return "", false
}

func (r *Response) IsOK() bool {
	return r.Status == "ok"
}

type Notification struct {
	Event   string
	Path    string
	Headers []Header
	Body    []byte
}

type clientEvent struct {
	kind int
	pkt  []byte
	addr *net.UDPAddr
	req  *requestEvent
}

const (
	cevPacket   = 0
	cevTimer    = 1
	cevShutdown = 2
	cevRequest  = 3
)

type requestEvent struct {
	creq    C.nwep_request
	cleanup func()
	pending *pendingRequest
}

type pendingRequest struct {
	done    chan struct{}
	resp    *Response
	err     error
	bodyBuf []byte
}

type Client struct {
	cclient   *C.nwep_client
	keypair   *Keypair
	conn      *net.UDPConn
	nodeID    NodeID
	parsedURL C.nwep_url
	raddr     *net.UDPAddr
	handle    cgo.Handle

	mu          sync.Mutex
	pendingReqs map[int64]*pendingRequest
	onNotify    func(*Notification)

	userSettings *Settings

	events    chan clientEvent
	connected chan struct{}
	connErr   error
	shutdown  chan struct{}
	done      chan struct{}
}

func NewClient(keypair *Keypair, opts ...ClientOption) (*Client, error) {
	c := &Client{
		keypair:     keypair,
		pendingReqs: make(map[int64]*pendingRequest),
		events:      make(chan clientEvent, 256),
		connected:   make(chan struct{}),
		shutdown:    make(chan struct{}),
		done:        make(chan struct{}),
	}
	for _, opt := range opts {
		opt(c)
	}

	nid, err := keypair.NodeID()
	if err != nil {
		return nil, fmt.Errorf("nwep: compute node id: %w", err)
	}
	c.nodeID = nid

	// Configure settings
	var settings C.nwep_settings
	C.nwep_settings_default(&settings)
	if c.userSettings != nil {
		if c.userSettings.MaxStreams > 0 {
			settings.max_streams = C.uint32_t(c.userSettings.MaxStreams)
		}
		if c.userSettings.MaxMessageSize > 0 {
			settings.max_message_size = C.uint32_t(c.userSettings.MaxMessageSize)
		}
		if c.userSettings.TimeoutMs > 0 {
			settings.timeout_ms = C.uint32_t(c.userSettings.TimeoutMs)
		}
	}

	// Set up callbacks
	var callbacks C.nwep_callbacks
	callbacks.on_connect = C.nwep_on_connect(C.cClientOnConnect)
	callbacks.on_disconnect = C.nwep_on_disconnect(C.cClientOnDisconnect)
	callbacks.on_response = C.nwep_on_response(C.cClientOnResponse)
	callbacks.on_notify = C.nwep_on_notify(C.cClientOnNotify)
	callbacks.on_stream_data = C.nwep_on_stream_data(C.cClientOnStreamData)
	callbacks.on_stream_end = C.nwep_on_stream_end(C.cClientOnStreamEnd)
	callbacks.rand = C.nwep_rand(C.cClientRand)

	// cgo.Handle for callback dispatch
	c.handle = cgo.NewHandle(c)

	// Create C client with handle as user_data
	var cclient *C.nwep_client
	rv := C.nwep_client_new(&cclient, &settings, &callbacks, &keypair.c, C.handle_to_ptr(C.uintptr_t(c.handle)))
	if err := errorFromCode(int(rv)); err != nil {
		c.handle.Delete()
		return nil, fmt.Errorf("nwep: client new: %w", err)
	}
	c.cclient = cclient

	return c, nil
}

// Connect initiates a connection to the given web:// URL and blocks until
// the handshake completes or an error occurs.
func (c *Client) Connect(url string) error {
	curl := C.CString(url)
	defer C.free(unsafe.Pointer(curl))
	rv := C.nwep_url_parse(&c.parsedURL, curl)
	if err := errorFromCode(int(rv)); err != nil {
		return fmt.Errorf("nwep: url parse: %w", err)
	}

	c.raddr = addrToUDP(&c.parsedURL.addr)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return fmt.Errorf("nwep: listen udp: %w", err)
	}
	c.conn = udpConn

	laddr := udpConn.LocalAddr().(*net.UDPAddr)
	var lsa C.struct_sockaddr_storage
	var lsaLen C.size_t
	fillClientSockaddr(&lsa, &lsaLen, laddr)

	// nwep_client_connect queues initial handshake packets.
	ts := C.nwep_tstamp(nowNanos())
	rv = C.nwep_client_connect(c.cclient, &c.parsedURL,
		(*C.struct_sockaddr)(unsafe.Pointer(&lsa)), lsaLen, ts)
	if err := errorFromCode(int(rv)); err != nil {
		udpConn.Close()
		return fmt.Errorf("nwep: client connect: %w", err)
	}

	// Start protocol goroutine -- ALL subsequent C calls happen there.
	go c.run()

	select {
	case <-c.connected:
		return c.connErr
	case <-c.done:
		if c.connErr != nil {
			return c.connErr
		}
		return fmt.Errorf("nwep: connection closed before handshake completed")
	}
}

func (c *Client) Close() error {
	select {
	case c.events <- clientEvent{kind: cevShutdown}:
	case <-c.done:
		return nil
	}
	<-c.done
	return nil
}

func (c *Client) NodeID() NodeID {
	return c.nodeID
}

// Must only be called after Connect returns successfully.
func (c *Client) PeerIdentity() (Identity, error) {
	conn := C.nwep_client_get_conn(c.cclient)
	if conn == nil {
		return Identity{}, fmt.Errorf("nwep: not connected")
	}
	peer := C.nwep_conn_get_peer_identity(conn)
	if peer == nil {
		return Identity{}, fmt.Errorf("nwep: no peer identity")
	}
	return identityFromC(peer), nil
}

func (c *Client) PeerNodeID() (NodeID, error) {
	id, err := c.PeerIdentity()
	if err != nil {
		return NodeID{}, err
	}
	return id.NodeID, nil
}

func (c *Client) FetchWithHeaders(method, path string, body []byte, headers []Header) (*Response, error) {
	var creq C.nwep_request
	var allocs []unsafe.Pointer

	cmethod := C.CString(method)
	allocs = append(allocs, unsafe.Pointer(cmethod))
	creq.method = cmethod
	creq.method_len = C.size_t(len(method))

	cpath := C.CString(path)
	allocs = append(allocs, unsafe.Pointer(cpath))
	creq.path = cpath
	creq.path_len = C.size_t(len(path))

	if len(body) > 0 {
		cbody := C.CBytes(body)
		allocs = append(allocs, cbody)
		creq.body = (*C.uint8_t)(cbody)
		creq.body_len = C.size_t(len(body))
	}

	var reqID [16]byte
	cryptoRand(reqID[:])
	C.memcpy(unsafe.Pointer(&creq.request_id[0]), unsafe.Pointer(&reqID[0]), 16)

	// Allocate headers in C memory to avoid cgo pointer panic.
	if len(headers) > 0 {
		cheaders := make([]C.nwep_header, len(headers))
		for i, h := range headers {
			cname := C.CString(h.Name)
			cval := C.CString(h.Value)
			allocs = append(allocs, unsafe.Pointer(cname), unsafe.Pointer(cval))
			cheaders[i].name = (*C.uint8_t)(unsafe.Pointer(cname))
			cheaders[i].name_len = C.size_t(len(h.Name))
			cheaders[i].value = (*C.uint8_t)(unsafe.Pointer(cval))
			cheaders[i].value_len = C.size_t(len(h.Value))
		}
		// Copy to C memory so nwep_request doesn't hold Go pointers.
		hdrSize := C.size_t(len(cheaders)) * C.size_t(unsafe.Sizeof(C.nwep_header{}))
		chdrs := (*C.nwep_header)(C.malloc(hdrSize))
		allocs = append(allocs, unsafe.Pointer(chdrs))
		C.memcpy(unsafe.Pointer(chdrs), unsafe.Pointer(&cheaders[0]), hdrSize)
		creq.headers = chdrs
		creq.header_count = C.size_t(len(cheaders))
	}

	cleanup := func() {
		for _, p := range allocs {
			C.free(p)
		}
	}

	pending := &pendingRequest{
		done: make(chan struct{}),
	}

	rev := &requestEvent{
		creq:    creq,
		cleanup: cleanup,
		pending: pending,
	}

	select {
	case c.events <- clientEvent{kind: cevRequest, req: rev}:
	case <-c.done:
		cleanup()
		return nil, fmt.Errorf("nwep: client closed")
	}

	timeout := 30 * time.Second
	if c.userSettings != nil && c.userSettings.TimeoutMs > 0 {
		timeout = time.Duration(c.userSettings.TimeoutMs) * time.Millisecond
	}

	select {
	case <-pending.done:
		if pending.err != nil {
			return nil, pending.err
		}
		if pending.resp == nil {
			return nil, fmt.Errorf("nwep: no response received")
		}
		return pending.resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("nwep: request timed out")
	case <-c.done:
		return nil, fmt.Errorf("nwep: client closed")
	}
}

func (c *Client) Fetch(method, path string, body []byte) (*Response, error) {
	return c.FetchWithHeaders(method, path, body, nil)
}

func (c *Client) Get(path string) (*Response, error) {
	return c.Fetch("read", path, nil)
}

func (c *Client) Post(path string, body []byte) (*Response, error) {
	return c.Fetch("write", path, body)
}

// Protocol goroutine event loop. All C library calls happen here.
func (c *Client) run() {
	defer close(c.done)
	raddr := c.raddr

	// Drain initial handshake writes queued by nwep_client_connect
	c.drainWritesTo(raddr)

	// Reader goroutine
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := c.conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-c.shutdown:
					return
				default:
					continue
				}
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			c.events <- clientEvent{kind: cevPacket, pkt: pkt, addr: addr}
		}
	}()

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	resetTimer := func() {
		expiry := C.nwep_client_get_expiry(c.cclient)
		if expiry == C.UINT64_MAX {
			return
		}
		now := nowNanos()
		var delay time.Duration
		if uint64(expiry) > now {
			delay = time.Duration(uint64(expiry)-now) * time.Nanosecond
		} else {
			delay = time.Millisecond
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(delay)
	}

	resetTimer()

	for {
		select {
		case ev := <-c.events:
			switch ev.kind {
			case cevPacket:
				c.handlePacket(ev.pkt, ev.addr)
				c.drainWritesTo(raddr)
				resetTimer()

			case cevTimer:
				ts := C.nwep_tstamp(nowNanos())
				C.nwep_client_handle_expiry(c.cclient, ts)
				c.drainWritesTo(raddr)
				resetTimer()

			case cevRequest:
				c.handleRequest(ev.req, raddr)
				c.drainWritesTo(raddr)
				resetTimer()

			case cevShutdown:
				C.nwep_client_close(c.cclient)
				c.drainWritesTo(raddr)
				c.conn.Close()
				close(c.shutdown)
				C.nwep_client_free(c.cclient)
				c.handle.Delete()
				// Fail any pending requests
				c.mu.Lock()
				for _, p := range c.pendingReqs {
					p.err = fmt.Errorf("nwep: client closed")
					close(p.done)
				}
				c.pendingReqs = nil
				c.mu.Unlock()
				return
			}

		case <-timer.C:
			ts := C.nwep_tstamp(nowNanos())
			C.nwep_client_handle_expiry(c.cclient, ts)
			c.drainWritesTo(raddr)
			resetTimer()
		}
	}
}

func (c *Client) handlePacket(data []byte, raddr *net.UDPAddr) {
	laddr := c.conn.LocalAddr().(*net.UDPAddr)

	var path C.nwep_path
	fillClientPath(&path, laddr, raddr)

	ts := C.nwep_tstamp(nowNanos())
	C.nwep_client_read(c.cclient, &path, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)), ts)
}

func (c *Client) handleRequest(rev *requestEvent, raddr *net.UDPAddr) {
	defer rev.cleanup()

	conn := C.nwep_client_get_conn(c.cclient)
	if conn == nil {
		rev.pending.err = fmt.Errorf("nwep: not connected")
		close(rev.pending.done)
		return
	}

	var stream *C.nwep_stream
	rv := C.nwep_stream_request(conn, &rev.creq, &stream)
	if err := errorFromCode(int(rv)); err != nil {
		rev.pending.err = err
		close(rev.pending.done)
		return
	}

	sid := int64(C.nwep_stream_get_id(stream))
	c.mu.Lock()
	c.pendingReqs[sid] = rev.pending
	c.mu.Unlock()

	C.nwep_stream_end(stream)
}

func (c *Client) drainWritesTo(raddr *net.UDPAddr) {
	var path C.nwep_path
	var buf [1500]byte

	for {
		ts := C.nwep_tstamp(nowNanos())
		n := C.nwep_client_write(c.cclient, &path, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), ts)
		if n <= 0 {
			break
		}
		dest := sockaddrToUDP(&path.remote_addr, path.remote_addrlen)
		if dest == nil {
			dest = raddr
		}
		c.conn.WriteToUDP(buf[:int(n)], dest)
	}
}

// Callback exports using cgo.Handle dispatch.

//export goClientOnConnect
func goClientOnConnect(conn *C.nwep_conn, peer *C.nwep_identity, userData unsafe.Pointer) C.int {
	cl := cgo.Handle(userData).Value().(*Client)

	// Signal that the handshake has completed
	select {
	case <-cl.connected:
	default:
		close(cl.connected)
	}
	return 0
}

//export goClientOnDisconnect
func goClientOnDisconnect(conn *C.nwep_conn, errCode C.int, userData unsafe.Pointer) {
	cl := cgo.Handle(userData).Value().(*Client)

	// Signal connection error if not yet connected
	select {
	case <-cl.connected:
	default:
		if errCode != 0 {
			cl.connErr = errorFromCode(int(errCode))
		} else {
			cl.connErr = fmt.Errorf("nwep: disconnected")
		}
		close(cl.connected)
	}

	// Fail all pending requests
	cl.mu.Lock()
	for sid, p := range cl.pendingReqs {
		p.err = fmt.Errorf("nwep: disconnected (code %d)", int(errCode))
		close(p.done)
		delete(cl.pendingReqs, sid)
	}
	cl.mu.Unlock()
}

//export goClientOnResponse
func goClientOnResponse(conn *C.nwep_conn, stream *C.nwep_stream, resp *C.nwep_response, userData unsafe.Pointer) C.int {
	cl := cgo.Handle(userData).Value().(*Client)

	sid := int64(C.nwep_stream_get_id(stream))
	cl.mu.Lock()
	p, ok := cl.pendingReqs[sid]
	cl.mu.Unlock()
	if !ok {
		return 0
	}

	r := &Response{}
	if resp.status != nil {
		r.Status = C.GoStringN(resp.status, C.int(resp.status_len))
	}
	if resp.status_details != nil {
		r.StatusDetails = C.GoStringN(resp.status_details, C.int(resp.status_details_len))
	}
	for i := C.size_t(0); i < resp.header_count; i++ {
		hdr := (*C.nwep_header)(unsafe.Pointer(uintptr(unsafe.Pointer(resp.headers)) + uintptr(i)*unsafe.Sizeof(C.nwep_header{})))
		r.Headers = append(r.Headers, Header{
			Name:  C.GoStringN((*C.char)(unsafe.Pointer(hdr.name)), C.int(hdr.name_len)),
			Value: C.GoStringN((*C.char)(unsafe.Pointer(hdr.value)), C.int(hdr.value_len)),
		})
	}
	if resp.body != nil && resp.body_len > 0 {
		r.Body = C.GoBytes(unsafe.Pointer(resp.body), C.int(resp.body_len))
	}

	p.resp = r
	return 0
}

//export goClientOnStreamData
func goClientOnStreamData(conn *C.nwep_conn, stream *C.nwep_stream, data *C.uint8_t, length C.size_t, userData unsafe.Pointer) C.int {
	cl := cgo.Handle(userData).Value().(*Client)

	sid := int64(C.nwep_stream_get_id(stream))
	cl.mu.Lock()
	p, ok := cl.pendingReqs[sid]
	cl.mu.Unlock()
	if !ok {
		return 0
	}

	chunk := C.GoBytes(unsafe.Pointer(data), C.int(length))
	p.bodyBuf = append(p.bodyBuf, chunk...)
	return 0
}

//export goClientOnStreamEnd
func goClientOnStreamEnd(conn *C.nwep_conn, stream *C.nwep_stream, userData unsafe.Pointer) C.int {
	cl := cgo.Handle(userData).Value().(*Client)

	sid := int64(C.nwep_stream_get_id(stream))
	cl.mu.Lock()
	p, ok := cl.pendingReqs[sid]
	if ok {
		delete(cl.pendingReqs, sid)
	}
	cl.mu.Unlock()
	if !ok {
		return 0
	}

	// Assemble final body from bodyBuf if on_stream_data was used
	if p.resp != nil && len(p.bodyBuf) > 0 {
		p.resp.Body = append(p.resp.Body, p.bodyBuf...)
	}

	close(p.done)
	return 0
}

//export goClientOnNotify
func goClientOnNotify(conn *C.nwep_conn, stream *C.nwep_stream, notify *C.nwep_notify, userData unsafe.Pointer) C.int {
	cl := cgo.Handle(userData).Value().(*Client)
	if cl.onNotify == nil {
		return 0
	}

	n := &Notification{}
	if notify.event != nil {
		n.Event = C.GoStringN(notify.event, C.int(notify.event_len))
	}
	if notify.path != nil {
		n.Path = C.GoStringN(notify.path, C.int(notify.path_len))
	}
	for i := C.size_t(0); i < notify.header_count; i++ {
		hdr := (*C.nwep_header)(unsafe.Pointer(uintptr(unsafe.Pointer(notify.headers)) + uintptr(i)*unsafe.Sizeof(C.nwep_header{})))
		n.Headers = append(n.Headers, Header{
			Name:  C.GoStringN((*C.char)(unsafe.Pointer(hdr.name)), C.int(hdr.name_len)),
			Value: C.GoStringN((*C.char)(unsafe.Pointer(hdr.value)), C.int(hdr.value_len)),
		})
	}
	if notify.body != nil && notify.body_len > 0 {
		n.Body = C.GoBytes(unsafe.Pointer(notify.body), C.int(notify.body_len))
	}

	cl.onNotify(n)
	return 0
}

//export goClientRand
func goClientRand(dest *C.uint8_t, length C.size_t, userData unsafe.Pointer) C.int {
	buf := make([]byte, int(length))
	if _, err := cryptoRand(buf); err != nil {
		return -1
	}
	C.memcpy(unsafe.Pointer(dest), unsafe.Pointer(&buf[0]), length)
	return 0
}

func fillClientPath(path *C.nwep_path, local, remote *net.UDPAddr) {
	fillClientSockaddr(&path.local_addr, &path.local_addrlen, local)
	fillClientSockaddr(&path.remote_addr, &path.remote_addrlen, remote)
}

// Always uses AF_INET6 (IPv4-mapped IPv6 for IPv4 addresses) to match
// the reference client behavior and keep address families consistent.
func fillClientSockaddr(ss *C.struct_sockaddr_storage, sslen *C.size_t, addr *net.UDPAddr) {
	sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(ss))
	sa.Family = syscall.AF_INET6
	sa.Port = htons(uint16(addr.Port))
	copy((*[16]byte)(unsafe.Pointer(&sa.Addr))[:], addr.IP.To16())
	*sslen = C.size_t(unsafe.Sizeof(syscall.RawSockaddrInet6{}))
}
