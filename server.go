package nwep

/*
#include <nwep/nwep.h>
#include <stdlib.h>
#include <string.h>

// Shim functions defined in callbacks.c (cast away const for cgo exports).
extern int cServerOnConnect(nwep_conn *conn, const nwep_identity *peer, void *ud);
extern void cServerOnDisconnect(nwep_conn *conn, int error, void *ud);
extern int cServerOnRequest(nwep_conn *conn, nwep_stream *stream, const nwep_request *req, void *ud);
extern int cServerRand(uint8_t *dest, size_t len, void *ud);
extern void* handle_to_ptr(uintptr_t h);
*/
import "C"

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime/cgo"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type Settings struct {
	MaxStreams      uint32
	MaxMessageSize uint32
	TimeoutMs      uint32
	Compression    string
	Role           string
}

type ServerOption func(*Server)

func WithOnConnect(fn func(*Conn)) ServerOption {
	return func(s *Server) { s.onConnect = fn }
}

func WithOnDisconnect(fn func(*Conn, int)) ServerOption {
	return func(s *Server) { s.onDisconnect = fn }
}

func WithSettings(settings Settings) ServerOption {
	return func(s *Server) { s.userSettings = &settings }
}

type Conn struct {
	c      *C.nwep_conn
	nodeID NodeID
	Role   ServerRole
}

func (c *Conn) PeerIdentity() (pubkey [32]byte, nodeid NodeID) {
	peer := C.nwep_conn_get_peer_identity(c.c)
	if peer == nil {
		return
	}
	C.memcpy(unsafe.Pointer(&pubkey[0]), unsafe.Pointer(&peer.pubkey[0]), 32)
	nodeid = nodeIDFromC(&peer.nodeid)
	return
}

func (c *Conn) LocalIdentity() Identity {
	id := C.nwep_conn_get_local_identity(c.c)
	if id == nil {
		return Identity{}
	}
	return identityFromC(id)
}

func (c *Conn) NodeID() NodeID {
	return c.nodeID
}

// Close closes the connection with the given error code (0 for graceful).
func (c *Conn) Close(err int) {
	C.nwep_conn_close(c.c, C.int(err))
}

func (c *Conn) UserData() unsafe.Pointer {
	return C.nwep_conn_get_user_data(c.c)
}

func (c *Conn) SetUserData(data unsafe.Pointer) {
	C.nwep_conn_set_user_data(c.c, data)
}



type protocolEvent struct {
	kind    int
	pktData []byte
	addr    *net.UDPAddr
}

const (
	evPacket   = 0
	evShutdown = 1
)

type Server struct {
	bindAddr     string
	keypair      *Keypair
	handler      Handler
	cserver      *C.nwep_server
	conn         *net.UDPConn
	resolvedAddr net.Addr
	nodeID       NodeID
	handle       cgo.Handle

	conns   map[string]*Conn
	connsMu sync.Mutex

	onConnect    func(*Conn)
	onDisconnect func(*Conn, int)
	userSettings *Settings

	events   chan protocolEvent
	shutdown chan struct{}
	done     chan struct{}
}

func NewServer(addr string, keypair *Keypair, handler Handler, opts ...ServerOption) (*Server, error) {
	s := &Server{
		bindAddr: addr,
		keypair:  keypair,
		handler:  handler,
		conns:    make(map[string]*Conn),
		events:   make(chan protocolEvent, 256),
		shutdown: make(chan struct{}),
		done:     make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}

	nid, err := keypair.NodeID()
	if err != nil {
		return nil, fmt.Errorf("nwep: compute node id: %w", err)
	}
	s.nodeID = nid

	var settings C.nwep_settings
	C.nwep_settings_default(&settings)
	if s.userSettings != nil {
		if s.userSettings.MaxStreams > 0 {
			settings.max_streams = C.uint32_t(s.userSettings.MaxStreams)
		}
		if s.userSettings.MaxMessageSize > 0 {
			settings.max_message_size = C.uint32_t(s.userSettings.MaxMessageSize)
		}
		if s.userSettings.TimeoutMs > 0 {
			settings.timeout_ms = C.uint32_t(s.userSettings.TimeoutMs)
		}
		if s.userSettings.Compression != "" {
			ccomp := C.CString(s.userSettings.Compression)
			defer C.free(unsafe.Pointer(ccomp))
			settings.compression = ccomp
		}
		if s.userSettings.Role != "" {
			crole := C.CString(s.userSettings.Role)
			defer C.free(unsafe.Pointer(crole))
			settings.role = crole
		}
	}

	var callbacks C.nwep_callbacks
	callbacks.on_connect = C.nwep_on_connect(C.cServerOnConnect)
	callbacks.on_disconnect = C.nwep_on_disconnect(C.cServerOnDisconnect)
	callbacks.on_request = C.nwep_on_request(C.cServerOnRequest)
	callbacks.rand = C.nwep_rand(C.cServerRand)

	s.handle = cgo.NewHandle(s)

	var cserver *C.nwep_server
	rv := C.nwep_server_new(&cserver, &settings, &callbacks, &keypair.c, C.handle_to_ptr(C.uintptr_t(s.handle)))
	if err := errorFromCode(int(rv)); err != nil {
		s.handle.Delete()
		return nil, fmt.Errorf("nwep: server new: %w", err)
	}
	s.cserver = cserver

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		C.nwep_server_free(cserver)
		s.handle.Delete()
		return nil, fmt.Errorf("nwep: resolve addr: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		C.nwep_server_free(cserver)
		s.handle.Delete()
		return nil, fmt.Errorf("nwep: listen udp: %w", err)
	}
	s.conn = udpConn
	s.resolvedAddr = udpConn.LocalAddr()

	return s, nil
}

// Run starts the event loop. Blocks until Shutdown is called or a signal is received.
func (s *Server) Run() error {
	defer close(s.done)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			s.events <- protocolEvent{kind: evShutdown}
		case <-s.shutdown:
		}
		signal.Stop(sigCh)
	}()

	go func() {
		buf := make([]byte, 1500)
		for {
			n, raddr, err := s.conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-s.shutdown:
					return
				default:
					continue
				}
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			s.events <- protocolEvent{kind: evPacket, pktData: pkt, addr: raddr}
		}
	}()

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	resetTimer := func() {
		expiry := C.nwep_server_get_expiry(s.cserver)
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
		case ev := <-s.events:
			switch ev.kind {
			case evPacket:
				s.handlePacket(ev.pktData, ev.addr)
				s.drainWrites()
				resetTimer()

			case evShutdown:
				C.nwep_server_close(s.cserver)
				s.drainWrites()
				s.conn.Close()
				close(s.shutdown)
				C.nwep_server_free(s.cserver)
				s.handle.Delete()
				return nil
			}

		case <-timer.C:
			ts := C.nwep_tstamp(nowNanos())
			C.nwep_server_handle_expiry(s.cserver, ts)
			s.drainWrites()
			resetTimer()
		}
	}
}

func (s *Server) handlePacket(data []byte, raddr *net.UDPAddr) {
	laddr := s.conn.LocalAddr().(*net.UDPAddr)

	var path C.nwep_path
	fillServerPath(&path, laddr, raddr)

	ts := C.nwep_tstamp(nowNanos())
	C.nwep_server_read(s.cserver, &path, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)), ts)
}

func (s *Server) drainWrites() {
	var path C.nwep_path
	var buf [1500]byte

	for {
		ts := C.nwep_tstamp(nowNanos())
		n := C.nwep_server_write(s.cserver, &path, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), ts)
		if n <= 0 {
			break
		}
		raddr := sockaddrToUDP(&path.remote_addr, path.remote_addrlen)
		if raddr != nil {
			s.conn.WriteToUDP(buf[:int(n)], raddr)
		}
	}
}

func (s *Server) Shutdown() {
	s.events <- protocolEvent{kind: evShutdown}
	<-s.done
}

func (s *Server) NodeID() NodeID {
	return s.nodeID
}

// Addr returns the actual listen address (useful when binding to port 0).
func (s *Server) Addr() net.Addr {
	return s.resolvedAddr
}

func (s *Server) URL(path string) string {
	udpAddr := s.resolvedAddr.(*net.UDPAddr)
	ip := udpAddr.IP
	if ip.IsUnspecified() {
		ip = net.IPv4(127, 0, 0, 1)
	}
	u, err := FormatURL(ip, uint16(udpAddr.Port), s.nodeID, path)
	if err != nil {
		return ""
	}
	return u
}

func (s *Server) ConnectionCount() int {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	return len(s.conns)
}

func (s *Server) ConnectedPeers() []NodeID {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	peers := make([]NodeID, 0, len(s.conns))
	for _, c := range s.conns {
		peers = append(peers, c.nodeID)
	}
	return peers
}

type NotifyOptions struct {
	Headers  []Header
	NotifyID [16]byte
}

func (s *Server) Notify(peerNodeID NodeID, event, path string, body []byte) error {
	return s.NotifyWithOptions(peerNodeID, event, path, body, nil)
}

func (s *Server) NotifyWithOptions(peerNodeID NodeID, event, path string, body []byte, opts *NotifyOptions) error {
	s.connsMu.Lock()
	c, ok := s.conns[peerNodeID.String()]
	s.connsMu.Unlock()
	if !ok {
		return fmt.Errorf("nwep: peer %s not connected", peerNodeID)
	}

	var notify C.nwep_notify
	var allocs []unsafe.Pointer
	cevent := C.CString(event)
	cpath := C.CString(path)
	allocs = append(allocs, unsafe.Pointer(cevent), unsafe.Pointer(cpath))
	notify.event = cevent
	notify.event_len = C.size_t(len(event))
	notify.path = cpath
	notify.path_len = C.size_t(len(path))
	if len(body) > 0 {
		notify.body = (*C.uint8_t)(unsafe.Pointer(&body[0]))
		notify.body_len = C.size_t(len(body))
	}

	if opts != nil {
		if len(opts.Headers) > 0 {
			cheaders := make([]C.nwep_header, len(opts.Headers))
			for i, h := range opts.Headers {
				cname := C.CString(h.Name)
				cval := C.CString(h.Value)
				allocs = append(allocs, unsafe.Pointer(cname), unsafe.Pointer(cval))
				cheaders[i].name = (*C.uint8_t)(unsafe.Pointer(cname))
				cheaders[i].name_len = C.size_t(len(h.Name))
				cheaders[i].value = (*C.uint8_t)(unsafe.Pointer(cval))
				cheaders[i].value_len = C.size_t(len(h.Value))
			}
			notify.headers = (*C.nwep_header)(unsafe.Pointer(&cheaders[0]))
			notify.header_count = C.size_t(len(cheaders))
		}
		var zeroID [16]byte
		if opts.NotifyID != zeroID {
			C.memcpy(unsafe.Pointer(&notify.notify_id[0]), unsafe.Pointer(&opts.NotifyID[0]), 16)
			notify.has_notify_id = 1
		}
	}

	var stream *C.nwep_stream
	rv := C.nwep_conn_notify(c.c, &notify, &stream)
	for _, p := range allocs {
		C.free(p)
	}
	if err := errorFromCode(int(rv)); err != nil {
		return err
	}
	C.nwep_stream_end(stream)
	s.drainWrites()
	return nil
}

func (s *Server) NotifyAll(event, path string, body []byte) {
	s.connsMu.Lock()
	peers := make([]NodeID, 0, len(s.conns))
	for _, c := range s.conns {
		peers = append(peers, c.nodeID)
	}
	s.connsMu.Unlock()

	for _, p := range peers {
		s.Notify(p, event, path, body)
	}
}

// Server callback exports using cgo.Handle dispatch.

//export goServerOnConnect
func goServerOnConnect(conn *C.nwep_conn, peer *C.nwep_identity, userData unsafe.Pointer) C.int {
	srv := cgo.Handle(userData).Value().(*Server)

	nid := nodeIDFromC(&peer.nodeid)
	if nid.IsZero() {
		// C library may not fill in nodeid — derive from pubkey.
		var pubkey [32]byte
		C.memcpy(unsafe.Pointer(&pubkey[0]), unsafe.Pointer(&peer.pubkey[0]), 32)
		if derived, err := NodeIDFromPubkey(pubkey); err == nil {
			nid = derived
		}
	}
	c := &Conn{
		c:      conn,
		nodeID: nid,
	}
	roleStr := C.nwep_conn_get_role(conn)
	if roleStr != nil {
		c.Role = RoleFromString(C.GoString(roleStr))
	}

	srv.connsMu.Lock()
	srv.conns[nid.String()] = c
	srv.connsMu.Unlock()

	if srv.onConnect != nil {
		srv.onConnect(c)
	}
	return 0
}

//export goServerOnDisconnect
func goServerOnDisconnect(conn *C.nwep_conn, errCode C.int, userData unsafe.Pointer) {
	srv := cgo.Handle(userData).Value().(*Server)

	peer := C.nwep_conn_get_peer_identity(conn)
	if peer == nil {
		return
	}
	nid := nodeIDFromC(&peer.nodeid)
	key := nid.String()

	srv.connsMu.Lock()
	c, ok := srv.conns[key]
	if ok {
		delete(srv.conns, key)
	}
	srv.connsMu.Unlock()

	if ok && srv.onDisconnect != nil {
		srv.onDisconnect(c, int(errCode))
	}
}

//export goServerOnRequest
func goServerOnRequest(conn *C.nwep_conn, stream *C.nwep_stream, req *C.nwep_request, userData unsafe.Pointer) C.int {
	srv := cgo.Handle(userData).Value().(*Server)

	peer := C.nwep_conn_get_peer_identity(conn)
	var goConn *Conn
	if peer != nil {
		nid := nodeIDFromC(&peer.nodeid)
		srv.connsMu.Lock()
		goConn = srv.conns[nid.String()]
		srv.connsMu.Unlock()
	}

	r := requestFromC(req, goConn)
	w := &ResponseWriter{stream: stream}

	if srv.handler != nil {
		srv.handler.ServeNWEP(w, r)
		w.sendDefault()
	} else {
		w.Respond("not_found", nil)
	}
	return 0
}

//export goServerRand
func goServerRand(dest *C.uint8_t, length C.size_t, userData unsafe.Pointer) C.int {
	buf := make([]byte, int(length))
	if _, err := cryptoRand(buf); err != nil {
		return -1
	}
	C.memcpy(unsafe.Pointer(dest), unsafe.Pointer(&buf[0]), length)
	return 0
}

// fillServerPath fills a C nwep_path from Go UDP addresses using native AF_INET/AF_INET6.
func fillServerPath(path *C.nwep_path, local, remote *net.UDPAddr) {
	fillServerSockaddr(&path.local_addr, &path.local_addrlen, local)
	fillServerSockaddr(&path.remote_addr, &path.remote_addrlen, remote)
}

// Uses native AF_INET for IPv4 and AF_INET6 for IPv6.
func fillServerSockaddr(ss *C.struct_sockaddr_storage, sslen *C.size_t, addr *net.UDPAddr) {
	ip4 := addr.IP.To4()
	if ip4 != nil {
		sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(ss))
		sa.Family = syscall.AF_INET
		sa.Port = htons(uint16(addr.Port))
		copy((*[4]byte)(unsafe.Pointer(&sa.Addr))[:], ip4)
		*sslen = C.size_t(unsafe.Sizeof(syscall.RawSockaddrInet4{}))
	} else {
		sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(ss))
		sa.Family = syscall.AF_INET6
		sa.Port = htons(uint16(addr.Port))
		copy((*[16]byte)(unsafe.Pointer(&sa.Addr))[:], addr.IP.To16())
		*sslen = C.size_t(unsafe.Sizeof(syscall.RawSockaddrInet6{}))
	}
}

func sockaddrToUDP(ss *C.struct_sockaddr_storage, sslen C.size_t) *net.UDPAddr {
	family := (*syscall.RawSockaddr)(unsafe.Pointer(ss)).Family
	switch family {
	case syscall.AF_INET:
		sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(ss))
		return &net.UDPAddr{
			IP:   net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]),
			Port: int(ntohs(sa.Port)),
		}
	case syscall.AF_INET6:
		sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(ss))
		ip := make(net.IP, 16)
		copy(ip, (*[16]byte)(unsafe.Pointer(&sa.Addr))[:])
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}
		return &net.UDPAddr{
			IP:   ip,
			Port: int(ntohs(sa.Port)),
		}
	}
	return nil
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func ntohs(v uint16) uint16 {
	return htons(v)
}
