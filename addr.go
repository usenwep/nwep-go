package nwep

/*
#include <nwep/nwep.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"fmt"
	"net"
	"unsafe"
)

type Addr struct {
	IP     net.IP
	NodeID NodeID
	Port   uint16
}

type URL struct {
	Addr Addr
	Path string
}

func AddrEncode(addr *Addr) (string, error) {
	var ca C.nwep_addr
	ca.port = C.uint16_t(addr.Port)
	fillCAddr(&ca, addr.IP, addr.NodeID)

	var buf [C.NWEP_BASE58_ADDR_LEN + 1]C.char
	n := C.nwep_addr_encode((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &ca)
	if n == 0 {
		return "", fmt.Errorf("nwep: addr encode failed")
	}
	return C.GoString((*C.char)(unsafe.Pointer(&buf[0]))), nil
}

func AddrDecode(encoded string) (*Addr, error) {
	cs := C.CString(encoded)
	defer C.free(unsafe.Pointer(cs))
	var ca C.nwep_addr
	rv := C.nwep_addr_decode(&ca, cs)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return addrFromC(&ca), nil
}

func URLParse(raw string) (*URL, error) {
	cs := C.CString(raw)
	defer C.free(unsafe.Pointer(cs))
	var curl C.nwep_url
	rv := C.nwep_url_parse(&curl, cs)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return &URL{
		Addr: *addrFromC(&curl.addr),
		Path: C.GoString(&curl.path[0]),
	}, nil
}

func URLFormat(u *URL) (string, error) {
	return FormatURL(u.Addr.IP, u.Addr.Port, u.Addr.NodeID, u.Path)
}

func FormatURL(ip net.IP, port uint16, nodeID NodeID, path string) (string, error) {
	var ca C.nwep_addr
	ca.port = C.uint16_t(port)
	fillCAddr(&ca, ip, nodeID)

	var curl C.nwep_url
	curl.addr = ca
	if path == "" {
		path = "/"
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	C.strncpy(&curl.path[0], cpath, 255)

	var buf [C.NWEP_URL_MAX_LEN]C.char
	n := C.nwep_url_format((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &curl)
	if n == 0 {
		return "", fmt.Errorf("nwep: url format failed")
	}
	return C.GoString((*C.char)(unsafe.Pointer(&buf[0]))), nil
}

func fillCAddr(ca *C.nwep_addr, ip net.IP, nodeID NodeID) {
	ip4 := ip.To4()
	if ip4 != nil {
		C.nwep_addr_set_ipv4(ca, C.uint32_t(
			uint32(ip4[0])<<24|uint32(ip4[1])<<16|uint32(ip4[2])<<8|uint32(ip4[3])))
	} else {
		ip16 := ip.To16()
		if ip16 != nil {
			C.nwep_addr_set_ipv6(ca, (*C.uint8_t)(unsafe.Pointer(&ip16[0])))
		}
	}
	C.memcpy(unsafe.Pointer(&ca.nodeid.data[0]), unsafe.Pointer(&nodeID[0]), 32)
}

func addrFromC(ca *C.nwep_addr) *Addr {
	var ip net.IP
	rawIP := (*[16]byte)(unsafe.Pointer(&ca.ip[0]))

	// Check if IPv4-mapped: ::ffff:x.x.x.x
	isV4 := true
	for i := 0; i < 10; i++ {
		if rawIP[i] != 0 {
			isV4 = false
			break
		}
	}
	if isV4 && rawIP[10] == 0xff && rawIP[11] == 0xff {
		ip = net.IPv4(rawIP[12], rawIP[13], rawIP[14], rawIP[15])
	} else {
		ip = make(net.IP, 16)
		copy(ip, rawIP[:])
	}

	return &Addr{
		IP:     ip,
		NodeID: nodeIDFromC(&ca.nodeid),
		Port:   uint16(ca.port),
	}
}

func addrToUDP(addr *C.nwep_addr) *net.UDPAddr {
	a := addrFromC(addr)
	return &net.UDPAddr{
		IP:   a.IP,
		Port: int(a.Port),
	}
}
