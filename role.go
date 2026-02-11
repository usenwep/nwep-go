package nwep

/*
#include <nwep/nwep.h>
#include <stdlib.h>
*/
import "C"

import "unsafe"

type ServerRole int

const (
	RoleRegular   ServerRole = C.NWEP_ROLE_REGULAR
	RoleLogServer ServerRole = C.NWEP_ROLE_LOG_SERVER
	RoleAnchor    ServerRole = C.NWEP_ROLE_ANCHOR
)

const (
	RoleStrRegular   = "regular"
	RoleStrLogServer = "log_server"
	RoleStrAnchor    = "anchor"
)

func RoleFromString(s string) ServerRole {
	cs := C.CString(s)
	defer C.free(unsafe.Pointer(cs))
	return ServerRole(C.nwep_role_from_str(cs))
}

func (r ServerRole) String() string {
	return C.GoString(C.nwep_role_to_str(C.nwep_server_role(r)))
}
