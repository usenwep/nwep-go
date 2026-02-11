package nwep

/*
#include <nwep/nwep.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import "unsafe"

// Client connection states.
const (
	ClientStateInitial       = C.NWEP_CLIENT_STATE_INITIAL
	ClientStateTLSHandshake  = C.NWEP_CLIENT_STATE_TLS_HANDSHAKE
	ClientStateSendConnect   = C.NWEP_CLIENT_STATE_SEND_CONNECT
	ClientStateWaitConnResp  = C.NWEP_CLIENT_STATE_WAIT_CONNECT_RESP
	ClientStateSendAuth      = C.NWEP_CLIENT_STATE_SEND_AUTHENTICATE
	ClientStateWaitAuthResp  = C.NWEP_CLIENT_STATE_WAIT_AUTH_RESP
	ClientStateConnected     = C.NWEP_CLIENT_STATE_CONNECTED
	ClientStateError         = C.NWEP_CLIENT_STATE_ERROR
)

// Server connection states.
const (
	ServerStateInitial          = C.NWEP_SERVER_STATE_INITIAL
	ServerStateTLSHandshake     = C.NWEP_SERVER_STATE_TLS_HANDSHAKE
	ServerStateAwaitingConnect  = C.NWEP_SERVER_STATE_AWAITING_CONNECT
	ServerStateAwaitingAuth     = C.NWEP_SERVER_STATE_AWAITING_CLIENT_AUTH
	ServerStateConnected        = C.NWEP_SERVER_STATE_CONNECTED
	ServerStateError            = C.NWEP_SERVER_STATE_ERROR
)

type HandshakeParams struct {
	MaxStreams      uint32
	MaxMessageSize  uint32
	Compression     string
	Role            string
}

type Handshake struct {
	c C.nwep_handshake
}

func HandshakeClientInit(kp *Keypair, expectedServer *NodeID) (*Handshake, error) {
	hs := &Handshake{}
	var nidPtr *C.nwep_nodeid
	if expectedServer != nil {
		cnid := expectedServer.toCNodeID()
		nidPtr = &cnid
	}
	rv := C.nwep_handshake_client_init(&hs.c, &kp.c, nidPtr)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return hs, nil
}

func HandshakeServerInit(kp *Keypair) (*Handshake, error) {
	hs := &Handshake{}
	rv := C.nwep_handshake_server_init(&hs.c, &kp.c)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return hs, nil
}

func (hs *Handshake) Free() {
	C.nwep_handshake_free(&hs.c)
}

func (hs *Handshake) SetParams(params *HandshakeParams) {
	var cp C.nwep_handshake_params
	cp.max_streams = C.uint32_t(params.MaxStreams)
	cp.max_message_size = C.uint32_t(params.MaxMessageSize)
	if params.Compression != "" {
		cp.compression = C.CString(params.Compression)
		defer C.free(unsafe.Pointer(cp.compression))
	}
	if params.Role != "" {
		cp.role = C.CString(params.Role)
		defer C.free(unsafe.Pointer(cp.role))
	}
	C.nwep_handshake_set_params(&hs.c, &cp)
}

func (hs *Handshake) PeerPubkey() [32]byte {
	var out [32]byte
	C.memcpy(unsafe.Pointer(&out[0]), unsafe.Pointer(&hs.c.peer_pubkey[0]), 32)
	return out
}

func (hs *Handshake) PeerNodeID() NodeID {
	return nodeIDFromC(&hs.c.peer_nodeid)
}

func (hs *Handshake) NegotiatedParams() HandshakeParams {
	np := hs.c.negotiated_params
	p := HandshakeParams{
		MaxStreams:     uint32(np.max_streams),
		MaxMessageSize: uint32(np.max_message_size),
	}
	if np.compression != nil {
		p.Compression = C.GoString(np.compression)
	}
	if np.role != nil {
		p.Role = C.GoString(np.role)
	}
	return p
}

// Buffer size for Base64-encoded handshake header values.
const handshakeHeaderBufSize = 1024

func (hs *Handshake) ConnectRequestBuild() (*Msg, error) {
	var cmsg C.nwep_msg
	var cheaders [MaxHeaders]C.nwep_header
	var hbuf [handshakeHeaderBufSize]C.uint8_t
	rv := C.nwep_connect_request_build(&cmsg, &cheaders[0], C.size_t(MaxHeaders),
		&hbuf[0], C.size_t(handshakeHeaderBufSize), &hs.c)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return msgFromC(&cmsg, &cheaders), nil
}

func (hs *Handshake) ConnectRequestParse(msg *Msg) error {
	cmsg, _, cleanup := msgToC(msg)
	defer cleanup()
	return errorFromCode(int(C.nwep_connect_request_parse(&hs.c, &cmsg)))
}

func (hs *Handshake) ConnectResponseBuild() (*Msg, error) {
	var cmsg C.nwep_msg
	var cheaders [MaxHeaders]C.nwep_header
	var hbuf [handshakeHeaderBufSize]C.uint8_t
	rv := C.nwep_connect_response_build(&cmsg, &cheaders[0], C.size_t(MaxHeaders),
		&hbuf[0], C.size_t(handshakeHeaderBufSize), &hs.c)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return msgFromC(&cmsg, &cheaders), nil
}

// Also verifies the server identity.
func (hs *Handshake) ConnectResponseParse(msg *Msg) error {
	cmsg, _, cleanup := msgToC(msg)
	defer cleanup()
	return errorFromCode(int(C.nwep_connect_response_parse(&hs.c, &cmsg)))
}

func (hs *Handshake) AuthRequestBuild() (*Msg, error) {
	var cmsg C.nwep_msg
	var cheaders [MaxHeaders]C.nwep_header
	var hbuf [handshakeHeaderBufSize]C.uint8_t
	rv := C.nwep_auth_request_build(&cmsg, &cheaders[0], C.size_t(MaxHeaders),
		&hbuf[0], C.size_t(handshakeHeaderBufSize), &hs.c)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return msgFromC(&cmsg, &cheaders), nil
}

// Also verifies the client identity.
func (hs *Handshake) AuthRequestParse(msg *Msg) error {
	cmsg, _, cleanup := msgToC(msg)
	defer cleanup()
	return errorFromCode(int(C.nwep_auth_request_parse(&hs.c, &cmsg)))
}

func (hs *Handshake) AuthResponseBuild() (*Msg, error) {
	var cmsg C.nwep_msg
	var cheaders [MaxHeaders]C.nwep_header
	rv := C.nwep_auth_response_build(&cmsg, &cheaders[0], C.size_t(MaxHeaders), &hs.c)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return msgFromC(&cmsg, &cheaders), nil
}

func (hs *Handshake) AuthResponseParse(msg *Msg) error {
	cmsg, _, cleanup := msgToC(msg)
	defer cleanup()
	return errorFromCode(int(C.nwep_auth_response_parse(&hs.c, &cmsg)))
}

// Layer 1: TLS cert pubkey matches peer_pubkey.
func (hs *Handshake) VerifyLayer1(tlsPubkey [32]byte) error {
	return errorFromCode(int(C.nwep_verify_layer1(&hs.c,
		(*C.uint8_t)(unsafe.Pointer(&tlsPubkey[0])))))
}

// Layer 2: NodeID derivation is correct.
func (hs *Handshake) VerifyLayer2() error {
	return errorFromCode(int(C.nwep_verify_layer2(&hs.c)))
}

// Layer 3: challenge signature is valid.
func (hs *Handshake) VerifyLayer3(signature [64]byte) error {
	return errorFromCode(int(C.nwep_verify_layer3(&hs.c,
		(*C.uint8_t)(unsafe.Pointer(&signature[0])))))
}

func (hs *Handshake) VerifyAllLayers(tlsPubkey [32]byte, signature [64]byte) error {
	return errorFromCode(int(C.nwep_verify_all_layers(&hs.c,
		(*C.uint8_t)(unsafe.Pointer(&tlsPubkey[0])),
		(*C.uint8_t)(unsafe.Pointer(&signature[0])))))
}

func (hs *Handshake) TranscriptInit() error {
	return errorFromCode(int(C.nwep_transcript_init(&hs.c)))
}

func (hs *Handshake) TranscriptAddConnectRequest() error {
	return errorFromCode(int(C.nwep_transcript_add_connect_request(&hs.c)))
}

func (hs *Handshake) TranscriptAddConnectResponse() error {
	return errorFromCode(int(C.nwep_transcript_add_connect_response(&hs.c)))
}

func (hs *Handshake) TranscriptSign() ([64]byte, error) {
	var sig [64]byte
	rv := C.nwep_transcript_sign((*C.uint8_t)(unsafe.Pointer(&sig[0])), &hs.c)
	if err := errorFromCode(int(rv)); err != nil {
		return [64]byte{}, err
	}
	return sig, nil
}

func (hs *Handshake) TranscriptVerify(signature [64]byte) error {
	return errorFromCode(int(C.nwep_transcript_verify(&hs.c,
		(*C.uint8_t)(unsafe.Pointer(&signature[0])))))
}

func ClientStateStr(state int) string {
	return C.GoString(C.nwep_client_state_str(C.nwep_client_state(state)))
}

func ServerStateStr(state int) string {
	return C.GoString(C.nwep_server_state_str(C.nwep_server_state(state)))
}
