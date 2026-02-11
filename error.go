package nwep

/*
#include <nwep/nwep.h>
*/
import "C"

import "fmt"

type ErrorCategory int

const (
	ErrCatNone     ErrorCategory = C.NWEP_ERR_CAT_NONE
	ErrCatConfig   ErrorCategory = C.NWEP_ERR_CAT_CONFIG
	ErrCatNetwork  ErrorCategory = C.NWEP_ERR_CAT_NETWORK
	ErrCatCrypto   ErrorCategory = C.NWEP_ERR_CAT_CRYPTO
	ErrCatProtocol ErrorCategory = C.NWEP_ERR_CAT_PROTOCOL
	ErrCatIdentity ErrorCategory = C.NWEP_ERR_CAT_IDENTITY
	ErrCatStorage  ErrorCategory = C.NWEP_ERR_CAT_STORAGE
	ErrCatTrust    ErrorCategory = C.NWEP_ERR_CAT_TRUST
	ErrCatInternal ErrorCategory = C.NWEP_ERR_CAT_INTERNAL
)

func (c ErrorCategory) String() string {
	return C.GoString(C.nwep_err_category_str(C.nwep_error_category(c)))
}

const (
	ErrConfigFileNotFound     = C.NWEP_ERR_CONFIG_FILE_NOT_FOUND
	ErrConfigParseError       = C.NWEP_ERR_CONFIG_PARSE_ERROR
	ErrConfigInvalidValue     = C.NWEP_ERR_CONFIG_INVALID_VALUE
	ErrConfigMissingRequired  = C.NWEP_ERR_CONFIG_MISSING_REQUIRED
	ErrConfigValidationFailed = C.NWEP_ERR_CONFIG_VALIDATION_FAILED
)

const (
	ErrNetworkConnFailed  = C.NWEP_ERR_NETWORK_CONN_FAILED
	ErrNetworkConnClosed  = C.NWEP_ERR_NETWORK_CONN_CLOSED
	ErrNetworkTimeout     = C.NWEP_ERR_NETWORK_TIMEOUT
	ErrNetworkAddrInUse   = C.NWEP_ERR_NETWORK_ADDR_IN_USE
	ErrNetworkAddrInvalid = C.NWEP_ERR_NETWORK_ADDR_INVALID
	ErrNetworkSocket      = C.NWEP_ERR_NETWORK_SOCKET
	ErrNetworkTLS         = C.NWEP_ERR_NETWORK_TLS
	ErrNetworkQUIC        = C.NWEP_ERR_NETWORK_QUIC
	ErrNetworkNoServers   = C.NWEP_ERR_NETWORK_NO_SERVERS
)

const (
	ErrCryptoKeyGenFailed     = C.NWEP_ERR_CRYPTO_KEY_GEN_FAILED
	ErrCryptoSignFailed       = C.NWEP_ERR_CRYPTO_SIGN_FAILED
	ErrCryptoVerifyFailed     = C.NWEP_ERR_CRYPTO_VERIFY_FAILED
	ErrCryptoHashFailed       = C.NWEP_ERR_CRYPTO_HASH_FAILED
	ErrCryptoInvalidKey       = C.NWEP_ERR_CRYPTO_INVALID_KEY
	ErrCryptoInvalidSig       = C.NWEP_ERR_CRYPTO_INVALID_SIG
	ErrCryptoEncryptFailed    = C.NWEP_ERR_CRYPTO_ENCRYPT_FAILED
	ErrCryptoDecryptFailed    = C.NWEP_ERR_CRYPTO_DECRYPT_FAILED
	ErrCryptoKeyLoadFailed    = C.NWEP_ERR_CRYPTO_KEY_LOAD_FAILED
	ErrCryptoKeySaveFailed    = C.NWEP_ERR_CRYPTO_KEY_SAVE_FAILED
	ErrCryptoCertError        = C.NWEP_ERR_CRYPTO_CERT_ERROR
	ErrCryptoPubkeyMismatch   = C.NWEP_ERR_CRYPTO_PUBKEY_MISMATCH
	ErrCryptoNodeIDMismatch   = C.NWEP_ERR_CRYPTO_NODEID_MISMATCH
	ErrCryptoChallengeFailed  = C.NWEP_ERR_CRYPTO_CHALLENGE_FAILED
	ErrCryptoServerSigInvalid = C.NWEP_ERR_CRYPTO_SERVER_SIG_INVALID
	ErrCryptoClientSigInvalid = C.NWEP_ERR_CRYPTO_CLIENT_SIG_INVALID
	ErrCryptoAuthTimeout      = C.NWEP_ERR_CRYPTO_AUTH_TIMEOUT
)

const (
	ErrProtoInvalidMessage  = C.NWEP_ERR_PROTO_INVALID_MESSAGE
	ErrProtoInvalidMethod   = C.NWEP_ERR_PROTO_INVALID_METHOD
	ErrProtoInvalidHeader   = C.NWEP_ERR_PROTO_INVALID_HEADER
	ErrProtoMsgTooLarge     = C.NWEP_ERR_PROTO_MSG_TOO_LARGE
	ErrProtoStreamError     = C.NWEP_ERR_PROTO_STREAM_ERROR
	ErrProtoInvalidStatus   = C.NWEP_ERR_PROTO_INVALID_STATUS
	ErrProtoConnectRequired = C.NWEP_ERR_PROTO_CONNECT_REQUIRED
	ErrProtoTooManyHeaders  = C.NWEP_ERR_PROTO_TOO_MANY_HEADERS
	ErrProtoHeaderTooLarge  = C.NWEP_ERR_PROTO_HEADER_TOO_LARGE
	ErrProto0RTTRejected    = C.NWEP_ERR_PROTO_0RTT_REJECTED
	ErrProtoMissingHeader   = C.NWEP_ERR_PROTO_MISSING_HEADER
	ErrProtoRoleMismatch    = C.NWEP_ERR_PROTO_ROLE_MISMATCH
	ErrProtoUnauthorized    = C.NWEP_ERR_PROTO_UNAUTHORIZED
	ErrProtoPathNotFound    = C.NWEP_ERR_PROTO_PATH_NOT_FOUND
	ErrProtoVersionMismatch = C.NWEP_ERR_PROTO_VERSION_MISMATCH
)

const (
	ErrIdentityInvalidNodeID      = C.NWEP_ERR_IDENTITY_INVALID_NODEID
	ErrIdentityInvalidAddr        = C.NWEP_ERR_IDENTITY_INVALID_ADDR
	ErrIdentityAuthFailed         = C.NWEP_ERR_IDENTITY_AUTH_FAILED
	ErrIdentityChallengeExpired   = C.NWEP_ERR_IDENTITY_CHALLENGE_EXPIRED
	ErrIdentityNoRecovery         = C.NWEP_ERR_IDENTITY_NO_RECOVERY
	ErrIdentityRecoveryMismatch   = C.NWEP_ERR_IDENTITY_RECOVERY_MISMATCH
	ErrIdentityInvalidShare       = C.NWEP_ERR_IDENTITY_INVALID_SHARE
	ErrIdentityShareCombine       = C.NWEP_ERR_IDENTITY_SHARE_COMBINE
	ErrIdentityInvalidThreshold   = C.NWEP_ERR_IDENTITY_INVALID_THRESHOLD
	ErrIdentityRotationInProgress = C.NWEP_ERR_IDENTITY_ROTATION_IN_PROGRESS
	ErrIdentityKeyMismatch        = C.NWEP_ERR_IDENTITY_KEY_MISMATCH
	ErrIdentityRevoked            = C.NWEP_ERR_IDENTITY_REVOKED
)

const (
	ErrStorageFileNotFound    = C.NWEP_ERR_STORAGE_FILE_NOT_FOUND
	ErrStorageReadError       = C.NWEP_ERR_STORAGE_READ_ERROR
	ErrStorageWriteError      = C.NWEP_ERR_STORAGE_WRITE_ERROR
	ErrStoragePermission      = C.NWEP_ERR_STORAGE_PERMISSION
	ErrStorageDiskFull        = C.NWEP_ERR_STORAGE_DISK_FULL
	ErrStorageKeyNotFound     = C.NWEP_ERR_STORAGE_KEY_NOT_FOUND
	ErrStorageIndexOutOfRange = C.NWEP_ERR_STORAGE_INDEX_OUT_OF_RANGE
	ErrStorageCorrupted       = C.NWEP_ERR_STORAGE_CORRUPTED
)

const (
	ErrTrustParseError       = C.NWEP_ERR_TRUST_PARSE_ERROR
	ErrTrustInvalidEntry     = C.NWEP_ERR_TRUST_INVALID_ENTRY
	ErrTrustInvalidSig       = C.NWEP_ERR_TRUST_INVALID_SIG
	ErrTrustQuorumNotReached = C.NWEP_ERR_TRUST_QUORUM_NOT_REACHED
	ErrTrustInvalidProof     = C.NWEP_ERR_TRUST_INVALID_PROOF
	ErrTrustEntryNotFound    = C.NWEP_ERR_TRUST_ENTRY_NOT_FOUND
	ErrTrustCheckpointStale  = C.NWEP_ERR_TRUST_CHECKPOINT_STALE
	ErrTrustAnchorUnknown    = C.NWEP_ERR_TRUST_ANCHOR_UNKNOWN
	ErrTrustDuplicateBinding = C.NWEP_ERR_TRUST_DUPLICATE_BINDING
	ErrTrustNodeNotFound     = C.NWEP_ERR_TRUST_NODE_NOT_FOUND
	ErrTrustAlreadyRevoked   = C.NWEP_ERR_TRUST_ALREADY_REVOKED
	ErrTrustInvalidAuth      = C.NWEP_ERR_TRUST_INVALID_AUTH
	ErrTrustUnauthorized     = C.NWEP_ERR_TRUST_UNAUTHORIZED
	ErrTrustTypeNotAllowed   = C.NWEP_ERR_TRUST_TYPE_NOT_ALLOWED
	ErrTrustKeyMismatch      = C.NWEP_ERR_TRUST_KEY_MISMATCH
	ErrTrustStorage          = C.NWEP_ERR_TRUST_STORAGE
	ErrTrustLogCorrupted     = C.NWEP_ERR_TRUST_LOG_CORRUPTED
	ErrTrustEquivocation     = C.NWEP_ERR_TRUST_EQUIVOCATION
)

const (
	ErrFatalThreshold = C.NWEP_ERR_FATAL_THRESHOLD
	ErrContextMax     = C.NWEP_ERR_CONTEXT_MAX
)

const (
	ErrInternalUnknown         = C.NWEP_ERR_INTERNAL_UNKNOWN
	ErrInternalNotImplemented  = C.NWEP_ERR_INTERNAL_NOT_IMPLEMENTED
	ErrInternalInvalidState    = C.NWEP_ERR_INTERNAL_INVALID_STATE
	ErrInternalNullPtr         = C.NWEP_ERR_INTERNAL_NULL_PTR
	ErrInternalNomem           = C.NWEP_ERR_INTERNAL_NOMEM
	ErrInternalInvalidArg      = C.NWEP_ERR_INTERNAL_INVALID_ARG
	ErrInternalCallbackFailure = C.NWEP_ERR_INTERNAL_CALLBACK_FAILURE
	ErrInternalNobuf           = C.NWEP_ERR_INTERNAL_NOBUF
)

type Error struct {
	Code     int
	Category ErrorCategory
	Fatal    bool
	message  string
}

func (e *Error) Error() string {
	return fmt.Sprintf("nwep [%s:%d] %s", e.Category, e.Code, e.message)
}

func errorFromCode(code int) error {
	if code == 0 {
		return nil
	}
	return &Error{
		Code:     code,
		Category: ErrorCategory(C.nwep_err_category(C.int(code))),
		Fatal:    C.nwep_err_is_fatal(C.int(code)) != 0,
		message:  C.GoString(C.nwep_strerror(C.int(code))),
	}
}

// ErrToStatus maps an error code to its WEB/1 status token.
func ErrToStatus(code int) string {
	return C.GoString(C.nwep_err_to_status(C.int(code)))
}
