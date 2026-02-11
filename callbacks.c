#include <nwep/nwep.h>
#include <stdint.h>

/* ===== Server callback Go exports ===== */
extern int goServerOnConnect(nwep_conn *conn, nwep_identity *peer, void *user_data);
extern void goServerOnDisconnect(nwep_conn *conn, int error, void *user_data);
extern int goServerOnRequest(nwep_conn *conn, nwep_stream *stream, nwep_request *req, void *user_data);
extern int goServerRand(uint8_t *dest, size_t len, void *user_data);

/* ===== Client callback Go exports ===== */
extern int goClientOnConnect(nwep_conn *conn, nwep_identity *peer, void *user_data);
extern void goClientOnDisconnect(nwep_conn *conn, int error, void *user_data);
extern int goClientOnResponse(nwep_conn *conn, nwep_stream *stream, nwep_response *resp, void *user_data);
extern int goClientOnNotify(nwep_conn *conn, nwep_stream *stream, nwep_notify *notify, void *user_data);
extern int goClientOnStreamData(nwep_conn *conn, nwep_stream *stream, uint8_t *data, size_t len, void *user_data);
extern int goClientOnStreamEnd(nwep_conn *conn, nwep_stream *stream, void *user_data);
extern int goClientRand(uint8_t *dest, size_t len, void *user_data);

/* ===== Log callback Go exports ===== */
extern void goLogCallback(nwep_log_entry *entry, void *user_data);

/* ===== Merkle log storage callback Go exports ===== */
extern int goLogAppend(void *user_data, uint64_t index, uint8_t *entry, size_t entry_len);
extern ptrdiff_t goLogGet(void *user_data, uint64_t index, uint8_t *buf, size_t buflen);
extern uint64_t goLogSize(void *user_data);

/* ===== Log index storage callback Go exports ===== */
extern int goIndexGet(void *user_data, nwep_nodeid *nodeid, nwep_log_index_entry *entry);
extern int goIndexPut(void *user_data, nwep_log_index_entry *entry);

/* ===== Server callback shims (cast away const) ===== */
int cServerOnConnect(nwep_conn *conn, const nwep_identity *peer, void *ud) {
    return goServerOnConnect(conn, (nwep_identity *)peer, ud);
}

void cServerOnDisconnect(nwep_conn *conn, int error, void *ud) {
    goServerOnDisconnect(conn, error, ud);
}

int cServerOnRequest(nwep_conn *conn, nwep_stream *stream, const nwep_request *req, void *ud) {
    return goServerOnRequest(conn, stream, (nwep_request *)req, ud);
}

int cServerRand(uint8_t *dest, size_t len, void *ud) {
    return goServerRand(dest, len, ud);
}

/* ===== Client callback shims (cast away const) ===== */
int cClientOnConnect(nwep_conn *conn, const nwep_identity *peer, void *ud) {
    return goClientOnConnect(conn, (nwep_identity *)peer, ud);
}

void cClientOnDisconnect(nwep_conn *conn, int error, void *ud) {
    goClientOnDisconnect(conn, error, ud);
}

int cClientOnResponse(nwep_conn *conn, nwep_stream *stream, const nwep_response *resp, void *ud) {
    return goClientOnResponse(conn, stream, (nwep_response *)resp, ud);
}

int cClientOnNotify(nwep_conn *conn, nwep_stream *stream, const nwep_notify *notify, void *ud) {
    return goClientOnNotify(conn, stream, (nwep_notify *)notify, ud);
}

int cClientOnStreamData(nwep_conn *conn, nwep_stream *stream, const uint8_t *data, size_t len, void *ud) {
    return goClientOnStreamData(conn, stream, (uint8_t *)data, len, ud);
}

int cClientOnStreamEnd(nwep_conn *conn, nwep_stream *stream, void *ud) {
    return goClientOnStreamEnd(conn, stream, ud);
}

int cClientRand(uint8_t *dest, size_t len, void *ud) {
    return goClientRand(dest, len, ud);
}

/* ===== Logging callback shim ===== */
void cLogCallback(const nwep_log_entry *entry, void *ud) {
    goLogCallback((nwep_log_entry *)entry, ud);
}

/* ===== Merkle log storage shims ===== */
static int cLogAppend(void *ud, uint64_t index, const uint8_t *entry, size_t entry_len) {
    return goLogAppend(ud, index, (uint8_t *)entry, entry_len);
}
static nwep_ssize cLogGet(void *ud, uint64_t index, uint8_t *buf, size_t buflen) {
    return (nwep_ssize)goLogGet(ud, index, buf, buflen);
}
static uint64_t cLogSize(void *ud) {
    return goLogSize(ud);
}

nwep_log_storage make_log_storage(void *ud) {
    nwep_log_storage s;
    s.append = cLogAppend;
    s.get = cLogGet;
    s.size = cLogSize;
    s.user_data = ud;
    return s;
}

/* ===== Log index storage shims ===== */
static int cIndexGet(void *ud, const nwep_nodeid *nodeid, nwep_log_index_entry *entry) {
    return goIndexGet(ud, (nwep_nodeid *)nodeid, entry);
}
static int cIndexPut(void *ud, const nwep_log_index_entry *entry) {
    return goIndexPut(ud, (nwep_log_index_entry *)entry);
}

nwep_log_index_storage make_index_storage(void *ud) {
    nwep_log_index_storage s;
    s.get = cIndexGet;
    s.put = cIndexPut;
    s.user_data = ud;
    return s;
}

/* ===== Log authorize callback ===== */
extern int goLogAuthorize(void *user_data, nwep_nodeid *nodeid, nwep_merkle_entry *entry);

static int cLogAuthorize(void *ud, const nwep_nodeid *nodeid, const nwep_merkle_entry *entry) {
    return goLogAuthorize(ud, (nwep_nodeid *)nodeid, (nwep_merkle_entry *)entry);
}

nwep_log_server_settings make_log_server_settings(void *ud) {
    nwep_log_server_settings s;
    s.authorize = cLogAuthorize;
    s.user_data = ud;
    return s;
}

/* ===== Anchor proposal callback ===== */
extern int goAnchorProposal(void *user_data, nwep_checkpoint *cp);

static int cAnchorProposal(void *ud, const nwep_checkpoint *cp) {
    return goAnchorProposal(ud, (nwep_checkpoint *)cp);
}

nwep_anchor_server_settings make_anchor_server_settings(void *ud) {
    nwep_anchor_server_settings s;
    s.on_proposal = cAnchorProposal;
    s.user_data = ud;
    return s;
}

/* ===== Trust storage callbacks ===== */
extern int goTrustAnchorLoad(void *user_data, nwep_bls_pubkey *anchors, size_t max_anchors);
extern int goTrustAnchorSave(void *user_data, nwep_bls_pubkey *anchors, size_t count);
extern int goTrustCheckpointLoad(void *user_data, nwep_checkpoint *checkpoints, size_t max_checkpoints);
extern int goTrustCheckpointSave(void *user_data, nwep_checkpoint *cp);

static int cTrustAnchorLoad(void *ud, nwep_bls_pubkey *anchors, size_t max_anchors) {
    return goTrustAnchorLoad(ud, anchors, max_anchors);
}
static int cTrustAnchorSave(void *ud, const nwep_bls_pubkey *anchors, size_t count) {
    return goTrustAnchorSave(ud, (nwep_bls_pubkey *)anchors, count);
}
static int cTrustCheckpointLoad(void *ud, nwep_checkpoint *checkpoints, size_t max_checkpoints) {
    return goTrustCheckpointLoad(ud, checkpoints, max_checkpoints);
}
static int cTrustCheckpointSave(void *ud, const nwep_checkpoint *cp) {
    return goTrustCheckpointSave(ud, (nwep_checkpoint *)cp);
}

nwep_trust_storage make_trust_storage(void *ud) {
    nwep_trust_storage s;
    s.anchor_load = cTrustAnchorLoad;
    s.anchor_save = cTrustAnchorSave;
    s.checkpoint_load = cTrustCheckpointLoad;
    s.checkpoint_save = cTrustCheckpointSave;
    s.user_data = ud;
    return s;
}

/* ===== Variadic log function wrappers ===== */
/* cgo cannot call C variadic functions directly, so we wrap with "%s". */
void nwep_log_write_str(nwep_log_level level, const uint8_t *trace_id,
                         const char *component, const char *msg) {
    nwep_log_write(level, trace_id, component, "%s", msg);
}

void nwep_log_trace_str(const uint8_t *trace_id, const char *component,
                         const char *msg) {
    nwep_log_trace(trace_id, component, "%s", msg);
}

void nwep_log_debug_str(const uint8_t *trace_id, const char *component,
                         const char *msg) {
    nwep_log_debug(trace_id, component, "%s", msg);
}

void nwep_log_info_str(const uint8_t *trace_id, const char *component,
                        const char *msg) {
    nwep_log_info(trace_id, component, "%s", msg);
}

void nwep_log_warn_str(const uint8_t *trace_id, const char *component,
                        const char *msg) {
    nwep_log_warn(trace_id, component, "%s", msg);
}

void nwep_log_error_str(const uint8_t *trace_id, const char *component,
                         const char *msg) {
    nwep_log_error(trace_id, component, "%s", msg);
}

/* ===== cgo.Handle to void* conversion ===== */
/* Converts a Go cgo.Handle (uintptr_t) to void* for C user_data params. */
/* This avoids "possible misuse of unsafe.Pointer" from go vet. */
void* handle_to_ptr(uintptr_t h) { return (void*)h; }

/* ===== Debug logging setup ===== */
void setup_debug_logging(void) {
    nwep_log_set_level(NWEP_LOG_TRACE);
    nwep_log_set_callback(cLogCallback, NULL);
}
