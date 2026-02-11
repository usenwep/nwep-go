package nwep

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func init() {
	if err := Init(); err != nil {
		panic("nwep.Init: " + err.Error())
	}
	SetLogLevel(LogWarn)
}

// ============================================================
// Init & Version
// ============================================================

func TestVersion(t *testing.T) {
	v := Version()
	if v == "" {
		t.Fatal("Version() returned empty string")
	}
	t.Logf("nwep version: %s", v)
}

// ============================================================
// Keypair / NodeID / Identity
// ============================================================

func TestKeypairGenerate(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Clear()

	pub := kp.PublicKey()
	if pub == [32]byte{} {
		t.Fatal("PublicKey is all zeros")
	}
}

func TestKeypairFromSeed(t *testing.T) {
	var seed [32]byte
	seed[0] = 42
	kp1, err := KeypairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer kp1.Clear()

	kp2, err := KeypairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer kp2.Clear()

	if kp1.PublicKey() != kp2.PublicKey() {
		t.Fatal("same seed produced different pubkeys")
	}
}

func TestNodeID(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Clear()

	nid, err := kp.NodeID()
	if err != nil {
		t.Fatal(err)
	}
	if nid.IsZero() {
		t.Fatal("NodeID is zero")
	}

	// NodeIDFromPubkey should match
	pub := kp.PublicKey()
	nid2, err := NodeIDFromPubkey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !nid.Equal(nid2) {
		t.Fatalf("NodeID mismatch: %s vs %s", nid, nid2)
	}

	// String round-trip
	s := nid.String()
	if len(s) != 64 {
		t.Fatalf("NodeID.String() len = %d, want 64", len(s))
	}
}

func TestManagedIdentity(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Clear()

	mi, err := NewManagedIdentity(kp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer mi.Clear()

	if mi.IsRevoked() {
		t.Fatal("new managed identity should not be revoked")
	}

	nid := mi.NodeID()
	if nid.IsZero() {
		t.Fatal("managed identity NodeID is zero")
	}

	active := mi.ActiveKeypair()
	if active == nil {
		t.Fatal("no active keypair")
	}

	keys := mi.ActiveKeys()
	if len(keys) == 0 {
		t.Fatal("ActiveKeys returned empty")
	}
}

func TestManagedIdentityRotation(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Clear()

	mi, err := NewManagedIdentity(kp, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer mi.Clear()

	pubBefore := mi.ActiveKeypair().PublicKey()

	if err := mi.Rotate(); err != nil {
		t.Fatal(err)
	}

	pubAfter := mi.ActiveKeypair().PublicKey()
	if pubBefore == pubAfter {
		t.Fatal("pubkey unchanged after rotation")
	}

	// During overlap, both keys should be active
	keys := mi.ActiveKeys()
	if len(keys) < 2 {
		t.Logf("active keys = %d (overlap may have expired)", len(keys))
	}
}

func TestRecoveryAuthority(t *testing.T) {
	ra, err := NewRecoveryAuthority()
	if err != nil {
		t.Fatal(err)
	}
	defer ra.Clear()

	pub := ra.PublicKey()
	if pub == [32]byte{} {
		t.Fatal("recovery authority pubkey is zero")
	}

	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Clear()

	mi, err := NewManagedIdentity(kp, ra)
	if err != nil {
		t.Fatal(err)
	}
	defer mi.Clear()

	if err := mi.Revoke(ra); err != nil {
		t.Fatal(err)
	}
	if !mi.IsRevoked() {
		t.Fatal("identity should be revoked")
	}
}

// ============================================================
// Crypto (Sign/Verify, Challenge, Random, Shamir)
// ============================================================

func TestSignVerify(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Clear()

	msg := []byte("hello nwep")
	sig, err := Sign(kp, msg)
	if err != nil {
		t.Fatal(err)
	}
	if sig == [64]byte{} {
		t.Fatal("signature is all zeros")
	}

	pub := kp.PublicKey()
	if err := Verify(pub, sig, msg); err != nil {
		t.Fatal("verify failed:", err)
	}

	// Tamper with message
	msg[0] ^= 0xff
	if err := Verify(pub, sig, msg); err == nil {
		t.Fatal("verify should fail on tampered message")
	}
}

func TestSignEmpty(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Clear()

	sig, err := Sign(kp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(kp.PublicKey(), sig, nil); err != nil {
		t.Fatal("verify empty message:", err)
	}
}

func TestChallenge(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Clear()

	challenge, err := ChallengeGenerate()
	if err != nil {
		t.Fatal(err)
	}
	if challenge == [32]byte{} {
		t.Fatal("challenge is all zeros")
	}

	response, err := ChallengeSign(challenge, kp)
	if err != nil {
		t.Fatal(err)
	}

	pub := kp.PublicKey()
	if err := ChallengeVerify(response, challenge, pub); err != nil {
		t.Fatal("challenge verify failed:", err)
	}

	// Wrong challenge
	challenge[0] ^= 0xff
	if err := ChallengeVerify(response, challenge, pub); err == nil {
		t.Fatal("challenge verify should fail with wrong nonce")
	}
}

func TestRandomBytes(t *testing.T) {
	buf := make([]byte, 64)
	if err := RandomBytes(buf); err != nil {
		t.Fatal(err)
	}
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("RandomBytes returned all zeros")
	}

	// Empty is fine
	if err := RandomBytes(nil); err != nil {
		t.Fatal(err)
	}
}

func TestShamir(t *testing.T) {
	var secret [32]byte
	if err := RandomBytes(secret[:]); err != nil {
		t.Fatal(err)
	}

	shares, err := ShamirSplit(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 5 {
		t.Fatalf("got %d shares, want 5", len(shares))
	}

	// Reconstruct from 3 shares
	recovered, err := ShamirCombine(shares[:3])
	if err != nil {
		t.Fatal(err)
	}
	if recovered != secret {
		t.Fatal("recovered secret mismatch")
	}

	// Different subset of 3 shares
	recovered2, err := ShamirCombine(shares[2:5])
	if err != nil {
		t.Fatal(err)
	}
	if recovered2 != secret {
		t.Fatal("recovered secret (subset 2) mismatch")
	}
}

// ============================================================
// Encoding (Base58, Base64)
// ============================================================

func TestBase58(t *testing.T) {
	// Use a 32-byte value (typical key/hash size) for reliable round-trip.
	var data [32]byte
	for i := range data {
		data[i] = byte(i + 1)
	}
	encoded := Base58Encode(data[:])
	if encoded == "" {
		t.Fatal("Base58Encode returned empty")
	}
	t.Logf("Base58 encoded: %s", encoded)
	decoded, err := Base58Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, data[:]) {
		t.Fatalf("Base58 round-trip mismatch: %x vs %x", decoded, data)
	}
}

func TestBase64(t *testing.T) {
	data := []byte("hello world 12345678")
	encoded := Base64Encode(data)
	if encoded == "" {
		t.Fatal("Base64Encode returned empty")
	}
	decoded, err := Base64Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatalf("Base64 round-trip mismatch")
	}
}

func TestBase64DecodeN(t *testing.T) {
	data := []byte("test data for base64 decode_n")
	encoded := Base64Encode(data)
	decoded, err := Base64DecodeN([]byte(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatalf("Base64DecodeN mismatch")
	}
}

// ============================================================
// Address / URL
// ============================================================

func TestAddrEncodeDecode(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Clear()

	nid, _ := kp.NodeID()
	addr := &Addr{
		IP:     net.IPv4(127, 0, 0, 1),
		NodeID: nid,
		Port:   6937,
	}
	encoded, err := AddrEncode(addr)
	if err != nil {
		t.Fatal(err)
	}
	if encoded == "" {
		t.Fatal("encoded addr is empty")
	}

	decoded, err := AddrDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.NodeID != addr.NodeID {
		t.Fatal("NodeID mismatch after addr round-trip")
	}
}

func TestFormatParseURL(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Clear()

	nid, _ := kp.NodeID()
	u, err := FormatURL(net.IPv4(127, 0, 0, 1), 6937, nid, "/test")
	if err != nil {
		t.Fatal(err)
	}
	if u == "" {
		t.Fatal("FormatURL returned empty")
	}
	t.Logf("URL: %s", u)

	parsed, err := URLParse(u)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Path != "/test" {
		t.Fatalf("parsed path = %q, want /test", parsed.Path)
	}
	if parsed.Addr.Port != 6937 {
		t.Fatalf("parsed port = %d, want 6937", parsed.Addr.Port)
	}
}

// ============================================================
// Protocol helpers
// ============================================================

func TestMethodValidation(t *testing.T) {
	if !MethodIsValid("read") {
		t.Fatal("read should be valid")
	}
	if !MethodIsValid("write") {
		t.Fatal("write should be valid")
	}
	if MethodIsValid("INVALID") {
		t.Fatal("INVALID should not be valid")
	}
	if !MethodIsIdempotent("read") {
		t.Fatal("read should be idempotent")
	}
	if MethodIsIdempotent("write") {
		t.Fatal("write should not be idempotent")
	}
	if !MethodAllowed0RTT("read") {
		t.Fatal("read should be allowed in 0-RTT")
	}
	if MethodAllowed0RTT("write") {
		t.Fatal("write should not be allowed in 0-RTT")
	}
}

func TestStatusValidation(t *testing.T) {
	if !StatusIsValid("ok") {
		t.Fatal("ok should be valid")
	}
	if !StatusIsSuccess("ok") {
		t.Fatal("ok should be success")
	}
	if StatusIsError("ok") {
		t.Fatal("ok should not be error")
	}
	if !StatusIsError("not_found") {
		t.Fatal("not_found should be error")
	}
	if StatusIsValid("gibberish") {
		t.Fatal("gibberish should not be valid")
	}
}

func TestIDGeneration(t *testing.T) {
	tid, err := TraceIDGenerate()
	if err != nil {
		t.Fatal(err)
	}
	if tid == [16]byte{} {
		t.Fatal("trace ID is zero")
	}

	rid, err := RequestIDGenerate()
	if err != nil {
		t.Fatal(err)
	}
	if rid == [16]byte{} {
		t.Fatal("request ID is zero")
	}

	// Uniqueness
	tid2, _ := TraceIDGenerate()
	if tid == tid2 {
		t.Fatal("two trace IDs are identical")
	}
}

// ============================================================
// Error system
// ============================================================

func TestErrorFromCode(t *testing.T) {
	err := errorFromCode(0)
	if err != nil {
		t.Fatal("code 0 should be nil")
	}

	err = errorFromCode(ErrInternalUnknown)
	if err == nil {
		t.Fatal("non-zero code should be error")
	}
	e, ok := err.(*Error)
	if !ok {
		t.Fatal("error should be *Error")
	}
	if e.Code != ErrInternalUnknown {
		t.Fatalf("code = %d, want %d", e.Code, ErrInternalUnknown)
	}
	if e.Category != ErrCatInternal {
		t.Fatalf("category = %d, want %d", e.Category, ErrCatInternal)
	}
	if e.Error() == "" {
		t.Fatal("error message is empty")
	}
}

func TestErrToStatus(t *testing.T) {
	s := ErrToStatus(ErrProtoPathNotFound)
	if s == "" {
		t.Fatal("ErrToStatus returned empty")
	}
	t.Logf("ErrProtoPathNotFound -> %q", s)
}

// ============================================================
// BLS
// ============================================================

func TestBLSSignVerify(t *testing.T) {
	kp, err := BLSKeypairGenerate()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("bls test message")
	sig, err := BLSSign(kp, msg)
	if err != nil {
		t.Fatal(err)
	}

	pk := kp.Pubkey()
	if err := BLSVerify(pk, sig, msg); err != nil {
		t.Fatal("BLS verify failed:", err)
	}

	// Tamper
	msg[0] ^= 0xff
	if err := BLSVerify(pk, sig, msg); err == nil {
		t.Fatal("BLS verify should fail on tampered msg")
	}
}

func TestBLSAggregate(t *testing.T) {
	msg := []byte("aggregate test")
	var pks []BLSPubkey
	var sigs []BLSSig

	for i := 0; i < 3; i++ {
		kp, err := BLSKeypairGenerate()
		if err != nil {
			t.Fatal(err)
		}
		sig, err := BLSSign(kp, msg)
		if err != nil {
			t.Fatal(err)
		}
		pks = append(pks, kp.Pubkey())
		sigs = append(sigs, sig)
	}

	agg, err := BLSAggregateSigs(sigs)
	if err != nil {
		t.Fatal(err)
	}

	if err := BLSVerifyAggregate(pks, agg, msg); err != nil {
		t.Fatal("BLS aggregate verify failed:", err)
	}
}

func TestBLSPubkeySerialization(t *testing.T) {
	kp, err := BLSKeypairGenerate()
	if err != nil {
		t.Fatal(err)
	}

	pk := kp.Pubkey()
	serialized, err := BLSPubkeySerialize(&pk)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := BLSPubkeyDeserialize(serialized)
	if err != nil {
		t.Fatal(err)
	}
	if deserialized != pk {
		t.Fatal("BLS pubkey serialization round-trip mismatch")
	}
}

func TestBLSKeypairFromSeed(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 99
	kp1, err := BLSKeypairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := BLSKeypairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if kp1.Pubkey() != kp2.Pubkey() {
		t.Fatal("same seed produced different BLS pubkeys")
	}
}

// ============================================================
// Merkle log
// ============================================================

// memLogStorage is an in-memory LogStorage for testing.
type memLogStorage struct {
	mu      sync.Mutex
	entries [][]byte
}

func (s *memLogStorage) Append(index uint64, entry []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if int(index) != len(s.entries) {
		return fmt.Errorf("index mismatch: %d vs %d", index, len(s.entries))
	}
	s.entries = append(s.entries, append([]byte(nil), entry...))
	return nil
}

func (s *memLogStorage) Get(index uint64, buf []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if int(index) >= len(s.entries) {
		return -1, fmt.Errorf("index out of range")
	}
	n := copy(buf, s.entries[int(index)])
	return n, nil
}

func (s *memLogStorage) Size() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return uint64(len(s.entries))
}

func makeTestEntry(t *testing.T) *MerkleEntry {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Clear()

	nid, err := kp.NodeID()
	if err != nil {
		t.Fatal(err)
	}

	entry := &MerkleEntry{
		Type:      LogEntryKeyBinding,
		Timestamp: uint64(time.Now().UnixNano()),
		NodeID:    nid,
		Pubkey:    kp.PublicKey(),
	}

	// Sign it
	encoded, err := MerkleEntryEncode(entry)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(kp, encoded)
	if err != nil {
		t.Fatal(err)
	}
	entry.Signature = sig
	return entry
}

func TestMerkleLogAppendAndGet(t *testing.T) {
	storage := &memLogStorage{}
	ml, err := NewMerkleLog(storage)
	if err != nil {
		t.Fatal(err)
	}
	defer ml.Free()

	entry := makeTestEntry(t)
	idx, err := ml.Append(entry)
	if err != nil {
		t.Fatal(err)
	}
	if idx != 0 {
		t.Fatalf("first index = %d, want 0", idx)
	}
	if ml.Size() != 1 {
		t.Fatalf("size = %d, want 1", ml.Size())
	}

	got, err := ml.Get(0)
	if err != nil {
		t.Fatal(err)
	}
	if got.NodeID != entry.NodeID {
		t.Fatal("retrieved entry NodeID mismatch")
	}
}

func TestMerkleLogRootAndProof(t *testing.T) {
	storage := &memLogStorage{}
	ml, err := NewMerkleLog(storage)
	if err != nil {
		t.Fatal(err)
	}
	defer ml.Free()

	// Append several entries
	for i := 0; i < 8; i++ {
		entry := makeTestEntry(t)
		if _, err := ml.Append(entry); err != nil {
			t.Fatal(err)
		}
	}

	root, err := ml.Root()
	if err != nil {
		t.Fatal(err)
	}
	if root == (MerkleHash{}) {
		t.Fatal("root is zero")
	}

	// Prove inclusion for entry 3
	proof, err := ml.Prove(3)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Index != 3 {
		t.Fatalf("proof index = %d, want 3", proof.Index)
	}

	if err := MerkleProofVerify(proof, root); err != nil {
		t.Fatal("proof verification failed:", err)
	}

	// Proof encode/decode round-trip
	encoded, err := MerkleProofEncode(proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := MerkleProofDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Index != proof.Index || decoded.LogSize != proof.LogSize {
		t.Fatal("proof round-trip mismatch")
	}
}

func TestMerkleEntryEncodeDecode(t *testing.T) {
	entry := makeTestEntry(t)
	encoded, err := MerkleEntryEncode(entry)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := MerkleEntryDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Type != entry.Type {
		t.Fatal("type mismatch")
	}
	if decoded.NodeID != entry.NodeID {
		t.Fatal("NodeID mismatch")
	}
	if decoded.Pubkey != entry.Pubkey {
		t.Fatal("pubkey mismatch")
	}
}

// ============================================================
// Checkpoints
// ============================================================

func TestCheckpointCreateSignVerify(t *testing.T) {
	// Create a merkle log to get a real root
	storage := &memLogStorage{}
	ml, err := NewMerkleLog(storage)
	if err != nil {
		t.Fatal(err)
	}
	defer ml.Free()

	entry := makeTestEntry(t)
	ml.Append(entry)
	root, _ := ml.Root()

	cp, err := CheckpointNew(1, uint64(time.Now().UnixNano()), root, ml.Size())
	if err != nil {
		t.Fatal(err)
	}
	if cp.Epoch != 1 {
		t.Fatalf("epoch = %d, want 1", cp.Epoch)
	}

	// Sign with BLS anchor
	anchor, err := BLSKeypairGenerate()
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckpointSign(cp, anchor); err != nil {
		t.Fatal(err)
	}
	if len(cp.Signers) == 0 {
		t.Fatal("no signers after signing")
	}

	// Create anchor set and verify
	as, err := NewAnchorSet(1)
	if err != nil {
		t.Fatal(err)
	}
	defer as.Free()

	if err := as.Add(anchor.Pubkey(), true); err != nil {
		t.Fatal(err)
	}
	if err := CheckpointVerify(cp, as); err != nil {
		t.Fatal("checkpoint verify failed:", err)
	}
}

func TestCheckpointEncodeDecode(t *testing.T) {
	root := MerkleHash{1, 2, 3}
	cp, err := CheckpointNew(42, uint64(time.Now().UnixNano()), root, 100)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := CheckpointEncode(cp)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := CheckpointDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Epoch != 42 {
		t.Fatalf("epoch = %d, want 42", decoded.Epoch)
	}
	if decoded.LogSize != 100 {
		t.Fatalf("log_size = %d, want 100", decoded.LogSize)
	}
}

// ============================================================
// Anchor set
// ============================================================

func TestAnchorSet(t *testing.T) {
	as, err := NewAnchorSet(2)
	if err != nil {
		t.Fatal(err)
	}
	defer as.Free()

	if as.Size() != 0 {
		t.Fatalf("initial size = %d, want 0", as.Size())
	}
	if as.Threshold() != 2 {
		t.Fatalf("threshold = %d, want 2", as.Threshold())
	}

	kp1, _ := BLSKeypairGenerate()
	kp2, _ := BLSKeypairGenerate()

	as.Add(kp1.Pubkey(), true)
	as.Add(kp2.Pubkey(), false)

	if as.Size() != 2 {
		t.Fatalf("size = %d, want 2", as.Size())
	}
	if !as.Contains(kp1.Pubkey()) {
		t.Fatal("should contain kp1")
	}

	pk, builtin, err := as.Get(0)
	if err != nil {
		t.Fatal(err)
	}
	if pk != kp1.Pubkey() {
		t.Fatal("Get(0) pubkey mismatch")
	}
	if !builtin {
		t.Fatal("Get(0) should be builtin")
	}

	// Remove non-builtin
	as.Remove(kp2.Pubkey())
	if as.Size() != 1 {
		t.Fatalf("size after remove = %d, want 1", as.Size())
	}
}

// ============================================================
// Identity cache
// ============================================================

func TestIdentityCache(t *testing.T) {
	settings := IdentityCacheSettingsDefault()
	if settings.Capacity <= 0 {
		t.Fatal("default capacity should be positive")
	}

	ic, err := NewIdentityCache(settings)
	if err != nil {
		t.Fatal(err)
	}
	defer ic.Free()

	if ic.Size() != 0 {
		t.Fatalf("initial size = %d", ic.Size())
	}
	if ic.Capacity() != settings.Capacity {
		t.Fatalf("capacity = %d, want %d", ic.Capacity(), settings.Capacity)
	}

	// Store and lookup
	kp, _ := GenerateKeypair()
	defer kp.Clear()
	nid, _ := kp.NodeID()
	pub := kp.PublicKey()
	now := uint64(time.Now().UnixNano())

	if err := ic.Store(nid, pub, 0, now); err != nil {
		t.Fatal(err)
	}
	if ic.Size() != 1 {
		t.Fatalf("size after store = %d", ic.Size())
	}

	cached, err := ic.Lookup(nid, now)
	if err != nil {
		t.Fatal(err)
	}
	if cached.NodeID != nid {
		t.Fatal("cached NodeID mismatch")
	}
	if cached.Pubkey != pub {
		t.Fatal("cached pubkey mismatch")
	}

	stats := ic.Stats()
	if stats.Stores != 1 {
		t.Fatalf("stores = %d, want 1", stats.Stores)
	}
	if stats.Hits != 1 {
		t.Fatalf("hits = %d, want 1", stats.Hits)
	}

	// Invalidate
	ic.Invalidate(nid)
	_, err = ic.Lookup(nid, now)
	if err == nil {
		t.Fatal("lookup should fail after invalidate")
	}

	// Clear
	ic.Store(nid, pub, 0, now)
	ic.Clear()
	if ic.Size() != 0 {
		t.Fatalf("size after clear = %d", ic.Size())
	}

	ic.ResetStats()
	stats = ic.Stats()
	if stats.Hits != 0 {
		t.Fatal("hits should be 0 after reset")
	}
}

// ============================================================
// Log server pool
// ============================================================

func TestLogServerPool(t *testing.T) {
	settings := PoolSettingsDefault()
	if settings.MaxFailures <= 0 {
		t.Fatal("default max failures should be positive")
	}

	pool, err := NewLogServerPool(settings)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Free()

	if pool.Size() != 0 {
		t.Fatalf("initial size = %d", pool.Size())
	}

	pool.Add("web://server1:6937")
	pool.Add("web://server2:6937")
	if pool.Size() != 2 {
		t.Fatalf("size = %d, want 2", pool.Size())
	}
	if pool.HealthyCount() != 2 {
		t.Fatalf("healthy = %d, want 2", pool.HealthyCount())
	}

	srv, err := pool.Select()
	if err != nil {
		t.Fatal(err)
	}
	if srv.URL == "" {
		t.Fatal("selected server URL is empty")
	}

	pool.Remove("web://server1:6937")
	if pool.Size() != 1 {
		t.Fatalf("size after remove = %d, want 1", pool.Size())
	}

	pool.ResetHealth()
}

// ============================================================
// Trust store
// ============================================================

func TestTrustStore(t *testing.T) {
	settings := TrustSettingsDefault()
	ts, err := NewTrustStore(settings)
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Free()

	// Add anchor
	kp, _ := BLSKeypairGenerate()
	if err := ts.AddAnchor(kp.Pubkey(), true); err != nil {
		t.Fatal(err)
	}

	anchors := ts.Anchors()
	if anchors == nil {
		t.Fatal("Anchors() returned nil")
	}
	if anchors.Size() != 1 {
		t.Fatalf("anchor set size = %d, want 1", anchors.Size())
	}

	if ts.CheckpointCount() != 0 {
		t.Fatalf("initial checkpoint count = %d", ts.CheckpointCount())
	}
}

func TestTrustStoreWithStorage(t *testing.T) {
	var savedAnchors []BLSPubkey
	var savedCheckpoints []*Checkpoint

	storage := &TrustStorage{
		AnchorLoad: func() ([]BLSPubkey, error) {
			return savedAnchors, nil
		},
		AnchorSave: func(anchors []BLSPubkey) error {
			savedAnchors = anchors
			return nil
		},
		CheckpointLoad: func() ([]*Checkpoint, error) {
			return savedCheckpoints, nil
		},
		CheckpointSave: func(cp *Checkpoint) error {
			savedCheckpoints = append(savedCheckpoints, cp)
			return nil
		},
	}

	ts, err := NewTrustStoreWithStorage(nil, storage)
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Free()

	kp, _ := BLSKeypairGenerate()
	if err := ts.AddAnchor(kp.Pubkey(), true); err != nil {
		t.Fatal(err)
	}
	// Storage callback should have been called
	t.Logf("saved %d anchors", len(savedAnchors))
}

// ============================================================
// Roles
// ============================================================

func TestRoles(t *testing.T) {
	if RoleFromString("regular") != RoleRegular {
		t.Fatal("regular mismatch")
	}
	if RoleFromString("log_server") != RoleLogServer {
		t.Fatal("log_server mismatch")
	}
	if RoleFromString("anchor") != RoleAnchor {
		t.Fatal("anchor mismatch")
	}
	if RoleFromString("unknown") != RoleRegular {
		t.Fatal("unknown should default to regular")
	}

	if RoleRegular.String() != "regular" {
		t.Fatalf("RoleRegular.String() = %q", RoleRegular.String())
	}
	if RoleLogServer.String() != "log_server" {
		t.Fatalf("RoleLogServer.String() = %q", RoleLogServer.String())
	}
	if RoleAnchor.String() != "anchor" {
		t.Fatalf("RoleAnchor.String() = %q", RoleAnchor.String())
	}
}

// ============================================================
// Logging
// ============================================================

func TestLogLevels(t *testing.T) {
	for _, lvl := range []LogLevel{LogTrace, LogDebug, LogInfo, LogWarn, LogError} {
		s := LogLevelStr(lvl)
		if s == "" {
			t.Fatalf("LogLevelStr(%d) returned empty", lvl)
		}
	}
}

func TestSetLogCallback(t *testing.T) {
	var received []*LogEntry
	var mu sync.Mutex

	SetLogCallback(func(e *LogEntry) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})
	defer SetLogCallback(nil)

	SetLogLevel(LogTrace)
	defer SetLogLevel(LogWarn)

	var tid [16]byte
	WriteInfo(tid, "test", "hello from Go test")

	// Give it a moment
	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	n := len(received)
	mu.Unlock()

	if n == 0 {
		t.Log("no log entries received (callback may be async)")
	} else {
		t.Logf("received %d log entries", n)
	}
}

func TestLogFormatJSON(t *testing.T) {
	entry := &LogEntry{
		Level:     LogInfo,
		Component: "test",
		Message:   "hello json",
	}
	json := LogFormatJSON(entry)
	if json == "" {
		t.Fatal("LogFormatJSON returned empty")
	}
	t.Logf("JSON: %s", json)
}

// ============================================================
// Server + Client end-to-end
// ============================================================

func TestServerClientEndToEnd(t *testing.T) {
	serverKP, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	defer serverKP.Clear()

	router := NewRouter()
	router.HandleFunc("/hello", func(w *ResponseWriter, r *Request) {
		w.Respond("ok", []byte("hello from test"))
	})
	router.HandleFunc("/echo", func(w *ResponseWriter, r *Request) {
		w.SetHeader("x-method", r.Method)
		w.Respond("ok", r.Body)
	})
	router.HandleFunc("/headers", func(w *ResponseWriter, r *Request) {
		val, ok := r.Header("x-custom")
		if ok {
			w.SetHeader("x-echo", val)
		}
		w.Respond("ok", nil)
	})

	var connectedPeer NodeID
	var mu sync.Mutex

	srv, err := NewServer(":0", serverKP, router,
		WithOnConnect(func(c *Conn) {
			mu.Lock()
			connectedPeer = c.NodeID()
			mu.Unlock()
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	go srv.Run()
	defer srv.Shutdown()

	// Wait briefly for server to be ready
	time.Sleep(50 * time.Millisecond)

	clientKP, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	defer clientKP.Clear()

	client, err := NewClient(clientKP)
	if err != nil {
		t.Fatal(err)
	}

	url := srv.URL("/")
	t.Logf("server URL: %s", url)

	if err := client.Connect(url); err != nil {
		t.Fatal("connect:", err)
	}
	defer client.Close()

	// Verify peer identity
	peerID, err := client.PeerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	serverNID, _ := serverKP.NodeID()
	if peerID.NodeID != serverNID {
		t.Fatalf("peer NodeID = %s, want %s", peerID.NodeID, serverNID)
	}

	// Test 1: simple GET
	t.Run("GET /hello", func(t *testing.T) {
		resp, err := client.Get("/hello")
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status != "ok" {
			t.Fatalf("status = %q, want ok", resp.Status)
		}
		if string(resp.Body) != "hello from test" {
			t.Fatalf("body = %q", string(resp.Body))
		}
	})

	// Test 2: POST with body
	t.Run("POST /echo", func(t *testing.T) {
		body := []byte("echo this please")
		resp, err := client.Post("/echo", body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status != "ok" {
			t.Fatalf("status = %q", resp.Status)
		}
		if !bytes.Equal(resp.Body, body) {
			t.Fatalf("body = %q, want %q", resp.Body, body)
		}
		val, ok := resp.Header("x-method")
		if !ok || val != "write" {
			t.Fatalf("x-method = %q, ok=%v", val, ok)
		}
	})

	// Test 3: custom headers
	t.Run("GET /headers with custom header", func(t *testing.T) {
		resp, err := client.FetchWithHeaders("read", "/headers", nil, []Header{
			{Name: "x-custom", Value: "test-value"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status != "ok" {
			t.Fatalf("status = %q", resp.Status)
		}
		val, ok := resp.Header("x-echo")
		if !ok || val != "test-value" {
			t.Fatalf("x-echo = %q, ok=%v", val, ok)
		}
	})

	// Test 4: 404 for unknown path
	t.Run("GET /unknown -> not_found", func(t *testing.T) {
		resp, err := client.Get("/unknown")
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status != "not_found" {
			t.Fatalf("status = %q, want not_found", resp.Status)
		}
	})

	// Test 5: multiple concurrent requests
	t.Run("concurrent requests", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, 10)
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := client.Get("/hello")
				if err != nil {
					errs <- err
					return
				}
				if resp.Status != "ok" || string(resp.Body) != "hello from test" {
					errs <- fmt.Errorf("unexpected: status=%q body=%q", resp.Status, resp.Body)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Fatal(e)
		}
	})

	// Verify server saw the connection
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	clientNID, _ := clientKP.NodeID()
	if connectedPeer != clientNID {
		t.Logf("connected peer = %s, client = %s", connectedPeer, clientNID)
	}
	mu.Unlock()

	// Server stats
	if srv.ConnectionCount() < 1 {
		t.Fatalf("connection count = %d", srv.ConnectionCount())
	}
	peers := srv.ConnectedPeers()
	if len(peers) < 1 {
		t.Fatal("no connected peers")
	}
}

func TestServerPrefixRouting(t *testing.T) {
	kp, _ := GenerateKeypair()
	defer kp.Clear()

	router := NewRouter()
	router.HandlePrefix("/api", HandlerFunc(func(w *ResponseWriter, r *Request) {
		w.Respond("ok", []byte("api: "+r.Path))
	}))

	srv, err := NewServer(":0", kp, router)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Run()
	defer srv.Shutdown()
	time.Sleep(50 * time.Millisecond)

	clientKP, _ := GenerateKeypair()
	defer clientKP.Clear()
	client, err := NewClient(clientKP)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(srv.URL("/")); err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	resp, err := client.Get("/api/users")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "ok" {
		t.Fatalf("status = %q", resp.Status)
	}
	if string(resp.Body) != "api: /api/users" {
		t.Fatalf("body = %q", resp.Body)
	}
}

func TestMultipleServersAndClients(t *testing.T) {
	// Create two servers
	kp1, _ := GenerateKeypair()
	defer kp1.Clear()
	kp2, _ := GenerateKeypair()
	defer kp2.Clear()

	router1 := NewRouter()
	router1.HandleFunc("/id", func(w *ResponseWriter, r *Request) {
		w.Respond("ok", []byte("server1"))
	})
	router2 := NewRouter()
	router2.HandleFunc("/id", func(w *ResponseWriter, r *Request) {
		w.Respond("ok", []byte("server2"))
	})

	srv1, err := NewServer(":0", kp1, router1)
	if err != nil {
		t.Fatal(err)
	}
	go srv1.Run()
	defer srv1.Shutdown()

	srv2, err := NewServer(":0", kp2, router2)
	if err != nil {
		t.Fatal(err)
	}
	go srv2.Run()
	defer srv2.Shutdown()

	time.Sleep(50 * time.Millisecond)

	// Two clients, each connecting to a different server
	ckp1, _ := GenerateKeypair()
	defer ckp1.Clear()
	ckp2, _ := GenerateKeypair()
	defer ckp2.Clear()

	c1, _ := NewClient(ckp1)
	c2, _ := NewClient(ckp2)

	if err := c1.Connect(srv1.URL("/")); err != nil {
		t.Fatal("c1 connect:", err)
	}
	defer c1.Close()

	if err := c2.Connect(srv2.URL("/")); err != nil {
		t.Fatal("c2 connect:", err)
	}
	defer c2.Close()

	r1, err := c1.Get("/id")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := c2.Get("/id")
	if err != nil {
		t.Fatal(err)
	}

	if string(r1.Body) != "server1" {
		t.Fatalf("c1 got %q, want server1", r1.Body)
	}
	if string(r2.Body) != "server2" {
		t.Fatalf("c2 got %q, want server2", r2.Body)
	}
}

func TestLargeBody(t *testing.T) {
	kp, _ := GenerateKeypair()
	defer kp.Clear()

	router := NewRouter()
	router.HandleFunc("/echo", func(w *ResponseWriter, r *Request) {
		w.Respond("ok", r.Body)
	})

	srv, err := NewServer(":0", kp, router)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Run()
	defer srv.Shutdown()
	time.Sleep(50 * time.Millisecond)

	ckp, _ := GenerateKeypair()
	defer ckp.Clear()
	client, _ := NewClient(ckp)
	if err := client.Connect(srv.URL("/")); err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// 64KB body
	body := make([]byte, 64*1024)
	for i := range body {
		body[i] = byte(i % 256)
	}

	resp, err := client.Post("/echo", body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "ok" {
		t.Fatalf("status = %q", resp.Status)
	}
	if !bytes.Equal(resp.Body, body) {
		t.Fatalf("body length = %d, want %d", len(resp.Body), len(body))
	}
}
