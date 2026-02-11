package nwep

/*
#include <nwep/nwep.h>
#include <string.h>
*/
import "C"

import "unsafe"

const (
	CheckpointDST        = "WEB/1-CHECKPOINT"
	DefaultEpochInterval = 3600 * Seconds
	MaxCheckpoints       = C.NWEP_MAX_CHECKPOINTS
)

type Checkpoint struct {
	Epoch      uint64
	Timestamp  Tstamp
	MerkleRoot MerkleHash
	LogSize    uint64
	Signature  BLSSig
	Signers    []BLSPubkey
}

func CheckpointNew(epoch uint64, timestamp Tstamp, merkleRoot MerkleHash, logSize uint64) (*Checkpoint, error) {
	var ccp C.nwep_checkpoint
	cmr := merkleHashToC(merkleRoot)
	rv := C.nwep_checkpoint_new(&ccp, C.uint64_t(epoch), C.nwep_tstamp(timestamp), &cmr, C.uint64_t(logSize))
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return checkpointFromC(&ccp), nil
}

func CheckpointSign(cp *Checkpoint, anchorKP *BLSKeypair) error {
	ccp := checkpointToC(cp)
	rv := C.nwep_checkpoint_sign(&ccp, &anchorKP.c)
	if err := errorFromCode(int(rv)); err != nil {
		return err
	}
	*cp = *checkpointFromC(&ccp)
	return nil
}

func CheckpointVerify(cp *Checkpoint, anchorSet *AnchorSet) error {
	ccp := checkpointToC(cp)
	return errorFromCode(int(C.nwep_checkpoint_verify(&ccp, anchorSet.c)))
}

func CheckpointEncode(cp *Checkpoint) ([]byte, error) {
	ccp := checkpointToC(cp)
	buf := make([]byte, 4096)
	n := C.nwep_checkpoint_encode((*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &ccp)
	if n < 0 {
		return nil, errorFromCode(int(n))
	}
	return buf[:n], nil
}

func CheckpointDecode(data []byte) (*Checkpoint, error) {
	var ccp C.nwep_checkpoint
	rv := C.nwep_checkpoint_decode(&ccp, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return checkpointFromC(&ccp), nil
}

// CheckpointMessage computes the signable message for a checkpoint.
func CheckpointMessage(cp *Checkpoint) ([]byte, error) {
	ccp := checkpointToC(cp)
	var buf [56]byte
	n := C.nwep_checkpoint_message((*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &ccp)
	if n < 0 {
		return nil, errorFromCode(int(n))
	}
	return buf[:n], nil
}

func checkpointToC(cp *Checkpoint) C.nwep_checkpoint {
	var ccp C.nwep_checkpoint
	ccp.epoch = C.uint64_t(cp.Epoch)
	ccp.timestamp = C.nwep_tstamp(cp.Timestamp)
	ccp.merkle_root = merkleHashToC(cp.MerkleRoot)
	ccp.log_size = C.uint64_t(cp.LogSize)
	C.memcpy(unsafe.Pointer(&ccp.signature.data[0]), unsafe.Pointer(&cp.Signature[0]), BLSSigLen)
	ccp.num_signers = C.size_t(len(cp.Signers))
	for i, s := range cp.Signers {
		if i >= MaxAnchors {
			break
		}
		C.memcpy(unsafe.Pointer(&ccp.signers[i].data[0]), unsafe.Pointer(&s[0]), BLSPubkeyLen)
	}
	return ccp
}

func checkpointFromC(ccp *C.nwep_checkpoint) *Checkpoint {
	cp := &Checkpoint{
		Epoch:      uint64(ccp.epoch),
		Timestamp:  Tstamp(ccp.timestamp),
		MerkleRoot: merkleHashFromC(&ccp.merkle_root),
		LogSize:    uint64(ccp.log_size),
	}
	C.memcpy(unsafe.Pointer(&cp.Signature[0]), unsafe.Pointer(&ccp.signature.data[0]), BLSSigLen)
	for i := 0; i < int(ccp.num_signers); i++ {
		cp.Signers = append(cp.Signers, blsPubkeyFromC(&ccp.signers[i]))
	}
	return cp
}
