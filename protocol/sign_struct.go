package protocol

import (
	"github.com/dedis/student_18_decenar/lib"
)

type VerificationData struct {
	RootKey             string
	Threshold           int
	ConodeKey           string
	Partials            map[int][]byte
	EncryptedCBFSet     *lib.CipherVector
	Leaves              []string
	CompleteProofs      lib.CompleteProofs
	ConsensusSet        []int64
	ConsensusParameters []uint64
}
