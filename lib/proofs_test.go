package lib

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/cothority.v2"
	"gopkg.in/dedis/kyber.v2/util/key"
	"gopkg.in/dedis/onet.v2/log"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestCipherVectorProof(t *testing.T) {
	// generate keys
	pair := key.NewKeyPair(cothority.Suite)
	valid := []int64{0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0}
	invalid := []int64{3, 4, 6, 0, 1}

	// encrypt and generate proofs
	_, validProof := EncryptIntVector(pair.Public, valid)
	_, invalidProof := EncryptIntVector(pair.Public, invalid)

	// verify proofs
	require.Equal(t, true, validProof.VerifyCipherVectorProof())
	require.Equal(t, false, invalidProof.VerifyCipherVectorProof())

}
