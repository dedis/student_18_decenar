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
	valid := []int64{0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1}
	invalid := []int64{3, 4, 6, 0, 1}

	// encrypt and generate proofs
	validEncrypted, validProof := EncryptIntVector(pair.Public, valid)
	invalidEncrypted, invalidProof := EncryptIntVector(pair.Public, invalid)

	// verify proofs
	require.Equal(t, true, validProof.VerifyCipherVectorProof(validEncrypted))
	require.Equal(t, false, invalidProof.VerifyCipherVectorProof(invalidEncrypted))
}

func TestAggregationProof(t *testing.T) {
	// generate keys and vectors
	pair := key.NewKeyPair(cothority.Suite)
	c1 := []int64{0, 1, 2, 3}
	c2 := []int64{0, 1, 2, 3}
	c3 := []int64{0, 1, 2, 3}

	// encrypt
	c1Encrypted, _ := EncryptIntVector(pair.Public, c1)
	c2Encrypted, _ := EncryptIntVector(pair.Public, c2)
	c3Encrypted, _ := EncryptIntVector(pair.Public, c3)

	// put in map
	contributions := make(map[string]*CipherVector)
	//contributions["first"] = c1Encrypted
	contributions["second"] = c2Encrypted
	contributions["third"] = c3Encrypted

	// create aggregations
	tmp := c1Encrypted
	for _, c := range contributions {
		log.Print("Adding contribution")
		tmp.Add(*tmp, *c)
	}

	log.Printf("Result: %#v\n", tmp)
}
