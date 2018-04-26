package lib

// adapted from https://github.com/lca1/unlynx/blob/master/lib/crypto_test.go

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/util/random"
)

// TestNullCipherText verifies encryption, decryption and behavior of null ciphertexts.
func TestNullCipherText(t *testing.T) {

	secKey, pubKey := GenKey()

	// second output is not used because proofs are tested somewhere else
	nullEnc, _ := EncryptInt(pubKey, 0)
	nullDec := DecryptInt(secKey, *nullEnc)

	if 0 != nullDec {
		t.Fatal("Decryption of encryption of 0 should be 0, got", nullDec)
	}

	var twoTimesNullEnc = CipherText{K: SuiTe.Point().Null(), C: SuiTe.Point().Null()}
	twoTimesNullEnc.Add(*nullEnc, *nullEnc)
	twoTimesNullDec := DecryptInt(secKey, twoTimesNullEnc)

	if 0 != nullDec {
		t.Fatal("Decryption of encryption of 0+0 should be 0, got", twoTimesNullDec)
	}

}

// TestEncryption tests a relatively high number of encryptions.
func TestEncryption(t *testing.T) {

	_, pubKey := GenKey()

	nbrEncryptions := 2
	for i := 0; i < nbrEncryptions; i++ {
		EncryptInt(pubKey, 0)
	}
}

// TestDecryptionConcurrent test the multiple encryptions/decryptions at the same time
func TestDecryptionConcurrent(t *testing.T) {
	numThreads := 5

	sec, pubKey := GenKey()

	StartParallelize(numThreads)

	for i := 0; i < numThreads; i++ {
		go func() {
			ct, _ := EncryptInt(pubKey, 0)
			val := DecryptInt(sec, *ct)
			require.Equal(t, val, int64(0))
		}()
	}
}

func TestEncryptDecryptIntVector(t *testing.T) {
	// generate keys
	secKey, pubKey := GenKey()

	vector := []int64{1, 2, 3, 4, 5, 6}

	cipher, _ := EncryptIntVector(pubKey, vector)
	plain := DecryptIntVector(secKey, cipher)

	require.Equal(t, vector, plain)
}

// TestHomomorphicOpp tests homomorphic addition.
func TestHomomorphicOpp(t *testing.T) {
	secKey, pubKey := GenKey()

	// second output is not used because proof is tested somewhere else
	cv1, _ := EncryptIntVector(pubKey, []int64{0, 1, 2, 3, 100})
	cv2, _ := EncryptIntVector(pubKey, []int64{0, 0, 1, 3, 3})
	targetAdd := []int64{0, 1, 3, 6, 103}
	targetSub := []int64{0, 1, 1, 0, 97}
	targetMul := int64(4)

	cv3 := NewCipherVector(5)
	cv3.Add(*cv1, *cv2)
	cv4 := NewCipherVector(5)
	cv4.Sub(*cv1, *cv2)
	cv5, _ := EncryptInt(pubKey, 2)
	cv5.MulCipherTextbyScalar(*cv5, SuiTe.Scalar().SetInt64(2))

	pAdd := DecryptIntVector(secKey, cv3)
	pSub := DecryptIntVector(secKey, cv4)
	pMul := DecryptInt(secKey, *cv5)

	require.Equal(t, targetAdd, pAdd)
	require.Equal(t, targetSub, pSub)
	require.Equal(t, targetMul, pMul)
}

// TestAbstractPointsConverter tests the kyber points array converter (to bytes)
func TestAbstractPointsConverter(t *testing.T) {
	aps := make([]kyber.Point, 0)

	clientPrivate := SuiTe.Scalar().Pick(random.New())

	for i := 0; i < 4; i++ {
		ap := SuiTe.Point().Mul(clientPrivate, SuiTe.Point().Base())
		aps = append(aps, ap)
	}

	apsBytes := AbstractPointsToBytes(aps)
	newAps := BytesToAbstractPoints(apsBytes)

	for i, el := range aps {
		if !reflect.DeepEqual(el.String(), newAps[i].String()) {
			t.Fatal("Wrong results, expected", el, "but got", newAps[i])
		}
	}

	t.Log("[AbstractPoints] -> Good results")
}

// TestCiphertextConverter tests the Ciphertext converter (to bytes)
func TestCiphertextConverter(t *testing.T) {
	secKey, pubKey := GenKey()

	target := int64(2)
	// second output is not used because proof are tested somewhere else
	ct, _ := EncryptInt(pubKey, target)

	ctb := ct.ToBytes()

	newCT := CipherText{}
	newCT.FromBytes(ctb)

	p := DecryptInt(secKey, newCT)

	require.Equal(t, target, p)
}

// TestCipherVectorConverter tests the CipherVector converter (to bytes)
func TestCipherVectorConverter(t *testing.T) {
	secKey, pubKey := GenKey()

	target := []int64{0, 1, 3, 103, 103}
	cv, _ := EncryptIntVector(pubKey, target)

	cvb, length := cv.ToBytes()

	newCV := CipherVector{}
	newCV.FromBytes(cvb, length)

	p := DecryptIntVector(secKey, &newCV)

	require.Equal(t, target, p)
}

// TestIntArrayToCipherVector tests the int array to CipherVector converter and IntToPoint + PointToCiphertext
func TestIntArrayToCipherVector(t *testing.T) {
	integers := []int64{1, 2, 3, 4, 5, 6}

	cipherVect := IntArrayToCipherVector(integers)
	for i, v := range cipherVect {
		B := SuiTe.Point().Base()
		i := SuiTe.Scalar().SetInt64(integers[i])
		M := SuiTe.Point().Mul(i, B)
		N := SuiTe.Point().Null()
		require.Equal(t, v.C, M)
		require.Equal(t, v.K, N)
	}
}

func TestB64Serialization(t *testing.T) {
	secKey, pubKey := GenKey()
	target := []int64{0, 1, 3, 103, 103}
	cv, _ := EncryptIntVector(pubKey, target)

	for i, ct := range *cv {
		ctSerialized := ct.Serialize()

		// with newciphertext
		ctDeserialized := NewCipherTextFromBase64(ctSerialized)
		decVal := DecryptInt(secKey, *ctDeserialized)
		require.Equal(t, target[i], decVal)

		// with deserialize
		ctDeserializedBis := NewCipherText()
		ctDeserializedBis.Deserialize(ctSerialized)
		decValBis := DecryptInt(secKey, *ctDeserializedBis)
		require.Equal(t, target[i], decValBis)
		require.Equal(t, decVal, decValBis)
	}
}
