package lib

// adapted from https://github.com/lca1/unlynx/blob/master/lib/crypto.go

import (
	"fmt"
	"sync"

	"github.com/fanliao/go-concurrentMap"
	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/util/random"
	"gopkg.in/dedis/onet.v2/log"
)

// MaxHomomorphicInt is upper bound for integers used in messages, a failed decryption will return this value.
const MaxHomomorphicInt int64 = 100000

// PointToInt creates a map between EC points and integers.
//var PointToInt = make(map[string]int64, MaxHomomorphicInt)
var PointToInt = concurrent.NewConcurrentMap()
var currentGreatestM kyber.Point
var currentGreatestInt int64
var mutex = sync.Mutex{}

// CipherText is an ElGamal encrypted point.
type CipherText struct {
	K, C kyber.Point
}

// CipherVector is a slice of ElGamal encrypted points.
type CipherVector []CipherText

// Constructors
//______________________________________________________________________________________________________________________

// NewCipherText creates a ciphertext of null elements.
func NewCipherText() *CipherText {
	return &CipherText{K: SuiTe.Point().Null(), C: SuiTe.Point().Null()}
}

// NewCipherVector creates a ciphervector of null elements.
func NewCipherVector(length int) *CipherVector {
	cv := make(CipherVector, length)
	for i := 0; i < length; i++ {
		cv[i] = CipherText{SuiTe.Point().Null(), SuiTe.Point().Null()}
	}
	return &cv
}

// Key Pairs (mostly used in tests)
//----------------------------------------------------------------------------------------------------------------------

// GenKey permits to generate a public/private key pairs.
func GenKey() (secKey kyber.Scalar, pubKey kyber.Point) {
	secKey = SuiTe.Scalar().Pick(random.New())
	pubKey = SuiTe.Point().Mul(secKey, SuiTe.Point().Base())
	return
}

// Encryption
//______________________________________________________________________________________________________________________

// encryptPoint creates an elliptic curve point from a non-encrypted point and
// encrypt it using ElGamal encryption. Returns also the DLEQ proof used to
// verify the correctness of the encrypted point
func encryptPoint(pubkey kyber.Point, M kyber.Point) (*CipherText, *CipherTextProof) {
	B := SuiTe.Point().Base()
	k := SuiTe.Scalar().Pick(random.New()) // ephemeral private key
	// ElGamal-encrypt the point to produce ciphertext (K,C).
	K := SuiTe.Point().Mul(k, B)      // ephemeral DH public key
	S := SuiTe.Point().Mul(k, pubkey) // ephemeral DH shared secret
	C := S.Add(S, M)                  // message blinded with secret
	cipher := &CipherText{K, C}
	return cipher, CreateCipherTextProof(cipher, pubkey, k)
}

// IntToPoint maps an integer to a point in the elliptic curve
func IntToPoint(integer int64) kyber.Point {
	B := SuiTe.Point().Base()
	i := SuiTe.Scalar().SetInt64(integer)
	M := SuiTe.Point().Mul(i, B)
	return M
}

// ZeroToPoint maps 0 to a point in the elliptic curve
func ZeroToPoint() kyber.Point {
	return IntToPoint(int64(0))
}

// OneToPoint maps 1 to a point in the elliptic curve
func OneToPoint() kyber.Point {
	return IntToPoint(int64(1))
}

// PointToCipherText converts a point into a ciphertext
func PointToCipherText(point kyber.Point) CipherText {
	return CipherText{K: SuiTe.Point().Null(), C: point}
}

// IntToCipherText converts an int into a ciphertext
func IntToCipherText(integer int64) CipherText {
	return PointToCipherText(IntToPoint(integer))
}

// EncryptInt encodes i as iB, encrypt it into a CipherText and returns a pointer to it.
func EncryptInt(pubkey kyber.Point, integer int64) (*CipherText, *CipherTextProof) {
	return encryptPoint(pubkey, IntToPoint(integer))
}

// EncryptIntVector encrypts a []int into a CipherVector and returns a pointer
// to it. A vector of DLEQ proofs is also returned to prove the correctness of
// all the ciphertext
func EncryptIntVector(pubkey kyber.Point, intArray []int64) (*CipherVector, *CipherVectorProof) {
	var wg sync.WaitGroup
	cv := make(CipherVector, len(intArray))
	cvProof := make(CipherVectorProof, len(intArray))
	if PARALLELIZE {
		for i := 0; i < len(intArray); i = i + VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < VPARALLELIZE && (j+i < len(intArray)); j++ {
					c, p := EncryptInt(pubkey, intArray[j+i])
					cv[j+i] = *c
					cvProof[j+i] = p

				}
				defer wg.Done()
			}(i)

		}
		wg.Wait()
	} else {
		for i, n := range intArray {
			cipher, proof := EncryptInt(pubkey, n)
			cv[i] = *cipher
			cvProof[i] = proof
		}
	}

	return &cv, &cvProof
}

// Decryption
//______________________________________________________________________________________________________________________

// DecryptPoint decrypts an elliptic point from an El-Gamal cipher text.
func DecryptPoint(prikey kyber.Scalar, c CipherText) kyber.Point {
	S := SuiTe.Point().Mul(prikey, c.K) // regenerate shared secret
	M := SuiTe.Point().Sub(c.C, S)      // use to un-blind the message
	return M
}

// DecryptInt decrypts an integer from an ElGamal cipher text where integer are
// encoded in the exponent.
func DecryptInt(prikey kyber.Scalar, cipher CipherText) int64 {
	M := DecryptPoint(prikey, cipher)
	return discreteLog(M, false)
}

// DecryptIntVector decrypts a cipherVector.
func DecryptIntVector(prikey kyber.Scalar, cipherVector *CipherVector) []int64 {
	result := make([]int64, len(*cipherVector))
	for i, c := range *cipherVector {
		result[i] = DecryptInt(prikey, c)
	}
	return result
}

// Brute-force the discrete log go get scalar integer
func GetPointToInt(P kyber.Point) int64 {
	return discreteLog(P, false)
}

// Brute-Forces the discrete log for integer decoding.
func discreteLog(P kyber.Point, checkNeg bool) int64 {
	B := SuiTe.Point().Base()
	var Bi kyber.Point
	var m int64

	object, ok := PointToInt.Get(P.String())
	if ok == nil && object != nil {
		return object.(int64)
	}
	mutex.Lock()
	if currentGreatestInt == 0 {
		currentGreatestM = SuiTe.Point().Null()
	}

	BiNeg := SuiTe.Point().Neg(B)
	for Bi, m = currentGreatestM, currentGreatestInt; !Bi.Equal(P) && !SuiTe.Point().Neg(Bi).Equal(P) && m < MaxHomomorphicInt; Bi, m = Bi.Add(Bi, B), m+1 {
		if checkNeg {
			BiNeg := SuiTe.Point().Neg(Bi)
			PointToInt.Put(BiNeg.String(), -m)
		}
		PointToInt.Put(Bi.String(), m)
	}
	currentGreatestM = Bi
	PointToInt.Put(BiNeg.String(), -m)
	PointToInt.Put(Bi.String(), m)
	currentGreatestInt = m

	//no negative responses
	if m == MaxHomomorphicInt {
		return 0
	}
	mutex.Unlock()

	if SuiTe.Point().Neg(Bi).Equal(P) {
		return -m
	}
	return m
}

// Homomorphic operations
//______________________________________________________________________________________________________________________

// Add two ciphertexts and stores result in receiver.
func (c *CipherText) Add(c1, c2 CipherText) {
	c.C.Add(c1.C, c2.C)
	c.K.Add(c1.K, c2.K)
}

// Add two ciphervectors and stores result in receiver.
func (cv *CipherVector) Add(cv1, cv2 CipherVector) {
	var wg sync.WaitGroup
	if PARALLELIZE {
		for i := 0; i < len(cv1); i = i + VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < VPARALLELIZE && (j+i < len(cv1)); j++ {
					(*cv)[i+j].Add(cv1[i+j], cv2[i+j])
				}
				defer wg.Done()
			}(i)

		}

	} else {
		for i := range cv1 {
			(*cv)[i].Add(cv1[i], cv2[i])
		}
	}
	if PARALLELIZE {
		wg.Wait()
	}
}

// String returns a string representation of a ciphertext.
func (c *CipherText) String() string {
	cstr := "nil"
	kstr := cstr
	if (*c).C != nil {
		cstr = (*c).C.String()[1:7]
	}
	if (*c).K != nil {
		kstr = (*c).K.String()[1:7]
	}
	return fmt.Sprintf("CipherText{%s,%s}", kstr, cstr)
}

// Conversion
//______________________________________________________________________________________________________________________

// ToBytes converts a CipherVector to a byte array
func (cv *CipherVector) ToBytes() ([]byte, int) {
	b := make([]byte, 0)

	for _, el := range *cv {
		b = append(b, el.ToBytes()...)
	}

	return b, len(*cv)
}

// FromBytes converts a byte array to a CipherVector. Note that you need to create the (empty) object beforehand.
func (cv *CipherVector) FromBytes(data []byte, length int) {
	*cv = make(CipherVector, length)
	for i, pos := 0, 0; i < length*64; i, pos = i+64, pos+1 {
		ct := CipherText{}
		ct.FromBytes(data[i : i+64])
		(*cv)[pos] = ct
	}
}

// ToBytes converts a CipherText to a byte array
func (c *CipherText) ToBytes() []byte {
	k, errK := (*c).K.MarshalBinary()
	if errK != nil {
		log.Fatal(errK)
	}
	cP, errC := (*c).C.MarshalBinary()
	if errC != nil {
		log.Fatal(errC)
	}
	b := append(k, cP...)

	return b
}

// FromBytes converts a byte array to a CipherText. Note that you need to create the (empty) object beforehand.
func (c *CipherText) FromBytes(data []byte) {
	(*c).K = SuiTe.Point()
	(*c).C = SuiTe.Point()

	(*c).K.UnmarshalBinary(data[:32])
	(*c).C.UnmarshalBinary(data[32:])
}

// AbstractPointsToBytes converts an array of kyber.Point to a byte array
func AbstractPointsToBytes(aps []kyber.Point) []byte {
	var err error
	var apsBytes []byte
	response := make([]byte, 0)

	for i := range aps {
		apsBytes, err = aps[i].MarshalBinary()
		if err != nil {
			log.Fatal(err)
		}

		response = append(response, apsBytes...)
	}
	return response
}

// BytesToAbstractPoints converts a byte array to an array of kyber.Point
func BytesToAbstractPoints(target []byte) []kyber.Point {
	var err error
	aps := make([]kyber.Point, 0)

	for i := 0; i < len(target); i += 32 {
		ap := SuiTe.Point()
		if err = ap.UnmarshalBinary(target[i : i+32]); err != nil {
			log.Fatal(err)
		}

		aps = append(aps, ap)
	}
	return aps
}
