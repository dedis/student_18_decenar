package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"io/ioutil"
	"math"
	"math/big"

	"golang.org/x/crypto/hkdf"
	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/util/random"
	"gopkg.in/dedis/onet.v2/network"
)

// Counting Bloom filter is a probabilistic data structure
// The code is based on the Bloom filter library by Will Fitzgerald
// (https://github.com/willf/bloom), adapted to implement counting
// Bloom filter instead of simple filter
type CBF struct {
	Set []byte // the counting Bloom filter byte set
	M   uint   // maximal number of buckets
	K   uint   // number of hash functions
}

// NewOptimalBloomFilter returns a pointer to a CBF whose parameters are
// optimal to store the unique leaves of the tree with the root given as
// parameter of the function. Return nil if root is nil, this is used
// to generalize the code in save.go and handle the additional data case
func NewOptimalBloomFilter(root *AnonNode) *CBF {
	if root == nil {
		return &CBF{}
	}
	return NewBloomFilter(getOptimalCBFParameters(root))
}

// NewBloomFilter returns a pointer to a CBF with the given parameters, i.e.
// with the given M and K
func NewBloomFilter(param []uint) *CBF {
	return &CBF{Set: make([]byte, param[0]), M: param[0], K: param[1]}
}

// GetOptimalCBFParametersToSend returns the optimal parameters, i.e. M and K,
// for the tree rooted by root as []uint64 type. This is used to send the
// parameters using protobuf
func GetOptimalCBFParametersToSend(root *AnonNode) []uint64 {
	p := getOptimalCBFParameters(root)
	return []uint64{uint64(p[0]), uint64(p[1])}
}

// GetOptimalCBFParametersToSend returns the optimal parameters, i.e. M and K,
// for the tree rooted by root as []uint type
func getOptimalCBFParameters(root *AnonNode) []uint {
	// TODO: check if this is the adapted zero value to return
	if root == nil {
		return []uint{0, 0}
	}
	uniqueLeaves := uint(len(root.ListUniqueDataLeaves()))
	m, k := bestParameters(uniqueLeaves, 0.001)

	return []uint{m, k}
}

// AddUniqueLeaves add to c the unique leaves contained
// in the AnonTree with the root given as parameter
// Return the CBF to allow chaining
func (c *CBF) AddUniqueLeaves(root *AnonNode) *CBF {
	uniqueLeaves := root.ListUniqueDataLeaves()
	for _, l := range uniqueLeaves {
		c.Add([]byte(l))
	}

	return c
}

// NewFilledBloomFilter create a new Bloom filter with the given parameters,
// add the unique leaves contained in the AnonTree with the given root and
// return the Bloom filter
func NewFilledBloomFilter(param []uint, root *AnonNode) *CBF {
	return NewBloomFilter(param).AddUniqueLeaves(root)
}

// Encrypt take the Set of the CBF c, encrypt it using AES-GCM, to protect the integrity of the
// ciphertext, and return the base64 encoded ciphertext
func (c *CBF) Encrypt(s network.Suite, private kyber.Scalar, public kyber.Point) ([]byte, error) {
	plainText := c.GetSet()

	// compute DH shared key
	sharedSecret := s.Point().Mul(private, public)

	// get AEAD cipher
	gcm, err := newAEAD(s.(kyber.HashFactory).Hash, sharedSecret)
	if err != nil {
		return nil, err
	}

	// generate nonce
	nonce := make([]byte, gcm.NonceSize())
	random.Bytes(nonce, s.RandomStream())

	// encrypt the plaintext, the output takes the form noce||ciphertext||tag
	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	// encode in base64 the cipherText
	encodedCipherText := &bytes.Buffer{}
	e := base64.NewEncoder(base64.StdEncoding, encodedCipherText)
	defer e.Close()
	e.Write(cipherText)

	return encodedCipherText.Bytes(), nil
}

// Decrypt returns a CBF with the parameters given as argument and the set decrypted from the given ciphertext
func Decrypt(s network.Suite, private kyber.Scalar, public kyber.Point, encodedCipherText []byte, parameters []uint) (*CBF, error) {
	// compute the shared secret, i.e. the AES key
	sharedSecret := s.Point().Mul(private, public)

	// get AEAD cipher
	gcm, err := newAEAD(s.(kyber.HashFactory).Hash, sharedSecret)

	// decode cipher text encoded in base64
	d := base64.NewDecoder(base64.StdEncoding, bytes.NewBuffer(encodedCipherText))
	cipherTextAndNonce, err := ioutil.ReadAll(d)
	if err != nil {
		return nil, err
	}

	// get nonce and ciphertext
	nonce := cipherTextAndNonce[:gcm.NonceSize()]
	cipherText := cipherTextAndNonce[gcm.NonceSize():]

	// decrypt
	CBFSet, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return &CBF{Set: CBFSet, M: parameters[0], K: parameters[1]}, nil
}

// newAEAD returns the AEAD cipher, GCM in this case, used to encrypt the CBF's set
func newAEAD(h func() hash.Hash, DHSharedKey kyber.Point) (cipher.AEAD, error) {
	// get bytes representation of the DH shared key
	byteDHSharedSecret, err := DHSharedKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// derive secure AES key using HKDF
	// Note that key length is hardcoded to 32 bytes
	// TODO: use salt (cf. RFC5869)
	reader := hkdf.New(h, byteDHSharedSecret, nil, nil)
	key := make([]byte, 32)
	_, err = reader.Read(key)
	if err != nil {
		return nil, err
	}

	// create block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// use GCM as mode of operaion
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm, nil
}

// Add add an elements e to the counting Bloom Filter c
func (c *CBF) Add(e []byte) *CBF {
	h := hashes(e)
	for i := uint(0); i < c.K; i++ {
		c.Set[c.location(h, i)]++
	}

	// return c to allow chaining
	return c
}

// Count return an estimate of how many times elements e
// has been added to the set
func (c *CBF) Count(e []byte) byte {
	min := byte(255)
	h := hashes(e)
	for i := uint(0); i < c.K; i++ {
		counter := c.Set[c.location(h, i)]
		if counter < min {
			min = counter
		}
	}

	return min
}

// Merge merges two counting Bloom Filters
func (c *CBF) Merge(cbf *CBF) {
	for i, counter := range cbf.Set {
		c.Set[i] += counter
	}
}

func (c *CBF) RemoveNewZero(newZero byte) {
	for i := range c.Set {
		c.Set[i] -= newZero
	}
}

func (c *CBF) MergeSet(set []byte) {
	for i, counter := range set {
		c.Set[i] += counter
	}
}

// Shuffle returns a shuffled CBF, i.e. a CBF with the same set as c,
// but shuffled. The parameters remain the same. To shuffle the set
// the Fisher–Yates shuffle algorithm is used
// see https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
func (c *CBF) Shuffle(s network.Suite) *CBF {
	maxUint := ^uint(0)
	maxInt := int(maxUint >> 1)
	shuffledCBF := NewBloomFilter(c.getParameters())
	for i := len(c.Set) - 1; i > 0; i-- {
		j := int(random.Int(big.NewInt(int64(maxInt)), s.RandomStream()).Int64()) % (i + 1)
		shuffledCBF.Set[i], shuffledCBF.Set[j] = c.Set[j], c.Set[i]
	}

	return shuffledCBF
}

func (c *CBF) getParameters() []uint {
	return []uint{c.M, c.K}
}

func (c *CBF) GetSet() []byte {
	if c == nil {
		return nil
	}
	return c.Set
}

func (c *CBF) SetByte(i uint, value byte) {
	c.Set[i] = value
}

func (c *CBF) GetByte(i uint) byte {
	return c.Set[i]
}

// hashes returns the four hash of e that are used to create
// the k hash values
func hashes(e []byte) [4]uint64 {
	hasher := sha256.New()
	sum := hasher.Sum(e)
	h1 := binary.BigEndian.Uint64(sum[0:])
	h2 := binary.BigEndian.Uint64(sum[8:])
	h3 := binary.BigEndian.Uint64(sum[16:])
	h4 := binary.BigEndian.Uint64(sum[24:])
	return [4]uint64{h1, h2, h3, h4}
}

// location returns the ith hashed location using the four base hash values
// uses a slightly modified version of the double hashing scheme
// see https://www.eecs.harvard.edu/~michaelm/postscripts/rsa2008.pdf
func (c *CBF) location(h [4]uint64, i uint) uint {
	return uint(h[i%4]+uint64(i)*h[(i+1)%4]) % c.M
}

// bestParameters return an estimate of m and k given the number of elements n
// that should be inserted in the set and fpRate, the desired false positive rate
func bestParameters(n uint, fpRate float64) (uint, uint) {
	m := uint(math.Ceil(-1 * float64(n) * math.Log(fpRate) / math.Pow(math.Log(2), 2)))
	k := uint(math.Ceil(math.Log(2) * float64(m) / float64(n)))

	return m, k
}
