package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"hash/fnv"
	"io/ioutil"
	"math"

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

func getOptimalCBFParameters(root *AnonNode) []uint {
	if root == nil {
		return []uint{0, 0}
	}
	uniqueLeaves := uint(len(root.ListUniqueDataLeaves()))
	m, k := bestParameters(uniqueLeaves, 0.001)

	return []uint{m, k}
}

// AddUniqueLeaves add to c the unique leaves contained
// in the AnonTree with the given root
func (c *CBF) AddUniqueLeaves(root *AnonNode) *CBF {
	uniqueLeaves := root.ListUniqueDataLeaves()
	for _, l := range uniqueLeaves {
		c.Add([]byte(l))
	}

	return c
}

func NewFilledBloomFilter(param []uint, root *AnonNode) *CBF {
	return NewBloomFilter(param).AddUniqueLeaves(root)
}

// Encrypt
func (c *CBF) Encrypt(s network.Suite, private kyber.Scalar, public kyber.Point) ([]byte, error) {
	// encrypt filter using a DH shared secret to seed AES
	plainText := c.GetSet()
	sharedSecret := s.Point().Mul(private, public)
	byteSharedSecret, err := sharedSecret.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// create new block cipher
	block, err := aes.NewCipher(byteSharedSecret)
	if err != nil {
		return nil, err
	}

	// put IV at the beginning of the ciphertext
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	random.Bytes(iv, s.RandomStream())

	// encrypt plainText
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	// encode in base64 the cipherText
	encodedCipherText := &bytes.Buffer{}
	e := base64.NewEncoder(base64.StdEncoding, encodedCipherText)
	defer e.Close()
	e.Write(cipherText)

	return encodedCipherText.Bytes(), nil
}

// Decrypt
func Decrypt(s network.Suite, private kyber.Scalar, public kyber.Point, encodedCipherText []byte, parameters []uint) (*CBF, error) {
	sharedSecret := s.Point().Mul(private, public)
	byteSharedSecret, err := sharedSecret.MarshalBinary()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(byteSharedSecret)
	if err != nil {
		return nil, err
	}

	// decode cipher text encoded in base64
	d := base64.NewDecoder(base64.StdEncoding, bytes.NewBuffer(encodedCipherText))
	cipherTextAndIV, err := ioutil.ReadAll(d)
	if err != nil {
		return nil, err
	}

	// get IV
	iv := cipherTextAndIV[:aes.BlockSize]
	cipherText := cipherTextAndIV[aes.BlockSize:]

	// decrypt
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return &CBF{Set: cipherText, M: parameters[0], K: parameters[1]}, nil
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

func (c *CBF) MergeSet(set []byte) {
	for i, counter := range set {
		c.Set[i] += counter
	}
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
	cst := []byte("constant")
	hasher := fnv.New128()
	hasher.Write(e)
	sum := hasher.Sum(nil)
	h1 := binary.BigEndian.Uint64(sum[0:])
	h2 := binary.BigEndian.Uint64(sum[8:])
	hasher.Write(cst)
	sum = hasher.Sum(nil)
	h3 := binary.BigEndian.Uint64(sum[0:])
	h4 := binary.BigEndian.Uint64(sum[8:])
	return [4]uint64{h1, h2, h3, h4}
}

// location returns the ith hashed location using the four base hash values
func location(h [4]uint64, i uint) uint64 {
	ii := uint64(i)
	return h[ii%2] + ii*h[2+(((ii+(ii%2))%4)/2)]
}

// location returns the ith hashed location using the four base hash values
func (c *CBF) location(h [4]uint64, i uint) uint {
	return uint(location(h, i) % uint64(c.M))
}

// bestParameters return an estimate of m and k given the number of elements n
// that should be inserted in the set and fpRate, the desired false positive rate
func bestParameters(n uint, fpRate float64) (uint, uint) {
	m := uint(math.Ceil(-1 * float64(n) * math.Log(fpRate) / math.Pow(math.Log(2), 2)))
	k := uint(math.Ceil(math.Log(2) * float64(m) / float64(n)))

	return m, k
}
