package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"math"
	"math/big"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/html"
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
func NewOptimalBloomFilter(root *html.Node) *CBF {
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
func GetOptimalCBFParametersToSend(root *html.Node) []uint64 {
	p := getOptimalCBFParameters(root)
	return []uint64{uint64(p[0]), uint64(p[1])}
}

// GetOptimalCBFParametersToSend returns the optimal parameters, i.e. M and K,
// for the tree rooted by root as []uint type
func getOptimalCBFParameters(root *html.Node) []uint {
	// if root is nil we return M = K = 0, this is done to keep the code
	// generic and handle also the additional unstructured resources, such
	// as images
	if root == nil {
		return []uint{0, 0}
	}
	uniqueLeaves := uint(len(listUniqueDataLeaves(root)))
	m, k := bestParameters(uniqueLeaves, 0.001)

	return []uint{m, k}
}

// AddUniqueLeaves add to c the unique leaves contained
// in the AnonTree with the root given as parameter
// Return the CBF to allow chaining
func (c *CBF) AddUniqueLeaves(root *html.Node) *CBF {
	uniqueLeaves := listUniqueDataLeaves(root)
	for _, l := range uniqueLeaves {
		c.Add([]byte(l))
	}

	return c
}

// NewFilledBloomFilter create a new Bloom filter with the given parameters,
// add the unique leaves contained in the AnonTree with the given root and
// return the Bloom filter
func NewFilledBloomFilter(param []uint, root *html.Node) *CBF {
	return NewBloomFilter(param).AddUniqueLeaves(root)
}

// Encrypt take the Set of the CBF c, encrypt it using AES-GCM, to protect the integrity of the
// ciphertext, and return the base64 encoded ciphertext
func (c *CBF) Encrypt(s network.Suite, private kyber.Scalar, public kyber.Point) ([]byte, error) {
	plain := c.Set

	// compute DH shared key
	sharedSecret := s.Point().Mul(private, public)

	// get AEAD cipher
	gcm, err := newAEAD(s.(kyber.HashFactory).Hash, sharedSecret, public)
	if err != nil {
		return nil, err
	}

	// generate nonce
	nonce := make([]byte, gcm.NonceSize())
	random.Bytes(nonce, s.RandomStream())

	// encrypt the plaintext, the output takes the form noce||ciphertext||tag
	cipher := gcm.Seal(nonce, nonce, plain, nil)

	// encode in base64 the cipherText
	// Note that we have to use RawStdEncoding because simply StdEncoding
	// does not work, because of padding
	encodedCipher := make([]byte, base64.RawStdEncoding.EncodedLen(len(cipher)))
	base64.RawStdEncoding.Encode(encodedCipher, cipher)

	//return encodedCipherText.Bytes(), nil
	//return cipher, nil
	return encodedCipher, nil
}

// Decrypt returns a CBF with the parameters given as argument and the set decrypted from the given ciphertext
func Decrypt(s network.Suite, private kyber.Scalar, public kyber.Point, encodedCipher []byte, parameters []uint) (*CBF, error) {
	// compute the shared secret, i.e. the AES key
	sharedSecret := s.Point().Mul(private, public)

	// get AEAD cipher
	gcm, err := newAEAD(s.(kyber.HashFactory).Hash, sharedSecret, public)
	if err != nil {
		return nil, err
	}

	// decode cipher text encoded in base64
	cipherAndNonce := make([]byte, base64.RawStdEncoding.DecodedLen(len(encodedCipher)))
	_, err = base64.RawStdEncoding.Decode(cipherAndNonce, encodedCipher)
	if err != nil {
		return nil, err
	}

	// get nonce and ciphertext
	nonce := cipherAndNonce[:gcm.NonceSize()]
	cipher := cipherAndNonce[gcm.NonceSize():]

	// decrypt
	CBFSet, err := gcm.Open(nil, nonce, cipher, nil)
	if err != nil {
		return nil, err
	}

	return &CBF{Set: CBFSet, M: parameters[0], K: parameters[1]}, nil
}

// newAEAD returns the AEAD cipher, GCM in this case, used to encrypt the CBF's set
func newAEAD(h func() hash.Hash, DHSharedKey kyber.Point, public kyber.Point) (cipher.AEAD, error) {
	// get bytes representation of the DH shared key
	byteDHSharedSecret, err := DHSharedKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// derive secure AES key using HKDF
	// Note that key length is hardcoded to 32 bytes
	salt := sha256.Sum256([]byte(public.String()))
	reader := hkdf.New(h, byteDHSharedSecret, salt[:], nil)
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
		location := c.location(h, i)
		// if we are at the maximum, we keep the maximum to avoid
		// overflow
		if c.Set[location] < 255 {
			c.Set[location]++
		}
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

// RemoveNewZero subtract newZero from every bucket in c
func (c *CBF) RemoveNewZero(newZero byte) {
	for i := range c.Set {
		c.Set[i] -= newZero
	}
}

// MergeSet add set to the receiver's set
func (c *CBF) MergeSet(set []byte) {
	for i, counter := range set {
		c.Set[i] += counter
	}
}

// SetByte set bucket i of the receiver's set with the given value
func (c *CBF) SetByte(i uint, value byte) {
	c.Set[i] = value
}

// GetByte returns the bucket i of the receiver's set
func (c *CBF) GetByte(i uint) byte {
	return c.Set[i]
}

// GetSet returns the set of the receiver
func (c *CBF) GetSet() []byte {
	if c == nil {
		return nil
	}

	return c.Set
}

// hashes returns the four hash of e that are used to create
// the k hash values
func hashes(e []byte) [2]*big.Int {
	sumSHA := sha256.Sum256(e)
	a := new(big.Int)
	a.SetBytes(sumSHA[:])
	sumBlake := blake2b.Sum256(e)
	b := new(big.Int)
	b.SetBytes(sumBlake[:])

	return [2]*big.Int{a, b}

}

// location returns the ith hashed location using the four base hash values
// uses a slightly modified version of the double hashing scheme
// see https://www.eecs.harvard.edu/~michaelm/postscripts/rsa2008.pdf
func (c *CBF) location(h [2]*big.Int, i uint) uint {
	secondHash := new(big.Int)
	sum := new(big.Int)
	res := new(big.Int)
	secondHash.Mul(big.NewInt(int64(i)), h[1])
	sum.Add(h[0], secondHash)
	res.Mod(sum, big.NewInt(int64(c.M)))

	return uint(res.Uint64())
}

// bestParameters return an estimate of m and k given the number of elements n
// that should be inserted in the set and fpRate, the desired false positive rate
func bestParameters(n uint, fpRate float64) (uint, uint) {
	m := uint(math.Ceil(-1 * float64(n) * math.Log(fpRate) / math.Pow(math.Log(2), 2)))
	k := uint(math.Ceil(math.Log(2) * float64(m) / (float64(n))))

	return m, k
}

// listUniqueDataLeaves takes the root of an HTML tree as input and
// outputs an array that contains all the unique leaves of the tree. To
// define if a leaf is unique, the content of the leaf is taken into account.
// The leaves data are ordered from the most right one to the most left one.
//     Example:
//                  R
//                 /|\
//     the tree   A D C   will output [F,D,E]
//               / \   \
//              D   E   F
func listUniqueDataLeaves(root *html.Node) []string {
	leaves := make([]string, 0)
	discovered := make(map[string]bool)
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.FirstChild == nil { // it is a leaf
			if !discovered[n.Data] {
				discovered[n.Data] = true
				leaves = append(leaves, n.Data)
			}

		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(root)
	return leaves
}
