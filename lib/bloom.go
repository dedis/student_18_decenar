package lib

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math"
	"math/big"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/net/html"
)

// Counting Bloom filter is a probabilistic data structure
// The code is based on the Bloom filter library by Will Fitzgerald
// (https://github.com/willf/bloom), adapted to implement counting
// Bloom filter instead of simple filter
type CBF struct {
	Set []int64 // the counting Bloom filter byte set
	M   uint    // maximal number of buckets
	K   uint    // number of hash functions
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
	return &CBF{Set: make([]int64, param[0]), M: param[0], K: param[1]}
}

func BloomFilterFromSet(set []int64, param []uint) *CBF {
	return &CBF{Set: set, M: param[0], K: param[1]}
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
	// TODO: check if this is the adapted zero value to return
	if root == nil {
		return []uint{0, 0}
	}
	uniqueLeaves := uint(len(listUniqueDataLeaves(root)))
	m, k := bestParameters(uniqueLeaves, 0.0001)

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

// Add add an elements e to the counting Bloom Filter c
func (c *CBF) Add(e []byte) *CBF {
	h := hashes(e)
	for i := uint(0); i < c.K; i++ {
		location := c.location(h, i)
		if c.Set[location] == 0 {
			c.Set[location]++
		}
	}

	// return c to allow chaining
	return c
}

// Count return an estimate of how many times elements e
// has been added to the set
func (c *CBF) Count(e []byte) int64 {
	min := int64(255)
	h := hashes(e)
	for i := uint(0); i < c.K; i++ {
		counter := c.Set[c.location(h, i)]
		if counter < min {
			min = counter
		}
	}

	return min
}

func (c *CBF) getParameters() []uint {
	return []uint{c.M, c.K}
}

func (c *CBF) SetByte(i uint, value int64) {
	c.Set[i] = value
}

func (c *CBF) GetByte(i uint) int64 {
	return c.Set[i]
}

func (c *CBF) GetSet() []int64 {
	if c == nil {
		return nil
	}

	return c.Set
}

// Write writes c to an io.Writer
func (c *CBF) Write(stream io.Writer) error {
	err := binary.Write(stream, binary.BigEndian, uint64(c.M))
	if err != nil {
		return err
	}
	err = binary.Write(stream, binary.BigEndian, uint64(c.K))
	if err != nil {
		return err
	}
	err = binary.Write(stream, binary.BigEndian, c.Set)
	if err != nil {
		return err
	}

	return nil
}

// Encode encodes the CBF c into a slice oy bytes
func (c *CBF) Encode() ([]byte, error) {
	var buf bytes.Buffer
	err := c.Write(&buf)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
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
