package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"io/ioutil"
	"math"

	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/util/random"
	"gopkg.in/dedis/onet.v2/network"
)

/*
This file define all the structures and functions used internally by the protocol
and that are not used as interface to communicate from one conode to another.

More precisely, it contains:
- The structure and the methods used to convert a tree to a map and vice versa.
- The structure and the methods that define an anonymised tree.
*/

// AnonNode define the structure of an anonymised node.
// It is used to anonymise an html.Node from "golang.org/x/net/html" package
type AnonNode struct {
	Parent, FirstChild, LastChild, PrevSibling, NextSibling *AnonNode

	HashedData string
	Seen       bool
}

// AppendChild adds a node c as a child of p.
// If c already has a parent or siblings, it outputs an error and do nothing.
// Note : This code is identical to the eponym function of "golang.org/x/net/html"
func (n *AnonNode) AppendChild(c *AnonNode) error {
	if c.Parent != nil || c.PrevSibling != nil || c.NextSibling != nil {
		return errors.New("protocol util.go: AppendChild called for an attached child Node")
	}
	last := n.LastChild
	if last != nil {
		last.NextSibling = c
	} else {
		n.FirstChild = c
	}
	n.LastChild = c
	c.Parent = n
	c.PrevSibling = last
	return nil
}

// RemoveChild removes a node c that is a child of n. Afterwards, c will have
// no parent and no siblings.
//
// It will panic if c's parent is not n.
// Note : This code is identical to the eponym function of "golang.org/x/net/html"
func (n *AnonNode) RemoveChild(c *AnonNode) error {
	if c.Parent != n {
		return errors.New("protocol util.go: RemoveChild called for a non-child Node")
	}
	if n.FirstChild == c {
		n.FirstChild = c.NextSibling
	}
	if c.NextSibling != nil {
		c.NextSibling.PrevSibling = c.PrevSibling
	}
	if n.LastChild == c {
		n.LastChild = c.PrevSibling
	}
	if c.PrevSibling != nil {
		c.PrevSibling.NextSibling = c.NextSibling
	}
	c.Parent = nil
	c.PrevSibling = nil
	c.NextSibling = nil
	return nil
}

// IsSimilarTo tests if two nodes, usually from different trees, share a
// sufficiently high amount of things so that they can be swapped with no
// consequences for both of the tree. Note that the swap would involve the
// nodes only and not their parent/children/siblings.
//     Example:
//      R            R
//     / \          /|\
//    A   A    and A B C
//         \
//          B
// we have exhaustively :
//    * the Rs are similar
//    * all the As are similar
func (n *AnonNode) IsSimilarTo(that *AnonNode) bool {
	if n == nil && that == nil {
		return true
	}
	if n != nil || that != nil {
		return false
	}

	sameData := n.HashedData == that.HashedData

	height := 0
	for c := n; c != nil; c = c.Parent {
		height += 1
	}
	for c := that; c != nil; c = c.Parent {
		height -= 1
	}
	sameHeight := height == 0

	return sameData && sameHeight
}

// IsIdenticalTo tests if two nodes are identical to each other.
//     Example:
//      R            R
//     / \          /|\
//    A   A    and A B C
//         \
//          B
// we have exhaustively that every node is identical with itself only.
func (n *AnonNode) IsIdenticalTo(that *AnonNode) bool {
	return n == that
}

// ListLeaves takes the root of an AnonNode tree as input and
// outputs an array that contains all the leaves of the tree.
// The leaves are ordered from the most right one to the most left one.
//     Example:
//                  R
//                 /|\
//     the tree   A B C   will output [F,B,E,D]
//               / \   \
//              D   E   F
func (root *AnonNode) ListLeaves() []*AnonNode {
	var stack []*AnonNode
	var discovered map[*AnonNode]bool = make(map[*AnonNode]bool)
	var leaves []*AnonNode = make([]*AnonNode, 0)
	var curr *AnonNode
	stack = append(stack, root)
	for len(stack) != 0 {
		l := len(stack)
		curr = stack[l-1]
		stack = stack[:l-1]
		if !discovered[curr] {
			discovered[curr] = true
			for n := curr.FirstChild; n != nil; n = n.NextSibling {
				stack = append(stack, n)
			}
			if curr.FirstChild == nil {
				leaves = append(leaves, curr)
			}
		}
	}
	return leaves
}

// ListUniqueDataLeaves takes the root of an AnonNode tree as input and
// outputs an array that contains all the unique leaves of the tree. To
// define if a leaf is unique, the content of the leaf is taken into account.
// The leaves data are ordered from the most right one to the most left one.
//     Example:
//                  R
//                 /|\
//     the tree   A D C   will output [F,D,E]
//               / \   \
//              D   E   F
func (root *AnonNode) ListUniqueDataLeaves() []string {
	var stack []*AnonNode
	var discovered map[string]bool = make(map[string]bool)
	var leaves []string = make([]string, 0)
	var curr *AnonNode
	stack = append(stack, root)
	for len(stack) != 0 {
		l := len(stack)
		curr = stack[l-1]
		stack = stack[:l-1]
		if !discovered[curr.HashedData] {
			discovered[curr.HashedData] = true
			for n := curr.FirstChild; n != nil; n = n.NextSibling {
				stack = append(stack, n)
			}
			if curr.FirstChild == nil {
				leaves = append(leaves, curr.HashedData)
			}
		}
	}
	return leaves
}

// ListPaths takes the root of an AnonNode tree as input and output
// an array of array. The latter is the list of all the paths from leaf to
// root of the tree. The paths are ordered from the most right path of the
// tree to the most left one.
//     Example:
//                  R
//                 / \
//     the tree   A   B   will output [ [F,B,R], [E,B,R], [D,B,R], [C,A,R] ]
//               /   /|\
//              C   D E F
func (root *AnonNode) ListPaths() [][]*AnonNode {
	var allPaths [][]*AnonNode = make([][]*AnonNode, 0)
	for _, leaf := range root.ListLeaves() {
		path := make([]*AnonNode, 0)
		for n := leaf; n != nil; n = n.Parent {
			path = append(path, n)
		}
		allPaths = append(allPaths, path)
	}
	return allPaths
}

// commonAncestor takes to paths represented by an array from leaf to parent.
// The paths must comes from the same tree.
// It outputs the common ancestor of those paths as well as the height of that
// ancestor.
//     Example:
//        R       X   · commonAncestor(   A-R, D-B-R ) =  0, R
//       / \      |   · commonAncestor( C-B-R, D-B-R ) =  1, B
//      A   B     Y   · commonAncestor( C-B-R, Z-Y-X ) = -1, nil
//         / \    |
//        C   D   Z
func commonAncestor(path1 []*AnonNode, path2 []*AnonNode) (int, *AnonNode) {
	for i, c1 := range path1 {
		for _, c2 := range path2 {
			if c1.IsIdenticalTo(c2) {
				return len(path1) - 1 - i, c1
			}
		}
	}
	return -1, nil
}

// ExplicitNode always used as a part of an array permits to store a tree of
// AnonNode as an array that can be send through the network and from which the
// original tree can be deterministically reconstructed.
type ExplicitNode struct {
	Children   []int64
	HashedData string
	Seen       bool
}

// nodeToExplicitNode take an AnonNode as input and output an ExplicitNode
// with the same data as AnonNode but without any family reference (namely
// no parent, children and sibling).
func nodeToExplicitNode(n *AnonNode) ExplicitNode {
	en := ExplicitNode{
		Children:   make([]int64, 0),
		HashedData: n.HashedData,
		Seen:       n.Seen,
	}
	return en
}

// explicitNodeToNode take an ExplicitNode and output an AnonNode with the
// same data as the ExplicitNode but without any family reference (namely
// no parent, children and sibling).
func explicitNodeToNode(en ExplicitNode) AnonNode {
	n := AnonNode{
		HashedData: en.HashedData,
		Seen:       en.Seen,
	}
	return n
}

// convertToAnonTree takes an array of ExplicitNode that represent a tree and
// outputs a pointer to an AnonNode that correspond to the root of a tree of
// AnonNodes.
func convertToAnonTree(explicitTree []ExplicitNode) *AnonNode {
	if explicitTree == nil || len(explicitTree) == 0 {
		return nil
	}
	// this list is used to link an explicit node with a node in the
	// constructed tree we have the correspondance:
	//               explicitTree[i] <---> treeNodes[i]
	var treeNodes []*AnonNode = make([]*AnonNode, 0)

	// we create the root node out of all node in order to have a reference
	var root AnonNode = explicitNodeToNode(explicitTree[0])
	treeNodes = append(treeNodes, &root)
	for _, child := range explicitTree[0].Children {
		child := explicitNodeToNode(explicitTree[child])
		(&root).AppendChild(&child)
		treeNodes = append(treeNodes, &child)
	}

	// we apply a similar procedure for all the remaining nodes
	for i, node := range explicitTree {
		if i > 0 {
			var htmlNode *AnonNode = treeNodes[i]
			for _, child := range node.Children {
				child := explicitNodeToNode(explicitTree[child])
				htmlNode.AppendChild(&child)
				treeNodes = append(treeNodes, &child)
			}

		}
	}
	return &root
}

// convertToExplicitTree takes a pointer to an AnonNode that correspond to the
// root of the tree and convert that tree to an array of ExplicitNode.
// The latter can be send through network without any loss of information and
// allows to reconstruct the tree in a deterministic manner.
func convertToExplicitTree(root *AnonNode) []ExplicitNode {
	if root == nil {
		return make([]ExplicitNode, 0)
	}

	var explicitTree []ExplicitNode = make([]ExplicitNode, 0)
	// add nodes in map using BFS
	var queue []*AnonNode
	var discovered map[*AnonNode]bool = make(map[*AnonNode]bool)
	var curr *AnonNode
	queue = append(queue, root)
	firstChildPosition := 1 // because the root will be 0
	for len(queue) != 0 {
		curr = queue[0]
		queue = queue[1:]
		if !discovered[curr] {
			discovered[curr] = true
			explicitCurr := nodeToExplicitNode(curr)
			explicitTree = append(explicitTree, explicitCurr)
			currIdx := len(explicitTree) - 1
			nb_child := 0
			for n := curr.FirstChild; n != nil; n = n.NextSibling {
				queue = append(queue, n)
				explicitTree[currIdx].Children = append(
					explicitTree[currIdx].Children,
					int64(firstChildPosition+nb_child))
				nb_child += 1
			}
			firstChildPosition += nb_child
		}
	}
	return explicitTree
}

// Counting Bloom Filter
// The code is based on the Bloom filter library by Will Fitzgerald:
// https://github.com/willf/bloom
type CBF struct {
	Set []byte // the counting Bloom filter byte set
	M   uint   // maximal number of buckets
	K   uint   // number of hash functions
}

func NewBloomFilter(param []uint) *CBF {
	return &CBF{Set: make([]byte, param[0]), M: param[0], K: param[1]}
}

func NewOptimalBloomFilter(root *AnonNode) *CBF {
	// Bloom filter is used only for HTML data
	if root == nil {
		return &CBF{}
	}
	p := GetOptimalCBFParameters(root)
	return NewBloomFilter(p)
}

func GetOptimalCBFParametersToSend(root *AnonNode) []uint64 {
	param := GetOptimalCBFParameters(root)
	return []uint64{uint64(param[0]), uint64(param[1])}
}

func GetOptimalCBFParameters(root *AnonNode) []uint {
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

func (c *CBF) Encrypt(s network.Suite, private kyber.Scalar, public kyber.Point) ([]byte, error) {
	// encrypt filter using a DH shared secret to seed AES
	plainText := c.GetSet()
	sharedSecret := s.Point().Mul(private, public)
	byteSharedSecret, err := sharedSecret.MarshalBinary()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(byteSharedSecret)
	if err != nil {
		return nil, err
	}
	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	random.Bytes(iv, s.RandomStream())

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return cipherText, nil
}

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
