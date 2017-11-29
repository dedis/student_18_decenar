package protocol

import (
	"errors"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/network"
)

/*
This file define all the structures and functions used internally by the protocol
and that are not used as interface to communicate from one conode to another.

More precisely, it contains:
- The structure and the methods used to convert a tree to a map and vice versa.
- The structure and the methods that define an anonymised, signable tree.
*/

// AnonNode define the structure of an anonymised signable node.
// It is used to anonymise an html.Node from "golang.org/x/net/html" package
type AnonNode struct {
	Parent, FirstChild, LastChild, PrevSibling, NextSibling *AnonNode

	HashedData string
	Signatures map[*network.ServerIdentity]crypto.SchnorrSig
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

func (n *AnonNode) Sign(server *network.ServerIdentity, signature crypto.SchnorrSig) {
	if n.Signatures == nil {
		n.Signatures = make(map[*network.ServerIdentity]crypto.SchnorrSig)
	}
	n.Signatures[server] = signature
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
	for c := n; c != nil; c = n.Parent {
		height += 1
	}
	for c := that; c != nil; c = that.Parent {
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
//        R       X   · commonAncestor(   A-R, D-B-R ) =  0, E
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
	Children []int64

	HashedData string
	Signatures map[*network.ServerIdentity]crypto.SchnorrSig
}

// nodeToExplicitNode take an AnonNode as input and output an ExplicitNode
// with the same data as AnonNode but without any family reference (namely
// no parent, children and sibling).
func nodeToExplicitNode(n *AnonNode) ExplicitNode {
	en := ExplicitNode{
		Children:   make([]int64, 0),
		HashedData: n.HashedData,
		Signatures: n.Signatures}
	return en
}

// explicitNodeToNode take an ExplicitNode and output an AnonNode with the
// same data as the ExplicitNode but without any family reference (namely
// no parent, children and sibling).
func explicitNodeToNode(en ExplicitNode) AnonNode {
	n := AnonNode{
		HashedData: en.HashedData,
		Signatures: en.Signatures,
	}
	return n
}

// convertToAnonTree takes an array of ExplicitNode that represent a tree and
// outputs a pointer to an AnonNode that correspond to the root of a tree of
// AnonNodes.
func convertToAnonTree(explicitTree []ExplicitNode) *AnonNode {
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
