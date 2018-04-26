package lib

import (
	"errors"

	"golang.org/x/net/html"
	"gopkg.in/dedis/kyber.v2"
	dkg "gopkg.in/dedis/kyber.v2/share/dkg/rabin"
)

// adapted form https://github.com/dedis/cothority/blob/master/evoting/lib/utils.go

// SharedSecret represents the needed information to do shared encryption and decryption.
type SharedSecret struct {
	Index   int
	V       kyber.Scalar
	X       kyber.Point
	Commits []kyber.Point
}

// NewSharedSecret takes an initialized DistKeyGenerator and returns the
// minimal set of values necessary to do shared encryption/decryption.
func NewSharedSecret(dkg *dkg.DistKeyGenerator) (*SharedSecret, error) {
	if dkg == nil {
		return nil, errors.New("no valid dkg given")
	}
	if !dkg.Finished() {
		return nil, errors.New("dkg is not finished yet")
	}
	dks, err := dkg.DistKeyShare()
	if err != nil {
		return nil, err
	}
	return &SharedSecret{
		Index:   dks.Share.I,
		V:       dks.Share.V,
		X:       dks.Public(),
		Commits: dks.Commits,
	}, nil
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
