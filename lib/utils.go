package lib

import (
	"errors"
	"strings"

	decenarch "github.com/dedis/student_18_decenar"
	"golang.org/x/net/html"
	"gopkg.in/dedis/cothority.v2"
	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/share"
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

// DKGSimulate runs an offline version of the DKG protocol. Used only for tests
func DKGSimulate(nbrNodes, threshold int) (dkgs []*dkg.DistKeyGenerator, err error) {
	dkgs = make([]*dkg.DistKeyGenerator, nbrNodes)
	scalars := make([]kyber.Scalar, nbrNodes)
	points := make([]kyber.Point, nbrNodes)

	// 1a - initialisation
	for i := range scalars {
		scalars[i] = decenarch.Suite.Scalar().Pick(cothority.Suite.RandomStream())
		points[i] = decenarch.Suite.Point().Mul(scalars[i], nil)
	}

	// 1b - key-sharing
	for i := range dkgs {
		dkgs[i], err = dkg.NewDistKeyGenerator(decenarch.Suite, scalars[i], points, threshold)
		if err != nil {
			return
		}
	}
	// Exchange of Deals
	responses := make([][]*dkg.Response, nbrNodes)
	for i, p := range dkgs {
		responses[i] = make([]*dkg.Response, nbrNodes)
		deals, err := p.Deals()
		if err != nil {
			return nil, err
		}
		for j, d := range deals {
			responses[i][j], err = dkgs[j].ProcessDeal(d)
			if err != nil {
				return nil, err
			}
		}
	}
	// ProcessResponses
	for _, resp := range responses {
		for j, r := range resp {
			for k, p := range dkgs {
				if r != nil && j != k {
					p.ProcessResponse(r)
				}
			}
		}
	}

	// Secret commits
	for _, p := range dkgs {
		commit, err := p.SecretCommits()
		if err != nil {
			return nil, err
		}
		for _, p2 := range dkgs {
			p2.ProcessSecretCommits(commit)
		}
	}

	// Verify if all is OK
	for _, p := range dkgs {
		if !p.Finished() {
			return nil, errors.New("one of the dkgs is not finished yet")
		}
	}
	return
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
func ListUniqueDataLeaves(root *html.Node) []string {
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

// ConcatenateErrors take a slice of errors an return a single error which is
// the concatenation of all the errors contained in the slice
func ConcatenateErrors(errs []error) error {
	var errsString []string
	for _, e := range errs {
		errsString = append(errsString, e.Error())
	}

	return errors.New(strings.Join(errsString, "\n"))
}

// ReconstructVectorFromPartials performs Lagrange interpolation with the given
// partial decryptions to reconstruct the jointly encrypted vector
func ReconstructVectorFromPartials(nodes, threshold int, partials map[int][]kyber.Point) ([]int64, error) {
	points := make([]kyber.Point, 0)
	n := nodes
	for i := 0; i < len(partials[0]); i++ {
		shares := make([]*share.PubShare, n)
		for j, partial := range partials {
			shares[j] = &share.PubShare{I: j, V: partial[i]}
		}
		message, err := share.RecoverCommit(decenarch.Suite, shares, threshold, n)
		if err != nil {
			return nil, err
		}
		points = append(points, message)
	}

	// reconstruct the points by computing the dlog
	reconstructed := make([]int64, 0)
	for _, point := range points {
		reconstructed = append(reconstructed, GetPointToInt(point))
	}

	return reconstructed, nil
}
