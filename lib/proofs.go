package lib

import (
	"fmt"
	"reflect"

	decenarch "github.com/dedis/student_18_decenar"
	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/proof/dleq"
	"gopkg.in/dedis/kyber.v2/sign/schnorr"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
)

type CompleteProofs map[string]*CompleteProof

// CompleteProof contains all the proofs a node has to provide in order to
// verify that he followed the protocol without cheating
type CompleteProof struct {
	Roster                   *onet.Roster
	TreeMarshal              *onet.TreeMarshal
	PublicKey                kyber.Point
	AggregationProof         *AggregationProof
	CipherVectorProof        *CipherVectorProof
	EncryptedCBFSet          *CipherVector
	EncryptedCBFSetSignature []byte
}

func (p *CompleteProofs) VerifyCompleteProofs() bool {
	for _, v := range *p {
		if !v.VerifyCompleteProof() {
			return false
		}
	}

	return true
}

func (p *CompleteProof) VerifyCompleteProof() bool {
	// for both leaf and non leaf node we verify the signature of the
	// ciphervector, i.e. the encrypted CBF set. Note that if the node creating this proof spoof someone's else identity, by using it's public key, this proof will not work and therefore it will be rejected.
	bytesEncryptedSet, _ := p.EncryptedCBFSet.ToBytes()
	hashed := decenarch.Suite.Hash().Sum(bytesEncryptedSet)
	vErr := schnorr.Verify(decenarch.Suite, p.PublicKey, hashed, p.EncryptedCBFSetSignature)
	if vErr != nil {
		fmt.Println(vErr)
		return false
	}

	// verify if the node is a leaf
	tree, err := p.TreeMarshal.MakeTree(p.Roster)
	if err != nil {
		log.Lvl1("error during MakeTree(), proof is rejected")
		return false
	}

	// verify that the node is really who he claims to be
	if !tree.Root.ServerIdentity.Public.Equal(p.PublicKey) {
		return false
	}

	// the node is a leaf?
	isLeaf := len(tree.Root.Children) == 0

	// if the node responsible of this complete proof is a leaf, we only
	// have to verify the signature of the ciphervector and the proof that
	// the ciphervector containts only zeros and ones, since a leaf node is
	// not responsible of aggregating ciphervectors of other conodes
	if isLeaf {
		return p.CipherVectorProof.VerifyCipherVectorProof()
	}

	// if the node isn't a leaf, we verify all the proofs
	return p.AggregationProof.VerifyAggregationProof() && p.CipherVectorProof.VerifyCipherVectorProof()
}

type AggregationProof struct {
	Contributions map[string]*CipherVector
	Aggregation   *CipherVector
}

func CreateAggregationiProof(c map[string]*CipherVector, a *CipherVector) *AggregationProof {
	return &AggregationProof{Contributions: c, Aggregation: a}
}

func (p *AggregationProof) VerifyAggregationProof() bool {
	tmp := NewCipherVector(len(*p.Aggregation))
	for _, c := range p.Contributions {
		tmp.Add(*tmp, *c)
	}

	return reflect.DeepEqual(tmp, p.Aggregation)
}

type CipherVectorProof []*CipherTextProof

type CipherTextProof struct {
	PublicKey  kyber.Point
	CipherText *CipherText
	Proof      *dleq.Proof
}

func CreateCipherTextProof(c *CipherText, publicKey kyber.Point, blinding kyber.Scalar) *CipherTextProof {
	Proof, _, _, _ := dleq.NewDLEQProof(decenarch.Suite, decenarch.Suite.Point().Base(), publicKey, blinding)
	return &CipherTextProof{PublicKey: publicKey, CipherText: c, Proof: Proof}
}

func (p *CipherVectorProof) VerifyCipherVectorProof() bool {
	c := make(chan bool, len(*p))
	for _, cipherTextProof := range *p {
		go cipherTextProof.verify(c)
	}

	// analyze outcomes
	for outcome := range c {
		if !outcome {
			return false
		}
	}

	return true
}

func (p *CipherTextProof) verify(c chan bool) {
	C := p.CipherText.C
	K := p.CipherText.K
	cMinusZero := decenarch.Suite.Point().Sub(C, ZeroToPoint())
	cMinusOne := decenarch.Suite.Point().Sub(C, OneToPoint())
	zeroProof := p.Proof.Verify(decenarch.Suite, decenarch.Suite.Point().Base(), p.PublicKey, K, cMinusZero)
	oneProof := p.Proof.Verify(decenarch.Suite, decenarch.Suite.Point().Base(), p.PublicKey, K, cMinusOne)

	if (zeroProof != nil && oneProof != nil) || (zeroProof == nil && oneProof == nil) {
		c <- false
	}
	c <- true
}
