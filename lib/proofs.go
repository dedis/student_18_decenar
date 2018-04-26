package lib

import (
	"reflect"

	"github.com/dedis/student_18_decenar"
	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/proof/dleq"
)

type CompleteProofs map[string]*CompleteProof

// CompleteProof contains all the proofs a node has to provide in order to
// verify that he followed the protocol without cheating
type CompleteProof struct {
	AggregationProof         *AggregationProof
	CipherVectorProof        *CipherVectorProof
	EncryptedCBFSetSignature []byte
	Leaf                     bool // leafs have one proof less
}

func (p *CompleteProof) VerifyCompleteProof() bool {
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
	for _, cipherTextProof := range *p {
		if !cipherTextProof.verify() {
			return false
		}
	}

	return true
}

func (p *CipherTextProof) verify() bool {
	C := p.CipherText.C
	K := p.CipherText.K
	cMinusZero := decenarch.Suite.Point().Sub(C, ZeroToPoint())
	cMinusOne := decenarch.Suite.Point().Sub(C, OneToPoint())
	zeroProof := p.Proof.Verify(decenarch.Suite, decenarch.Suite.Point().Base(), p.PublicKey, K, cMinusZero)
	oneProof := p.Proof.Verify(decenarch.Suite, decenarch.Suite.Point().Base(), p.PublicKey, K, cMinusOne)

	if (zeroProof != nil && oneProof != nil) || (zeroProof == nil && oneProof == nil) {
		return false
	}
	return true
}
