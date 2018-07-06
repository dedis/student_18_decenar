package lib

import (
	"fmt"
	"sync"

	decenarch "github.com/dedis/student_18_decenar"
	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/proof/dleq"
	"gopkg.in/dedis/kyber.v2/sign/schnorr"
	"gopkg.in/dedis/onet.v2"
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
	EncryptedCBFSetSignature []byte
	TreeNodeID               onet.TreeNodeID
	EncryptedBloomFilter     []byte
}

func (p *CompleteProofs) VerifyCompleteProofs() bool {
	fmt.Println("")
	fmt.Println("   Start verification function")
	for _, v := range *p {
		// verify also my proofs, to be sure that root did nothing wrong
		if !v.VerifyCompleteProof() {
			return false
		}
	}

	return true
}

func (p *CompleteProof) VerifyCompleteProof() bool {
	fmt.Print("    Verify complete proofs of node ", p.PublicKey.String(), "...")
	// for both leaf and non leaf node we verify the signature of the
	// ciphervector, i.e. the encrypted CBF set. Note that if the node creating this proof spoof someone's else identity, by using it's public key, this proof will not work and therefore it will be rejected.
	//bytesEncryptedSet, _ := p.AggregationProof.Aggregation.ToBytes()
	bytesEncryptedSet := p.AggregationProof.Aggregation
	hashed := decenarch.Suite.Hash().Sum(bytesEncryptedSet)
	vErr := schnorr.Verify(decenarch.Suite, p.PublicKey, hashed, p.EncryptedCBFSetSignature)
	if vErr != nil {
		return false
	}

	// verify if the node is a leaf
	tree, err := p.TreeMarshal.MakeTree(p.Roster)
	if err != nil {
		return false
	}

	// verify that the node is really who he claims to be
	treeNode := tree.Search(p.TreeNodeID)
	if !treeNode.ServerIdentity.Public.Equal(p.PublicKey) {
		return false
	}

	// the node is a leaf
	isLeaf := len(treeNode.Children) == 0

	// we use the aggregation length since it is the same as the Bloom filter length
	filter := make(CipherVector, p.AggregationProof.Length)
	filter.FromBytes(p.EncryptedBloomFilter, p.AggregationProof.Length)

	// if the node responsible of this complete proof is a leaf, we only
	// have to verify the signature of the ciphervector and the proof that
	// the ciphervector containts only zeros and ones, since a leaf node is
	// not responsible of aggregating ciphervectors of other conodes
	if isLeaf {
		GreenPrint("OK\n")
		return p.CipherVectorProof.VerifyCipherVectorProof(&filter)
	}

	// if the node isn't a leaf, we verify all the proofs
	outcome := p.AggregationProof.VerifyAggregationProof() && p.CipherVectorProof.VerifyCipherVectorProof(&filter)
	GreenPrint("OK\n")
	return outcome
}

type AggregationProof struct {
	Contributions map[string][]byte
	Aggregation   []byte
	Length        int
}

func CreateAggregationiProof(c map[string][]byte, a []byte, length int) *AggregationProof {
	return &AggregationProof{Contributions: c, Aggregation: a, Length: length}
}

func (p *AggregationProof) VerifyAggregationProof() bool {
	aggregation := make(CipherVector, p.Length)
	aggregation.FromBytes(p.Aggregation, p.Length)

	return p.VerifyAggregationProofWithAggregation(&aggregation)
}

func (p *AggregationProof) VerifyAggregationProofWithAggregation(a *CipherVector) bool {
	tmp := NewCipherVector(len(*a))

	// perform sum
	for _, c := range p.Contributions {
		cipher := make(CipherVector, p.Length)
		cipher.FromBytes(c, p.Length)
		tmp.Add(*tmp, cipher)
	}

	// verify sum
	for j, w := range *a {
		if !w.C.Equal((*tmp)[j].C) {
			return false
		}
		if !w.K.Equal((*tmp)[j].K) {
			return false
		}
	}

	return true
}

type CipherVectorProof []*CipherTextProof

type CipherTextProof struct {
	PublicKey kyber.Point
	Proof     dleq.Proof
}

func CreateCipherTextProof(c *CipherText, publicKey kyber.Point, blinding kyber.Scalar) *CipherTextProof {
	p, _, _, _ := dleq.NewDLEQProof(decenarch.Suite, decenarch.Suite.Point().Base(), publicKey, blinding)
	return &CipherTextProof{PublicKey: publicKey, Proof: *p}
}

func (p *CipherVectorProof) VerifyCipherVectorProof(cv *CipherVector) bool {
	ch := make(chan bool, len(*p))
	var wg sync.WaitGroup

	// constants for proof verification
	zeroPoint := ZeroToPoint()
	onePoint := OneToPoint()
	base := decenarch.Suite.Point().Base()

	// verifiy all proofs
	for i, cipherTextProof := range *p {
		wg.Add(1)
		go cipherTextProof.verify((*cv)[i], ch, &wg, zeroPoint, onePoint, base)
	}
	// wait for proof to be verified
	wg.Wait()
	close(ch)

	// analyze outcomes of proofs verification
	for outcome := range ch {
		if !outcome {
			return false
		}
	}

	return true
}

func (p *CipherTextProof) verify(c CipherText, ch chan bool, wg *sync.WaitGroup, zeroPoint, onePoint, base kyber.Point) {
	C := c.C
	K := c.K
	cMinusZero := decenarch.Suite.Point().Sub(C, zeroPoint)
	cMinusOne := decenarch.Suite.Point().Sub(C, onePoint)
	zeroProof := p.Proof.Verify(decenarch.Suite, base, p.PublicKey, K, cMinusZero)
	oneProof := p.Proof.Verify(decenarch.Suite, base, p.PublicKey, K, cMinusOne)

	// normally the condition would be
	// (zeroProof != nil && oneProof != nil) || (zeroProof == nil && oneProof == nil),
	// but since it is by construction impossible that the two proofs are valid at
	// the same time, we can use only the first contidion in the if clause
	if zeroProof != nil && oneProof != nil {
		ch <- false
	}
	ch <- true
	wg.Done()
}
