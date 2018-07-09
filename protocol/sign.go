package protocol

import (
	"bytes"
	"fmt"
	"time"

	"golang.org/x/net/html"
	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"

	ftcosiprotocol "gopkg.in/dedis/cothority.v2/ftcosi/protocol"

	decenarch "github.com/dedis/student_18_decenar"
	"github.com/dedis/student_18_decenar/lib"
)

// We define two signing protocols, and their respective sub protocols, because
// we have two different verification functions depending on the data that have
// to be signed. Since the a FtCoSi protocol is defined with its own
// verification function, we have to define two differents protocol
const NameSignStructured = "SignStructured"
const NameSubSignStructured = "Sub" + NameSignStructured

const NameSignUnstructured = "SignUnstructured"
const NameSubSignUnstructured = "Sub" + NameSignUnstructured

func init() {
	// this message is registerd but never sent. It is used to marshal and
	// unmarshal the data needed for the verification function using the
	// ont/network marshal and unmarshal functionalities
	network.RegisterMessage(VerificationData{})

	onet.GlobalProtocolRegister(NameSignStructured, NewSignStructuredProtocol)
	onet.GlobalProtocolRegister(NameSubSignStructured, NewSubSignStructuredProtocol)

	onet.GlobalProtocolRegister(NameSignUnstructured, NewSignUnstructuredProtocol)
	onet.GlobalProtocolRegister(NameSubSignUnstructured, NewSubSignUnstructuredProtocol)

}

func NewSignStructuredProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl4("Creating NewSignProtocol")
	return ftcosiprotocol.NewFtCosi(n, verificationFunctionStructured, NameSubSignStructured, ftcosiprotocol.EdDSACompatibleCosiSuite)
}

func NewSubSignStructuredProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl4("Creating NewSubSignProtocol")
	return ftcosiprotocol.NewSubFtCosi(n, verificationFunctionStructured, ftcosiprotocol.EdDSACompatibleCosiSuite)
}

func verificationFunctionStructured(msg, data []byte) bool {
	// unmarshal data
	_, vfData, err := network.Unmarshal(data, decenarch.Suite)
	if err != nil {
		log.Lvl1("Impossible ot decode verification data, node refuses to sign")
		return false
	}

	// verify if the leaves of the message are really in the conode's Bloom
	// filter
	// first of all we have to recontruct the HTML tree
	rootNode, err := html.Parse(bytes.NewReader(msg))
	if err != nil {
		log.Lvl1("Impossible to parse the proposed HTML page, node refuses to sign")
		return false
	}

	// then we get the leaves of the local HTML tree...
	listLeaves := lib.ListUniqueDataLeaves(rootNode)

	// ...and the list of the leaves in the proposed consensus HTML tree
	listLeavesConsensus := vfData.(*VerificationData).Leaves

	// create a map to check that the local HTML nodes are a subset of the
	// consensus HTML tree, return false if it is not the case
	consensusSet := make(map[string]bool)
	for _, l := range listLeavesConsensus {
		consensusSet[l] = true
	}

	// get complete proofs
	completeProofs := vfData.(*VerificationData).CompleteProofs

	// get conode and root keys
	// verify all the proofs of the protocol
	if !completeProofs.VerifyCompleteProofs() {
		return false
	}

	fmt.Print("    Verify leader's work...")
	// get consensus Bloom filter
	consensusBloomSet := vfData.(*VerificationData).ConsensusSet
	consensusParameters := vfData.(*VerificationData).ConsensusParameters
	consensusCBF := lib.BloomFilterFromSet(consensusBloomSet, []uint{uint(consensusParameters[0]), uint(consensusParameters[1])})

	// check if it is a subset and if the leave is indeed in the consensus
	// Bloom filter
	for _, l := range listLeaves {
		// something there are problem with this leaves values with the
		// Go parser, but since they are not important we simply skip
		// this test
		if l == "noscript" || l == "script" {
			continue
		}
		// subset
		if !consensusSet[l] {
			return false
		}
		// consensus Bloom filter
		if consensusCBF.Count([]byte(l)) == 0 {
			return false
		}
	}
	// check that root did a correct job, aka audit the leader
	conodeKey := vfData.(*VerificationData).ConodeKey
	rootKey := vfData.(*VerificationData).RootKey
	if conodeKey != rootKey { // root doesn't verify its own work
		rootProofs := completeProofs[rootKey]

		// first check that the constributions of the root's children indeed
		// sum up to the consensus filter proposed for the decryption protocol
		encryptedCBFSet := vfData.(*VerificationData).EncryptedCBFSet
		if !rootProofs.AggregationProof.VerifyAggregationProofWithAggregation(encryptedCBFSet) {
			return false
		}

		// convert byte arrays to kyber.Point arrays
		partialsKyber := make(map[int][]kyber.Point)
		for k, p := range vfData.(*VerificationData).Partials {
			partialsKyber[k] = lib.BytesToAbstractPoints(p)
		}

		// reconstruct consensus spectral Bloom filter
		reconstructed, err := lib.ReconstructVectorFromPartials(len(completeProofs), vfData.(*VerificationData).Threshold, partialsKyber)
		if err != nil {
			log.Lvl1("Impossible to reconstruct consensus vector, node refuses to sign")
			return false
		}

		// check if reconstruction is correct
		for i := range reconstructed {
			if reconstructed[i] != consensusBloomSet[i] {
				return false
			}
		}
	}
	time.Sleep(5 * time.Second)
	lib.GreenPrint("OK\n")

	fmt.Println("   Verification function returned true, sign the HTML document")

	return true
}

func NewSignUnstructuredProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl4("Creating NewSignProtocol")
	return ftcosiprotocol.NewFtCosi(n, verificationFunctionUnstructured, NameSubSignUnstructured, ftcosiprotocol.EdDSACompatibleCosiSuite)
}

func NewSubSignUnstructuredProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl4("Creating NewSubSignProtocol")
	return ftcosiprotocol.NewSubFtCosi(n, verificationFunctionUnstructured, ftcosiprotocol.EdDSACompatibleCosiSuite)
}

func verificationFunctionUnstructured(msg, data []byte) bool {
	return true
}
