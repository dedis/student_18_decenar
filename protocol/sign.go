package protocol

import (
	"bytes"

	"golang.org/x/net/html"
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

	// then we get the leaves of the HTML tree...
	listLeaves := lib.ListUniqueDataLeaves(rootNode)

	// ...and the list of the leaves in the proposed consensus HTML tree
	listLeavesConsensus := vfData.(*VerificationData).Leaves

	// compare the two leaves lists. Note that we test also the order of
	// the leaves for free here (see the implementation of
	// lib.ListUniqueDataLeaves)
	for i := range listLeaves {
		if listLeaves[i] != listLeavesConsensus[i] {
			return false
		}
	}

	// verify all the proofs of the protocol

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
