package protocol

/*
Struct holds the messages that will be sent around in the protocol. You have
to define each message twice: once the actual message, and a second time
with the `*onet.TreeNode` embedded. The latter is used in the handler-function
so that it can find out who sent the message.
*/

import (
	"github.com/dedis/student_18_decenar/lib"
	"golang.org/x/net/html"

	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/onet.v2"
)

// Name can be used from other packages to refer to this protocol.
const NameConsensusStructured = "ConsensusStructured"
const NameConsensusUnstructured = "ConsensusUnstructured"

// ***************** Struct for DecenarchSave ****************************** //

// SavePhase is an indicator of the behaviour to have for a child of the
// root in the protocol.
type SavePhase int32

const (
	NilPhase SavePhase = iota
	Consensus
	RequestMissingData
	End
)

// SaveAnnounce is used to pass a message to all children when the protocol
// called is DecenarchSave
//     Url:			url of the webpage the conodes will reach consensus on
//     ParametersCBF:		parameters, i,e, m and k, of the counting Bloom filter
type SaveAnnounceStructured struct {
	Url           string
	ParametersCBF []uint64
}

// StructSaveAnnounce just contains SaveAnnounce and the data necessary to
// identify and process the message in the sda framework.
type StructSaveAnnounceStructured struct {
	*onet.TreeNode
	SaveAnnounceStructured
}

// SaveReply return the protocol status, the consensus data and the errors of
// the conode that executed a save request.
//     Url:		url of the webpage the conodes will reach consensus on
//     Errs:		errors that happends during the protocol
//     EncryptedCBFSet: set of the spectral Bloom filter of a given node merged
//			with the sets of the children's filters. If the node is
//			a child, it contins the classical Bloom filter
//     CBFSetSig:	signature of CBFSet
//     CompleteProofs:  complete proofs of the operations performed by the nodes
type SaveReplyStructured struct {
	Url  string
	Errs []error

	EncryptedCBFSet *lib.CipherVector
	CBFSetSig       []byte

	CompleteProofs lib.CompleteProofs
}

// StructSaveReply
type StructSaveReplyStructured struct {
	*onet.TreeNode
	SaveReplyStructured
}

// Message used to send the complete proofs to the parent
type CompleteProofsAnnounce struct {
	CompleteProofs lib.CompleteProofs
}

// StructCompleteProofsAnnounce
type StructCompleteProofsAnnounce struct {
	*onet.TreeNode
	CompleteProofsAnnounce
}

// SaveAnnounceUnstructured
type SaveAnnounceUnstructured struct {
	Phase      SavePhase
	Url        string
	MasterHash map[string]map[kyber.Point][]byte
}

// StructSaveAnnounceUnstructured
type StructSaveAnnounceUnstructured struct {
	*onet.TreeNode
	SaveAnnounceUnstructured
}

// SaveReplyUnstructured
//     Phase:		phase the protocol is currently
//     Url:		URL of the additional data to be archived
//     Errs:		errors occured during the protocol
//     MasterHash:      updated MasterHash for the given external resource.
//			if the node has seen the resource, it adds it signature
//			to the map.
//     RequestedNode:	the map linking the hash of an AnonNode's data with its
//			plaintext html data.
//     RequestedData:	the map linking the hash of an unstructured data with
//			its plaintext data.
//
type SaveReplyUnstructured struct {
	Phase      SavePhase
	Url        string
	Errs       []error
	MasterHash map[string]map[kyber.Point][]byte

	RequestedNode map[string]html.Node
	RequestedData map[string][]byte
}

// StructSaveAnnounceUnstructured
type StructSaveReplyUnstructured struct {
	*onet.TreeNode
	SaveReplyUnstructured
}
