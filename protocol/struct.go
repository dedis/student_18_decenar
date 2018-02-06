package protocol

/*
Struct holds the messages that will be sent around in the protocol. You have
to define each message twice: once the actual message, and a second time
with the `*onet.TreeNode` embedded. The latter is used in the handler-function
so that it can find out who sent the message.
*/

import (
	"golang.org/x/net/html"

	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/crypto"

	"gopkg.in/dedis/crypto.v0/abstract"
)

// Name can be used from other packages to refer to this protocol.
const Name = "Decenarch"
const SaveName = Name + "Save"

// ***************** Struct for DecenarchSave ****************************** //

// SavePhase is an indicator of the behaviour to have for a child of the
// root in the protocol.
type SavePhase int32

const (
	NilPhase SavePhase = iota
	Consensus
	RequestMissingData
	CoSigning
	SkipchainSaving
	End
)

// SaveAnnounce is used to pass a message to all children when the protocol
// called is DecenarchSave
//     Phase : the phase the protocol is currently
//     Url : the url of the webpage the conodes will reach consensus on
//     MasterTree : the tree representing structured data with its signatures
//     MasterHash : the hash representing unstructured data with its signatures
type SaveAnnounce struct {
	Phase         SavePhase
	Url           string
	MasterTree    []ExplicitNode
	MasterTreeSig crypto.SchnorrSig
	MasterHash    map[string]map[abstract.Point]crypto.SchnorrSig
}

// StructSaveAnnounce just contains SaveAnnounce and the data necessary to
// identify and process the message in the sda framework.
type StructSaveAnnounce struct {
	*onet.TreeNode
	SaveAnnounce
}

// SaveReply return the protocol status, the consensus data and the errors of
// the conode that executed a save request.
//     Phase : the phase the protocol is currently
//     Url : the url of the webpage the conodes will reach consensus on
//     Errs : the errors that happends during the protocol
//     MasterTree : the tree representing structured data anonymised
//     MasterTreeSig : the signature of the root of the tree, creator of MasterTree
//     MasterHash : the hash representing unstructured data with its signatures
//
//     SeenMap : the map of the Seen field of each service of each conode. the
//               keys are the public keys of the conode.
//     SigMap : the map of the signature associatied with the Seen field of each
//              conodes. For a given public key (abstract.Point) both SigMap and
//              SeenMap must have an entry
//
//     RequestedNode : the map linking the hash of an AnonNode's data with its
//                     plaintext html data.
//     RequestedData : the map linking the hash of an unstructured data with
//                     its plaintext data.
type SaveReply struct {
	Phase         SavePhase
	Url           string
	Errs          []error
	MasterTree    []ExplicitNode //*AnonNode
	MasterTreeSig crypto.SchnorrSig
	MasterHash    map[string]map[abstract.Point]crypto.SchnorrSig

	SeenMap map[string][]byte
	SigMap  map[string]crypto.SchnorrSig

	RequestedNode map[string]html.Node
	RequestedData map[string][]byte
}

// StructSaveReply just contains StructSaveReply and the data necessary to
// identify and process the message in the sda framework.
type StructSaveReply struct {
	*onet.TreeNode
	SaveReply
}
