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
	"gopkg.in/dedis/onet.v1/network"
)

// Name can be used from other packages to refer to this protocol.
const Name = "Decenarch"
const SaveName = Name + "Save"
const RetrieveName = Name + "Retrieve"

// ***************** Struct for DecenarchSave ****************************** //

// SavePhase is an indicator of the behaviour to have for a child of the
// root in the protocol.
type SavePhase uint32

const (
	NilPhase SavePhase = iota
	Consensus
	RequestMissingPath
	CoSigning
	SkipchainSaving
	End
)

// PathHash represent a unique identifier for a path
type PathHash string

// Signatures are the signatures of the differents conodes that
// happens to match the HashPath. The number of signature is the number of
// occurence of the path. The key is the server identity of the signing server.
type PathSignatures map[*network.ServerIdentity][]byte

// WeightedPath represent one path in an html or css tree.
type WeightedPath map[PathHash]PathSignatures

// SaveAnnounce is used to pass a message to all children when the protocol
// called is DecenarchSave
type SaveAnnounce struct {
	Phase SavePhase
	Url   string
	Paths WeightedPath
}

// StructSaveAnnounce just contains SaveAnnounce and the data necessary to
// identify and process the message in the sda framework.
type StructSaveAnnounce struct {
	*onet.TreeNode
	SaveAnnounce
}

// SaveReply returns the Hash computed by the children of the website and the
// errors that happens
type SaveReply struct {
	Phase        SavePhase
	Url          string
	Errs         []error
	WeightTree   WeightedPath
	MissingPaths map[PathHash][]*html.Node
}

// StructSaveReply just contains StructSaveReply and the data necessary to
// identify and process the message in the sda framework.
type StructSaveReply struct {
	*onet.TreeNode
	SaveReply
}

// ***************** Struct for DecenarchRetrieve ************************** //

// RetrieveAnnounce is used to pass a message to the children when the protocol
// called is DecenarchRetrieve
type RetrieveAnnounce struct {
	Url string
}

// StructRetrieveAnnounce just contains RetrieveAnnounce and the data necessary
// to identify and process the message in the sda framework
type StructRetrieveAnnounce struct {
	*onet.TreeNode
	RetrieveAnnounce
}

// RetrieveReply return the data of the requested webpage. The key of the map
// is the path that must be used to save the file in the cache.
type RetrieveReply struct {
	Data map[string][]byte
}

// StructRetrieveReply just contains RetrieveReply and the data necessary
// to identify and process the message in the sda framework
type StructRetrieveReply struct {
	*onet.TreeNode
	RetrieveReply
}
