package decenarch

/*
This holds the messages used to communicate with the service over the network.
*/

import (
	"github.com/dedis/onet"
	"github.com/dedis/onet/network"
	cosiservice "gopkg.in/dedis/cothority.v1/cosi/service"

	"github.com/dedis/student_17_decenar/protocol"
)

// We need to register all messages so the network knows how to handle them.
func init() {
	for _, msg := range []interface{}{
		SaveRequest{}, SaveResponse{},
		RetrieveRequest{}, RetrieveResponse{},
	} {
		network.RegisterMessage(msg)
	}
}

const (
	// ErrorParse indicates an error while parsing the protobuf-file.
	ErrorParse = iota + 4000
	// CachePath indicates where to cache retrieved websites
	CachePath = "/tmp/cocache"
)

// SaveRequest will save the website in the conodes using the protocol and
// return the exit state of the saving process
type SaveRequest struct {
	Url    string
	Roster *onet.Roster
}

// SaveResponse return an error if the website could not be saved correctly
//     - Times  collect statistic times in form key;decenarch.StatTimeFormat
type SaveResponse struct {
	Times []string
}

// RetrieveRequest will retreive the website from the conode using the protocol
// and return the website file
type RetrieveRequest struct {
	Url       string
	Roster    *onet.Roster
	Timestamp string
}

// RetrieveResponse return the website requested.
// - Path is the path to the page requested on the filesystem
type RetrieveResponse struct {
	Main Webstore
	Adds []Webstore
}

// Webstore is used to store website
//    - Url is the address of the page
//    - ContentType is the MIME TYPE
//    - Sig is the collective signature for  base64.StdEncoding.DecodeString(Page)
//    - Page is a base64 string representing a []byte
//    - AddsUrl is the urls of the attached additional ressources
//    - Timestamp is the time at which the page was retrieved format 2006/01/02 15:04
type Webstore struct {
	Url         string
	ContentType string
	Sig         *cosiservice.SignatureResponse
	Page        string
	AddsUrl     []string
	Timestamp   string
}

// Webproof is the proof of the consensus code. It prooves that the leader
// does not add content to the html code produced in Page
//    - RefTree is the reference tree used to create the page
//    - SeenMap is all the seen array used in the consensus protocol
//    - SigMap is all the signature used in the consensus protocol
type Webproof struct {
	Url       string
	Sig       *cosiservice.SignatureResponse
	Page      string
	Timestamp string

	RefTree []protocol.ExplicitNode
	SeenMap map[string][]byte
	SigMap  map[string][]byte
}
