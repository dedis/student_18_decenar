package decenarch

/*
This holds the messages used to communicate with the service over the network.
*/

import (
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
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
type SaveResponse struct {
}

// RetrieveRequest will retreive the website from the conode using the protocol
// and return the website file
type RetrieveRequest struct {
	Url    string
	Roster *onet.Roster
}

// RetrieveResponse return the website requested.
// @Data is the map containing the raw data of the website. The key is the
// path to the page in the cache.
// @Website is the path in the cache to the requested page. It MUST BE a valid
// key of Data
type RetrieveResponse struct {
	Website string
	Data    map[string][]byte
}
