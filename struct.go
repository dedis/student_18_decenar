package template

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
		CountRequest{}, CountResponse{},
		ClockRequest{}, ClockResponse{},
		SaveRequest{}, SaveResponse{},
		RetrieveRequest{}, RetrieveResponse{},
	} {
		network.RegisterMessage(msg)
	}
}

const (
	// ErrorParse indicates an error while parsing the protobuf-file.
	ErrorParse = iota + 4000
)

// ClockRequest will run the tepmlate-protocol on the roster and return
// the time spent doing so.
type ClockRequest struct {
	Roster *onet.Roster
}

// ClockResponse returns the time spent for the protocol-run.
type ClockResponse struct {
	Time     float64
	Children int
}

// CountRequest will return how many times the protocol has been run.
type CountRequest struct {
}

// CountResponse returns the number of protocol-runs
type CountResponse struct {
	Count int
}

// SaveRequest will save the website in the conodes using the protocol and
// return the exit state of the saving process
type SaveRequest struct {
	Url string
}

// SaveResponse return an error if the website could not be saved correctly
type SaveResponse struct {
}

// RetrieveRequest will retreive the website from the conode using the protocol
// and return the website file
type RetrieveRequest struct {
	Url string
}

// RetrieveResponse return the website file requested
type RetrieveResponse struct {
	//TODO Define Website storage format
	Website []byte
}
