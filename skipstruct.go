package decenarch

/*
This holds the messages used to communicate with the service over the network.
*/

import (
	skipchain "gopkg.in/dedis/cothority.v1/skipchain"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
)

// We need to register all messages so the network knows how to handle them.
func init() {
	for _, msg := range []interface{}{
		SkipRootStartRequest{}, SkipRootStartResponse{},
		SkipStartRequest{}, SkipStartResponse{},
		SkipStopRequest{}, SkipStopResponse{},
		SkipAddDataRequest{}, SkipAddDataResponse{},
		SkipGetDataRequest{}, SkipGetDataResponse{},
	} {
		network.RegisterMessage(msg)
	}
}

// SkipRootStartRequest is the message passed by the user to create a genesis
// block of a skipchain.
type SkipRootStartRequest struct {
	Roster *onet.Roster
}

// SkipRootStartResponse is the message passed by a skipchain handling conode
// when it has created the genesis bloc Bloc.
type SkipRootStartResponse struct {
	Bloc *skipchain.SkipBlock
}

// SkipStartRequest is the message passed by the user to the skipchain handling
// conode in order to ask the conode to start its block creation's routine.
type SkipStartRequest struct {
	Roster  *onet.Roster
	Genesis *skipchain.SkipBlock
}

// SkipStartResponse is the message passed by the conode to the user to confirm
// that it started its bock creation's routine.
type SkipStartResponse struct {
	Msg string
}

// SkipStopRequest is the message passed by the user to the conode to ask to
// stop the block creation's routine.
// This command is not implemented yet.
type SkipStopRequest struct {
	Roster *onet.Roster
}

// SkipStopResponse is the message passed by the conode to confirm that it stops
// its block creation's routine.
// This command is not implemented yet.
type SkipStopResponse struct {
}

// SkipAddDataRequest is used to ask the skipchain handling conodes to store
// the data Data in the next block they will create.
type SkipAddDataRequest struct {
	Roster *onet.Roster
	Data   []Webstore
}

// SkipAddDataResponse is used to confirm that the data will be added.
// No confirmation to the user is given yet.
type SkipAddDataResponse struct {
}

// SkipGetDataRequest is used to request the skipchain handling conodes to send
// a particular webpage store in the skipchain. The webpage requested must have
// the same url as Url and a timestamp inferior or equal to Timestamp
type SkipGetDataRequest struct {
	Roster    *onet.Roster
	Url       string
	Timestamp string
}

// SkipGetDataResponse is used by the skipchain handling conode to provide the
// data requested by the user. The MainPage contains the page requested, AllPages
// contains the additional ressources necessary to display the webpage.
type SkipGetDataResponse struct {
	MainPage Webstore
	AllPages []Webstore
}
