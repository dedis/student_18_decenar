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

type SkipRootStartRequest struct {
	Roster *onet.Roster
}

type SkipRootStartResponse struct {
	Bloc *skipchain.SkipBlock
}

type SkipStartRequest struct {
	Roster  *onet.Roster
	Genesis *skipchain.SkipBlock
}

type SkipStartResponse struct {
	Msg string
}

type SkipStopRequest struct {
	Roster *onet.Roster
}

type SkipStopResponse struct {
}

type SkipAddDataRequest struct {
	Roster *onet.Roster
	Data   []Webstore
}

type SkipAddDataResponse struct {
}

type SkipGetDataRequest struct {
	Roster    *onet.Roster
	Url       string
	Timestamp string
}

type SkipGetDataResponse struct {
	MainPage Webstore
	AllPages []Webstore
}
