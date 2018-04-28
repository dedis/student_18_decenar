package decenarch

/*
This holds the messages used to communicate with the service over the network.
*/

import (
	"gopkg.in/dedis/onet.v2/network"

	decenarch "github.com/dedis/student_18_decenar"
)

// We need to register all messages so the network knows how to handle them.
func init() {
	network.RegisterMessage(SkipGetDataResponse{})
}

// SkipGetDataResponse is used by the skipchain handling conode to provide the
// data requested by the user. The MainPage contains the page requested, AllPages
// contains the additional ressources necessary to display the webpage.
type SkipGetDataResponse struct {
	MainPage decenarch.Webstore
	AllPages []decenarch.Webstore
}
