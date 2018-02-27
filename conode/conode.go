// Conode is the main binary for running a Cothority server.
// A conode can participate in various distributed protocols using the
// *onet* library as a network and overlay library and the *dedis/crypto*
// library for all cryptographic primitives.
// Basically, you first need to setup a config file for the server by using:
//
//  ./conode setup
//
// Then you can launch the daemon with:
//
//  ./conode
//
package main

import (
	// Here you can import any other needed service for your conode.
	"github.com/dedis/onet/app"
	_ "github.com/dedis/student_18_decenar/service"
	_ "github.com/dedis/student_18_decenar/skipservice"
	_ "gopkg.in/dedis/cothority.v1/cosi/service"
	_ "gopkg.in/dedis/cothority.v1/skipchain"
	_ "gopkg.in/dedis/cothority.v1/status/service"
)

func main() {
	app.Server()
}
