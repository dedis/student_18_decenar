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
	_ "github.com/nblp/decenarch/service"
	_ "github.com/nblp/decenarch/skipservice"
	_ "gopkg.in/dedis/cothority.v1/cosi/service"
	_ "gopkg.in/dedis/cothority.v1/skipchain"
	_ "gopkg.in/dedis/cothority.v1/status/service"
	"gopkg.in/dedis/onet.v1/app"
)

func main() {
	app.Server()
}
