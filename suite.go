package decenarch

import "gopkg.in/dedis/kyber.v2/suites"

// Suite is a convenience. It might go away when we decide the a better way to set the
// suite in repo cothority.
var DecenarSuite = suites.MustFind("Ed25519")
